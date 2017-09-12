/*
 * Copyright (c) 2017 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <json-c/json.h>

#include <rte_errno.h>
#include <rte_debug.h>
#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "cp.h"
#include "cp_stats.h"
#include "nb_listener.h"
#include "sdnODLnbcurl.h"
#include "interface.h"

#define LISTENER_HASH_SIZE (NUM_CURL_POST_PTHREADS*SDN_NB_MAX_QUEUE)

#define HTTP_RESPONSE_OK "HTTP/1.0 200 OK\r\n\r\n"
#define HTTP_RESPONSE_OK_LEN (sizeof(HTTP_RESPONSE_OK)-1)

struct rte_hash *nb_listener_hash = NULL;
uint64_t listener_hash_entries = 0;
fd_set fd_set_active;

void
add_nb_op_id(uint64_t op_id)
{
	int ret = rte_hash_add_key_data(nb_listener_hash, &op_id, NULL);

	if (ret) {
		fprintf(stderr, "rte_hash_add_key_data failed for op_id %"PRIu64
				": %s (%u)\n",
				op_id,
				rte_strerror(abs(ret)), ret);
	}
}


/* Curretly we are simply accounting the config-result-notifications for
 * each message passed to the SDN Controller. In future, we will be
 * using this for retransmit original messages that the SDN Controller
 * does not respond to. Nothing is needed to be done for deleted
 * entries, but rather those that do not get deleted.
 */
static void
del_nb_op_id(uint64_t op_id)
{
	int ret = rte_hash_del_key(nb_listener_hash, &op_id);

	if (ret < 0) {
		fprintf(stderr, "rte_hash_del_key failed for op_id %"PRIu64
				": %s (%u)\n",
				op_id,
				rte_strerror(abs(ret)), ret);
	} else {
		++cp_stats.nb_in;
	}
}


static int
nb_json_notify_parser(const char *buffer,
		struct json_object *notify_jobj, const char *message_type)
{
	json_bool ret;
	if (!strcmp(message_type, "Dpn-Availability")) {
		struct json_object *dpn_status_jobj;
		ret = json_object_object_get_ex(notify_jobj,
				"dpn-status", &dpn_status_jobj);
		if (ret == FALSE || json_object_get_type(dpn_status_jobj) !=
				json_type_string) {
			printf("Received unhandled JSON object "
					"(no dpn-status):\n");
			puts(buffer);
			return EXIT_FAILURE;
		}
		const char *dpn_status =
				json_object_get_string(dpn_status_jobj);
		if (!strcmp(dpn_status, "available")) {
			struct json_object *dpn_id_jobj;
			ret = json_object_object_get_ex(notify_jobj, "dpn-id",
					&dpn_id_jobj);
			if (ret == FALSE || json_object_get_type(dpn_id_jobj) !=
					json_type_string) {
				printf("Received unhandled JSON object "
						"(no dpn-id):\n");
				puts(buffer);
				return EXIT_FAILURE;
			}
			if (!set_dpn_id(json_object_get_string(dpn_id_jobj))) {
				printf("dpn id set to %s\n",
					json_object_get_string(dpn_id_jobj));
			}
			return EXIT_SUCCESS;
		} else if (!strcmp(dpn_status, "unavailable")) {
			struct json_object *dpn_id_jobj;
			ret = json_object_object_get_ex(notify_jobj, "dpn-id",
					&dpn_id_jobj);
			if (ret == FALSE || json_object_get_type(dpn_id_jobj) !=
					json_type_string) {
				printf("Received unhandled JSON object "
						"(no dpn-id):\n");
				puts(buffer);
				return EXIT_FAILURE;
			}
			if (dpn_id != NULL && !strcmp(dpn_id,
					json_object_get_string(dpn_id_jobj))) {
				printf("dpn_id currently in use "
						"is no longer available: %s\n",
					json_object_get_string(dpn_id_jobj));
				set_dpn_id(NULL);
				/* attempt to use different dpn */
				get_topology();
			}
			return EXIT_SUCCESS;
		}
	} else if (!strcmp(message_type, "Downlink-Data-Notification")) {
		struct json_object *session_id_jobj;
		ret = json_object_object_get_ex(notify_jobj, "session-id",
					&session_id_jobj);
		if (ret == FALSE || json_object_get_type(session_id_jobj) !=
				json_type_int) {
			printf("Received unhandled JSON object "
					"(no session-id):\n");
			puts(buffer);
			return EXIT_FAILURE;
		}

		uint64_t session_id = json_object_get_int64(session_id_jobj);

		ddn_by_session_id(session_id);
		return EXIT_SUCCESS;
	}

	printf("Received unhandled JSON object (unknown notification-id):\n");
	puts(buffer);
	return EXIT_FAILURE;
}


static int
nb_json_parser(const char *buffer)
{
	json_bool ret;
	enum json_tokener_error error;
	json_object *jobj = json_tokener_parse_verbose(buffer, &error);

	if (jobj == NULL || error != json_tokener_success) {
		printf("Error parsing json object: %s\n",
				json_tokener_error_desc(error));
		puts(buffer);
		return EXIT_FAILURE;
	}

	struct json_object *notify_jobj;
	ret = json_object_object_get_ex(jobj, "notify", &notify_jobj);
	if (ret == TRUE && json_object_get_type(notify_jobj) ==
			json_type_object) {

		struct json_object *message_type_jobj;
		ret = json_object_object_get_ex(notify_jobj, "message-type",
				&message_type_jobj);
		if (ret == FALSE || json_object_get_type(message_type_jobj) !=
				json_type_string) {
			puts("Received unhandled JSON object "
					"(no message-type):");
			puts(buffer);
			return EXIT_FAILURE;
		}
		nb_json_notify_parser(buffer, notify_jobj,
				json_object_get_string(message_type_jobj));
		return EXIT_SUCCESS;
	}

	struct json_object *config_result_notification_jobj;
	ret = json_object_object_get_ex(jobj, "config-result-notification",
			&config_result_notification_jobj);
	if (ret == TRUE && config_result_notification_jobj != NULL) {
		if (json_object_get_type(config_result_notification_jobj) !=
				json_type_object) {
			puts("Received unhandled JSON object "
				"(no config-result-notification object):");
			puts(buffer);
			return EXIT_FAILURE;
		}
		struct json_object *op_id_jobj;
		ret = json_object_object_get_ex(config_result_notification_jobj,
					"op-id", &op_id_jobj);
		if (ret == FALSE || json_object_get_type(op_id_jobj) !=
				json_type_int) {
			puts("Received unhandled JSON object "
				"(no op-id):");
			puts(buffer);
			return EXIT_FAILURE;
		}
		uint32_t op_id = json_object_get_int(op_id_jobj);
		del_nb_op_id(op_id);
		return EXIT_SUCCESS;
	}

	puts("Received unhandled JSON object (no matching contents):");
	puts(buffer);
	return EXIT_FAILURE;
}



static int
do_listen(int fd)
{
	int tx_bytes;
	char rx_buffer[RTE_MBUF_DEFAULT_DATAROOM];
	int rx_bytes = recv(fd, rx_buffer, sizeof(rx_buffer) - 1, 0);

	if (rx_bytes < 0) {
		printf("Listener recv error: %s\n", strerror(abs(errno)));
		return rx_bytes;
	}

	rx_buffer[rx_bytes] = '\0';

	/* TODO: ERROR on parsing/session errors*/
	tx_bytes = send(fd, HTTP_RESPONSE_OK, HTTP_RESPONSE_OK_LEN, 0);

	/* No error checking at the moment */
	if (tx_bytes != HTTP_RESPONSE_OK_LEN) {
		printf("Listener write error: only wrote %d of %lu bytes: %s\n",
			tx_bytes, HTTP_RESPONSE_OK_LEN, strerror(abs(errno)));
	}


	/* Attempt to find end of HTTP header and beginning of JSON */
	char *http_end = strstr(rx_buffer, "\r\n\r\n");
	if (http_end) {
		char *json_begin = strchr(http_end, '{');
		if (json_begin) {
			nb_json_parser(json_begin);

//			puts("NB RECEIVED:");
//			puts(json_begin);
		} else {
			printf("Cannot find JSON beginning\n");
			puts(rx_buffer);
		}
	} else {
		printf("Cannot find end of HTTP\n");
		puts(rx_buffer);
	}

	shutdown(fd, SHUT_RDWR);
	close(fd);
	FD_CLR(fd, &fd_set_active);
	return sizeof(HTTP_RESPONSE_OK);
}


void
clean_nb_listener_on_signal(int signo)
{
	int i;
	fd_set to_close = fd_set_active;
	FD_ZERO(&fd_set_active);
	if (signo == SIGINT) {
		for (i = 0; i < FD_SETSIZE; ++i) {
			if (FD_ISSET(i, &to_close))
				close(i);
		}
	}
}

int
listener(__rte_unused void *ptr)
{
	int i;
	int socket_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	struct linger so_linger = {
			.l_linger = 0,
			.l_onoff = 1,
	};

	int ret = setsockopt(socket_fd, SOL_SOCKET, SO_LINGER, &so_linger,
			sizeof(so_linger));

	if (ret)
		printf("Linger Error: %s\n", strerror(abs(errno)));

	struct sockaddr_in local_addr = {
			.sin_family = AF_INET,
			.sin_port = htons(cp_nb_server_port),
			.sin_addr = cp_nb_server_ip,
			.sin_zero = {0},
	};

	struct sockaddr_in remote_addr;

	socklen_t remote_addr_len = sizeof(remote_addr);

	errno = 0;

	if (bind(socket_fd, (struct sockaddr *) &local_addr,
	    sizeof(local_addr)) < 0) {
		rte_panic("Bind error for %s:%u - %s\n",
		    inet_ntoa(local_addr.sin_addr),
		    ntohs(local_addr.sin_port),
		    strerror(abs(errno)));
	}

	if (listen(socket_fd, 24) < 0)
		rte_panic("Listen error: %s\n", strerror(abs(errno)));

	fd_set fd_set_read;

	FD_ZERO(&fd_set_active);
	FD_SET(socket_fd, &fd_set_active);

	while (FD_ISSET(socket_fd, &fd_set_active)) {
		fd_set_read = fd_set_active;
		ret = select(FD_SETSIZE, &fd_set_read, NULL, NULL, NULL);
		if (ret == 0)
			continue;

		if (ret < 0 && FD_ISSET(socket_fd, &fd_set_active))
			rte_panic("Select error: %s", strerror(abs(errno)));

		for (i = 0; i < FD_SETSIZE; ++i) {
			if (!FD_ISSET(i, &fd_set_read))
				continue;
			if (i == socket_fd) {
				int new_connection = accept(socket_fd,
						(struct sockaddr *)&remote_addr,
						&remote_addr_len);

				if (new_connection < 0) {
					if (FD_ISSET(socket_fd, &fd_set_active))
						rte_panic("Accept Error: %s\n",
							strerror(abs(errno)));
					continue;
				}

				FD_SET(new_connection, &fd_set_active);
			} else {
				ret = do_listen(i);
				if (ret < 0) {
					close(i);
					FD_CLR(i, &fd_set_active);
				}
			}
		}

	}

	return 0;
}

void
init_nb_listener(void)
{
	struct rte_hash_parameters rte_hash_params = {
			.name = "nb_hash",
	    .entries = LISTENER_HASH_SIZE,
	    .key_len = sizeof(uint64_t),
	    .hash_func = rte_jhash,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	nb_listener_hash = rte_hash_create(&rte_hash_params);
	if (!nb_listener_hash) {
		rte_panic("%s hash create failed: %s (%u)\n",
				rte_hash_params.name,
		    rte_strerror(rte_errno), rte_errno);
	}
}
