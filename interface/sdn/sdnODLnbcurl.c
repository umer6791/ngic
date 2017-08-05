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

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <malloc.h>
#include <json-c/json.h>

#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_debug.h>
#include <rte_errno.h>

#include "nb_listener.h"
#include "sdnODLnbcurl.h"
#include "cp.h"
#include "packet_filters.h"
#include "cp_stats.h"
#include "interface.h"


char *dpn_id;
char *client_id;

#define DEBUG_SDN_ODL 0

#if DEBUG_SDN_ODL
#define DEBUG_PUTS(output) \
	puts(output)
#else
#define DEBUG_PUTS(output) do {} while (0)
#endif


struct sdnODLnbif_ring_entry_t {
	enum s11_msgtype sdnODLnbif_msgtyp;
	uint64_t sess_id;
	uint32_t assigned_ip;
	uint32_t remote_address;
	uint32_t local_address;
	uint32_t remote_teid;
	uint32_t local_teid;
	uint64_t imsi;
	uint8_t ebi;
	uint64_t op_id;
};

struct rte_mempool *nb_mempool[NUM_CURL_POST_PTHREADS];
pthread_t post_thread[NUM_CURL_POST_PTHREADS];
struct rte_ring *sdnODLnbif_ring[NUM_CURL_POST_PTHREADS];


CURL *curlnbhndl[NUM_CURL_POST_PTHREADS];
struct curl_slist *curlnbheaders;
CURL *curl_topology;
struct curl_slist *topology_list;
CURL *curl_bind_client;
struct curl_slist *bind_client_list;
CURL *curl_unbind_client;
struct curl_slist *unbind_client_list;

/**
 * This callback function consumes output returned from curl_easy_perform
 * in order to suppress output. We may decide to log content at a later date.
 */
static size_t
consume_output(__rte_unused char *ptr, size_t size, size_t nmemb,
		__rte_unused void *userdata)
{
	return size * nmemb;
}

static size_t
consume_output_unbind_client(__rte_unused char *ptr, size_t size, size_t nmemb,
		__rte_unused void *userdata)
{
	DEBUG_PUTS(ptr);
	return size * nmemb;
}


#define DO_CHECK_CURL_EASY_SETOPT(one, two, three) \
	do {\
		CURLcode res = curl_easy_setopt(one, two, three);\
		if (res != CURLE_OK) {\
			rte_panic("%s (%s:%d)\n", \
				curl_easy_strerror(res), \
				__func__, __LINE__);\
		} \
	} while (0)


static void
sdnODLnbopreq(CURL *curl_handle, char *postdata)
{
	CURLcode res;

	DO_CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_POSTFIELDS, postdata);
	res = curl_easy_perform(curl_handle);

	if (res != CURLE_OK) {
		printf("CURL OP: Error!!! CURLOPT_POSTFIELDS::"
				" curl_easy_perform():\t%s\n",
				curl_easy_strerror(res));
	} else {
		long response_code;
		CURLcode m = curl_easy_getinfo(curl_handle,
				CURLINFO_RESPONSE_CODE, &response_code);

		if (m != CURLE_OK) {
			printf("Error on curl_easy_getinfo: %s\n",
					curl_easy_strerror(m));
		} else if (response_code != HTTP_CONTINUE &&
				response_code != HTTP_OK) {
			printf("CURL response %ld\n", response_code);
			puts(postdata);
			puts("");
		}
	}


	DEBUG_PUTS("POST:");
	DEBUG_PUTS(postdata);
}


/**
 * @brief creates JSON object string from format specifier and posts to fpc
 * @param curl_handle
 *	curl handle to use
 * @param sdnODLnbif_entry
 *	values for use in message format specifiers
 */
static inline void
sdnODLpost(CURL *curl_handle, struct sdnODLnbif_ring_entry_t *sdnODLnbif_entry)
{
	char sdnODLjobjpost[JSON_BUF_SZ];
	char assigned_address_string[INET_ADDRSTRLEN];
	char remote_address_string[INET_ADDRSTRLEN];
	char local_address_string[INET_ADDRSTRLEN];

	strcpy(assigned_address_string,
		inet_ntoa(*((struct in_addr *)
				&sdnODLnbif_entry->assigned_ip)));
	strcpy(remote_address_string,
		inet_ntoa(*((struct in_addr *)
				&sdnODLnbif_entry->remote_address)));
	strcpy(local_address_string,
		inet_ntoa(*((struct in_addr *)
				&sdnODLnbif_entry->local_address)));

	if (dpn_id == NULL) {
		DEBUG_PUTS("NO DPN INSTALLED!!!!");
		return;
	}

	/* Initialize POST Jason Data Object- sdnODLjobjpost */
	if (sdnODLnbif_entry->sdnODLnbif_msgtyp == CREATE_SESSION) {
		snprintf(sdnODLjobjpost, JSON_BUF_SZ,
			POST_CREATE_UPDATE_FORMAT_STR,
			sdnODLnbif_entry->op_id,
			ODL_INSTRUCTION_SESSION_UPLINK,
			sdnODLnbif_entry->sess_id,
			assigned_address_string,
			local_address_string,		/* SGW-S1U IP Address*/
			remote_address_string,		/* eNB-S1U IP Address*/
			sdnODLnbif_entry->local_teid,	/* SGW-S1U TEID */
			local_address_string,		/* SGW-S1U IP Address*/
			remote_address_string,		/* eNB-S1U IP Address*/
			sdnODLnbif_entry->remote_teid,	/* eNB-S1U TEID      */
			dpn_id,
			sdnODLnbif_entry->imsi,
			sdnODLnbif_entry->ebi,
			sdnODLnbif_entry->ebi,
			client_id,
			ODL_OP_TYPE_CREATE,
			ODL_OP_PREF_NONE);
	} else if (sdnODLnbif_entry->sdnODLnbif_msgtyp == MODIFY_BEARER) {
		snprintf(sdnODLjobjpost, JSON_BUF_SZ,
			POST_CREATE_UPDATE_FORMAT_STR,
			sdnODLnbif_entry->op_id,
			ODL_INSTRUCTION_DOWNLINK,
			sdnODLnbif_entry->sess_id,
			assigned_address_string,
			local_address_string,		/* SGW-S1U IP Address*/
			remote_address_string,		/* eNB-S1U IP Address*/
			sdnODLnbif_entry->local_teid,	/* SGW-S1U TEID*/
			local_address_string,		/* SGW-S1U IP Address*/
			remote_address_string,		/* eNB-S1U IP Address*/
			sdnODLnbif_entry->remote_teid,	/* eNB-S1U TEID*/
			dpn_id,
			sdnODLnbif_entry->imsi,
			sdnODLnbif_entry->ebi,
			sdnODLnbif_entry->ebi,
			client_id,
			ODL_OP_TYPE_UPDATE,
			ODL_OP_PREF_NONE);
	} else if (sdnODLnbif_entry->sdnODLnbif_msgtyp == DELETE_SESSION) {
		snprintf(sdnODLjobjpost, JSON_BUF_SZ, POST_DELETE_FORMAT_STR,
			sdnODLnbif_entry->op_id,
			sdnODLnbif_entry->sess_id,
			client_id,
			ODL_OP_TYPE_DELETE,
			ODL_OP_PREF_NONE);
	} else {
		printf("Error: UNKNOWN Message Type: %d\n",
				sdnODLnbif_entry->sdnODLnbif_msgtyp);
		return;
	}

	sdnODLnbopreq(curl_handle, sdnODLjobjpost);
}

int
s11sdnODLprocess(enum s11_msgtype s11_mtyp, uint64_t sess_id,
		uint32_t assigned_ip, uint32_t remote_address,
		uint32_t local_address, uint32_t remote_teid,
		uint32_t local_teid, uint64_t imsi, uint8_t ebi)
{
	int ret;
	struct sdnODLnbif_ring_entry_t *s11sdnODLnb_entry = NULL;
	unsigned post_thread_id;
	static uint64_t create_count;
	static uint64_t modify_count;
	static uint64_t delete_count;

	post_thread_id = ntohl(assigned_ip) % NUM_CURL_POST_PTHREADS;
	ret = rte_mempool_get(nb_mempool[post_thread_id],
			(void **) &s11sdnODLnb_entry);
	if (ret)
		rte_panic("Error getting nb_mempool!!!...\n");
	s11sdnODLnb_entry->sdnODLnbif_msgtyp = s11_mtyp;
	s11sdnODLnb_entry->sess_id = sess_id;
	s11sdnODLnb_entry->assigned_ip = assigned_ip;
	s11sdnODLnb_entry->remote_address = remote_address;
	s11sdnODLnb_entry->local_address = local_address;
	s11sdnODLnb_entry->remote_teid = remote_teid;
	s11sdnODLnb_entry->local_teid = local_teid;
	s11sdnODLnb_entry->imsi = imsi;
	s11sdnODLnb_entry->ebi = ebi;

	/* set op_id as follows:
	 * lest significant decimal digit: operation
	 */
	switch (s11_mtyp) {
	case CREATE_SESSION:
		s11sdnODLnb_entry->op_id = create_count * 1000 +
				post_thread_id * 10 +
				CREATE_SESSION;
		++create_count;
		break;
	case MODIFY_BEARER:
		s11sdnODLnb_entry->op_id = modify_count * 1000 +
				post_thread_id * 10 +
				MODIFY_BEARER;
		++modify_count;
		break;
	case DELETE_SESSION:
		s11sdnODLnb_entry->op_id = delete_count * 1000 +
				post_thread_id * 10 +
				DELETE_SESSION;
		++delete_count;
		break;
	default:
		printf("Error: UNKNOWN Message Type: %d\n",
				s11_mtyp);
		return EXIT_FAILURE;

	}

	add_nb_op_id(s11sdnODLnb_entry->op_id);
	rte_ring_enqueue(sdnODLnbif_ring[post_thread_id],
			(void *) s11sdnODLnb_entry);

	return ret;
}


/**
 * @brief
 * initializes curl handlers
 * @param curl
 * curl handler to initialize
 * @param list
 * curl list for use in http header
 * @param request
 * request type, e.g. POST or GET
 * @param uri_path
 * http path, portion that follows ip/uri:port
 * @param ip
 * destination ip address for curl operation
 * @param port
 * destination port for curl operation
 * @param write_callback
 * callback to handle any response from curl operation
  */
static void
init_curl(CURL **curl, struct curl_slist **list, const char *request,
		const char *uri_path, const struct in_addr ip,
		const uint16_t port, curl_write_callback write_callback) {
	char uri[256];
	*curl = curl_easy_init();
	if (!*curl)
		rte_panic("curl_easy_init failed\n");
	curl_easy_reset(*curl);

	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_USERPWD, UIDPWD);
	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_CUSTOMREQUEST, request);
	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_HTTPHEADER, *list);
	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_WRITEFUNCTION, write_callback);
	snprintf(uri, sizeof(uri), "http://%s:%"PRIu16"%s", inet_ntoa(ip),
			port, uri_path);
	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_URL, uri);
}


static void *
dequeue_and_post(void *ptr) {
	unsigned id = *(unsigned *)ptr;
	struct sdnODLnbif_ring_entry_t *sdnODLnbif_entry;
	int ret;
	while (1) {
		do {
			ret = rte_ring_dequeue(sdnODLnbif_ring[id],
					(void **) &sdnODLnbif_entry);
		} while (ret);
		sdnODLpost(curlnbhndl[id], sdnODLnbif_entry);
		cp_stats.nb_out[id]++;
		rte_mempool_put(nb_mempool[id], sdnODLnbif_entry);
	}
	return NULL;
}

int
do_sdnODLnbif(__attribute__ ((unused)) void *arg)
{
	unsigned id[NUM_CURL_POST_PTHREADS];
	unsigned i;
	int ret;
	for (i = 0; i < NUM_CURL_POST_PTHREADS; ++i) {
		id[i] = i;
		ret = pthread_create(&post_thread[i], NULL, dequeue_and_post,
				&id[i]);
		if (ret)
			rte_panic("post_thread pthread_create failed: %s\n",
					strerror(ret));
	}
	for (i = 0; i < NUM_CURL_POST_PTHREADS; ++i) {
		ret = pthread_join(post_thread[i], NULL);
		if (ret)
			rte_panic("pthread_join pthread_create failed: %s\n",
					strerror(ret));
	}
	return ret;
}

/**
 * @brief consumes the response of a bind client POST and assigns the client id
 * contained within
 * @param ptr
 * pointer to data recieved from bind client POST
 * @param size
 * size of data units recieved
 * @param nmemb
 * number of data units received
 * @param userdata
 * unused
 */
static size_t
consume_bind_client_output(char *ptr, size_t size, size_t nmemb,
		__rte_unused void *userdata)
{
	static char *object;
	json_bool ret;

	if (object == NULL) {
		object = calloc(1, nmemb * size + 1);
		strncpy(object, ptr, size * nmemb);
	} else {
		char *tmp = object;
		object = calloc(1, strlen(tmp) + (size * nmemb));
		strcpy(object, tmp);
		strncat(object, ptr, size * nmemb);
		free(tmp);
	}

	enum json_tokener_error error;
	json_object *jobj = json_tokener_parse_verbose(object, &error);

	if (jobj == NULL || error != json_tokener_success)
		return size * nmemb;


	struct json_object *output_jobj;
	ret = json_object_object_get_ex(jobj, "output", &output_jobj);
	if (ret == FALSE ||
			json_object_get_type(output_jobj) != json_type_object) {
		free(object);
		object = NULL;
		return size * nmemb;
	}

	struct json_object *client_id_jobj;
	ret = json_object_object_get_ex(output_jobj, "client-id",
			&client_id_jobj);
	if (ret == FALSE || json_object_get_type(client_id_jobj) !=
			json_type_string) {
		free(object);
		object = NULL;
		return size * nmemb;
	}

	if (client_id != NULL)
		free(client_id);

	const char *client_id_jobj_str = json_object_get_string(client_id_jobj);
	client_id = calloc(1, strlen(client_id_jobj_str));
	strcpy(client_id, client_id_jobj_str);

	DEBUG_PUTS(object);
	printf("Established client_id as '%s'\n", client_id);

	free(object);
	object = NULL;

	return size * nmemb;
}

/**
 * @brief populates the bind client message and posts to FPC
 */
static void
bind_client(void) {

	CURLcode res;

	char sdnODLjobjpost[JSON_BUF_SZ];
	snprintf(sdnODLjobjpost, JSON_BUF_SZ, BIND_CLIENT_FORMAT_STR,
			inet_ntoa(cp_nb_server_ip), cp_nb_server_port);

	DO_CHECK_CURL_EASY_SETOPT(curl_bind_client,
			CURLOPT_POSTFIELDS, sdnODLjobjpost);

	res = curl_easy_perform(curl_bind_client);

	DEBUG_PUTS("POST:");
	DEBUG_PUTS(sdnODLpostdata);

	if (res != CURLE_OK) {
		printf("CURL OP: Error!!! CURLOPT_POSTFIELDS::"
				" curl_easy_perform():\t%s\n",
				curl_easy_strerror(res));
	}
}

/**
 * @brief consumes the response of a get topology POST and assigns the dpn id
 * contained within, if it exists
 * @param ptr
 * pointer to data recieved from bind client POST
 * @param size
 * size of data units recieved
 * @param nmemb
 * number of data units received
 * @param userdata
 * unused
 */
static size_t
consume_topology_output(char *ptr, size_t size, size_t nmemb,
		__rte_unused void *userdata)
{
	json_bool ret;
	static char *object;
	int i;

	if (object == NULL) {
		object = calloc(1, nmemb * size + 1);
		strncpy(object, ptr, size * nmemb);
	} else {
		char *tmp = object;
		object = calloc(1, strlen(tmp) + (size * nmemb));
		strcpy(object, tmp);
		strncat(object, ptr, size * nmemb);
		free(tmp);
	}

	enum json_tokener_error error;
	json_object *jobj = json_tokener_parse_verbose(object, &error);
	if (jobj == NULL || error != json_tokener_success)
		return size * nmemb;


	struct json_object *fpc_topology_jobj;
	ret = json_object_object_get_ex(jobj, "fpc-topology",
			&fpc_topology_jobj);
	if (ret == FALSE || json_object_get_type(fpc_topology_jobj) !=
			json_type_object) {
		free(object);
		object = NULL;
		return size * nmemb;
	}

	struct json_object *dpns_jobj;
	ret = json_object_object_get_ex(fpc_topology_jobj, "dpns", &dpns_jobj);
	if (json_object_get_type(dpns_jobj) != json_type_array) {
		free(object);
		object = NULL;
		return size * nmemb;
	}

	int dpns_jobj_array_length = json_object_array_length(dpns_jobj);
	if (dpns_jobj_array_length > 0)

	for (i = 0; i < dpns_jobj_array_length; ++i) {
		struct json_object *dpn_jobj =
				json_object_array_get_idx(dpns_jobj, i);

		struct json_object *dpn_id_jobj;
		ret = json_object_object_get_ex(dpn_jobj, "dpn-id",
				&dpn_id_jobj);
		if (ret == FALSE || json_object_get_type(dpn_id_jobj) !=
				json_type_string) {
			free(object);
			object = NULL;
			return size * nmemb;
		}

		if (dpn_id == NULL) {
			set_dpn_id(json_object_get_string(dpn_id_jobj));
			/* TODO: maintain a list of DPNs to allow multiple
			 * connections
			 */
			break;
		}
	}

	free(object);
	object = NULL;
	return size * nmemb;
}


int
set_dpn_id(const char *dpn_id_from_json)
{
	if (dpn_id != NULL && dpn_id_from_json != NULL)
		return -1;
	if (dpn_id != NULL && dpn_id_from_json == NULL) {
		free(dpn_id);
		dpn_id = NULL;
		reset_cp_stats();
		return 0;
	}
	if (dpn_id == NULL && dpn_id_from_json == NULL)
		return 0;
	dpn_id = calloc(1, strlen(dpn_id_from_json));
	strcpy(dpn_id, dpn_id_from_json);
	initialize_tables_on_dp();
	push_all_packet_filters();
	parse_adc_rules();
	return 0;
}

void
get_topology(void) {

	int res = curl_easy_perform(curl_topology);

	DEBUG_PUTS(GET);
	DEBUG_PUTS(SDN_TOPOLOGY_URI);

	if (res != CURLE_OK) {
		printf("CURL OP: Error!!! CURLOPT_POSTFIELDS::"
				" curl_easy_perform():\t%s\n",
				curl_easy_strerror(res));
	}

}

void
sdnODLnbinit(void)
{
	char name[64];
	unsigned i;
	rte_errno = 0;

	curlnbheaders = curl_slist_append(curlnbheaders, CONTENT_TYPE_HEADER);
	curlnbheaders = curl_slist_append(curlnbheaders, "Expect:");

	for (i = 0; i < NUM_CURL_POST_PTHREADS; ++i) {
		snprintf(name, sizeof(name), "nb_mempool_%u", i);
		nb_mempool[i] = rte_mempool_create(name,
				SDN_NB_MAX_QUEUE,
				sizeof(struct sdnODLnbif_ring_entry_t),
				0, 0, NULL, NULL, NULL, NULL,
				rte_socket_id(), MEMPOOL_F_NO_CACHE_ALIGN);
		if (rte_errno || nb_mempool[i] == NULL) {
			rte_panic("Cannot create nb_mempool - %s (%d)\n",
					rte_strerror(rte_errno), rte_errno);
		}

		snprintf(name, sizeof(name), "sdnODLnbif_ring_%u", i);
		sdnODLnbif_ring[i] = rte_ring_create(name,
				SDN_NB_MAX_QUEUE,
				rte_lcore_to_socket_id(cp_params.sdn_lcore_id),
				RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (sdnODLnbif_ring[i] == NULL) {
			rte_panic("%s create failed: %s", name,
					rte_strerror(abs(rte_errno)));
		}

		init_curl(&curlnbhndl[i], &curlnbheaders, POST,
				SDN_SESSION_BEARER_URI_PATH,
				fpc_ip, fpc_port,
				&consume_output);

		DO_CHECK_CURL_EASY_SETOPT(curlnbhndl[i],
				CURLOPT_TCP_KEEPALIVE, 1L);
	}

	topology_list = curl_slist_append(topology_list, CONTENT_TYPE_HEADER);
	init_curl(&curl_topology, &topology_list, GET,
			SDN_TOPOLOGY_URI_PATH,
			fpc_ip, fpc_port,
			&consume_topology_output);
	bind_client_list = curl_slist_append(bind_client_list,
			CONTENT_TYPE_HEADER);
	init_curl(&curl_bind_client, &bind_client_list, POST,
			BIND_CLIENT_URI_PATH,
			fpc_ip, fpc_port,
			&consume_bind_client_output);
	unbind_client_list = curl_slist_append(unbind_client_list,
			CONTENT_TYPE_HEADER);
	init_curl(&curl_unbind_client, &unbind_client_list, POST,
			UNBIND_CLIENT_URI_PATH,
			fpc_ip, fpc_port,
			&consume_output_unbind_client);

	bind_client();

	get_topology();
}

void
sdnODLcleanup(void)
{
	static int do_once;
	unsigned i;

	char sdnODLjobjpost[JSON_BUF_SZ];
	snprintf(sdnODLjobjpost, JSON_BUF_SZ, UNBIND_CLIENT_FORMAT_STR,
			client_id);
	DEBUG_PUTS(sdnODLjobjpost);
	DO_CHECK_CURL_EASY_SETOPT(curl_unbind_client, CURLOPT_POSTFIELDS,
			sdnODLjobjpost);
	curl_easy_perform(curl_unbind_client);

	if (!do_once) {
		do_once = 1;

		curl_easy_cleanup(curl_topology);
		curl_slist_free_all(topology_list);

		curl_easy_cleanup(curl_bind_client);
		curl_slist_free_all(bind_client_list);

		for (i = 0; i < NUM_CURL_POST_PTHREADS; ++i)
			curl_easy_cleanup(curlnbhndl[i]);

		curl_slist_free_all(curlnbheaders);
	}
}

