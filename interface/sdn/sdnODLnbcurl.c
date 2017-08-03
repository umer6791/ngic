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

#define S11_OBJ_MEMPOOL_SIZE  (64 * 1024)
#define SDN_NB_RING_SIZE      (2 * S11_OBJ_MEMPOOL_SIZE)
#define SDN_NB_CACHE_SIZE     (0)

struct rte_mempool *create_mempool;
struct rte_mempool *modify_mempool;
struct rte_mempool *delete_mempool;
struct rte_ring *sdnODLnbif_ring;

char *dpn_id;
char *client_id;

#define DEBUG_SDN_ODL 0

#if DEBUG_SDN_ODL
#define DEBUG_PUTS(output) \
	do { puts(output); } while (0)
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
};

static uint32_t sdnODLcreateqnb;
static uint32_t sdnODLmodifyqnb;
static uint32_t sdnODLdeleteqnb;


CURL *curlnbhndl = NULL;
struct curl_slist *curlnbheaders = NULL;
CURL *curl_topology = NULL;
struct curl_slist *topology_list = NULL;
CURL *curl_bind_client = NULL;
struct curl_slist *bind_client_list = NULL;
CURL *curl_unbind_client = NULL;
struct curl_slist *bind_unclient_list = NULL;

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
sdnODLnbopreq(char *sdnODLpostdata, enum s11_msgtype sdnODLop)
{
	CURLcode res;

	if (sdnODLop == CREATE_SESSION || sdnODLop == MODIFY_BEARER
			|| sdnODLop == DELETE_SESSION) {
		DO_CHECK_CURL_EASY_SETOPT(curlnbhndl, CURLOPT_POSTFIELDS,
				sdnODLpostdata);
		res = curl_easy_perform(curlnbhndl);

		if (res != CURLE_OK) {
			printf("CURL OP: Error!!! CURLOPT_POSTFIELDS::"
					" curl_easy_perform():\t%s\n",
					curl_easy_strerror(res));
		} else {
			long response_code;
			curl_easy_getinfo(curlnbhndl, CURLINFO_RESPONSE_CODE,
					&response_code);

			if (response_code != HTTP_CONTINUE &&
					response_code != HTTP_OK) {
				printf("CURL response %ld on op %d\n",
						response_code, sdnODLop);
				puts(sdnODLpostdata);
				puts("");
			}
		}
	} else {
		printf("Error: UNKNOWN CURL OP: %d\n", sdnODLop);
	}


	DEBUG_PUTS("POST:");
	DEBUG_PUTS(sdnODLpostdata);
}

/**
 * @brief creates JSON object string from format specifier and posts to fpc
 * @param sdnODLnbif_entry
 * values for use in message format specifiers
 */
static inline void
sdnODLpost(struct sdnODLnbif_ring_entry_t *sdnODLnbif_entry) {
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

	static uint32_t sdnODLnbcreateid_seq;
	static uint64_t sdnODLnbcreateid_nb = CREATE_OPID_NBSPACE;
	static uint32_t sdnODLnbmodifyid_seq;
	static uint64_t sdnODLnbmodifyid_nb = MODIFY_OPID_NBSPACE;
	static uint32_t sdnODLnbdeleteid_seq;
	static uint64_t sdnODLnbdeleteid_nb = DELETE_OPID_NBSPACE;

	static uint32_t create_session_nb;
	static uint32_t modify_bearer_nb;
	static uint32_t delete_session_nb;
	static uint32_t sdnODLnb_post_nb;

	if (dpn_id == NULL) {
		DEBUG_PUTS("NO DPN INSTALLED!!!!");
		return;
	}


	if (sdnODLnbif_entry->sdnODLnbif_msgtyp == CREATE_SESSION) {
		++sdnODLnbcreateid_seq;
		sdnODLnbcreateid_nb = CREATE_OPID_NBSPACE
				+ sdnODLnbcreateid_seq * OPID_MASK;

		uint64_t op_id = (sdnODLnbcreateid_nb | 0x01);
		add_nb_op_id(op_id);
		++create_session_nb;

		/* Initialize POST Jason Data Object- sdnODLjobjpost */
		snprintf(sdnODLjobjpost, JSON_BUF_SZ,
			POST_CREATE_UPDATE_FORMAT_STR,
			op_id,
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
		uint64_t op_id = (sdnODLnbmodifyid_nb | 0x02);
		add_nb_op_id(op_id);

		++sdnODLnbmodifyid_seq;
		sdnODLnbmodifyid_nb = MODIFY_OPID_NBSPACE
				+ sdnODLnbmodifyid_seq * OPID_MASK;
		++modify_bearer_nb;
		/* Initialize POST Jason Data Object- sdnODLjobjpost */
		snprintf(sdnODLjobjpost, JSON_BUF_SZ,
			POST_CREATE_UPDATE_FORMAT_STR, op_id,
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
		uint64_t op_id = (sdnODLnbdeleteid_nb | 0x03);
		add_nb_op_id(op_id);

		++sdnODLnbdeleteid_seq;
		sdnODLnbdeleteid_nb = DELETE_OPID_NBSPACE
				+ sdnODLnbdeleteid_seq * OPID_MASK;
		++delete_session_nb;

		/* Initialize POST Jason Data Object- sdnODLjobjpost */
		snprintf(sdnODLjobjpost, JSON_BUF_SZ, POST_DELETE_FORMAT_STR,
				op_id, sdnODLnbif_entry->sess_id,
				client_id,
				ODL_OP_TYPE_DELETE,
				ODL_OP_PREF_NONE);
	}

	sdnODLnbopreq(sdnODLjobjpost,
			sdnODLnbif_entry->sdnODLnbif_msgtyp);

	++sdnODLnb_post_nb;
}

int
s11sdnODLprocess(enum s11_msgtype s11_mtyp, uint64_t sess_id,
		uint32_t assigned_ip, uint32_t remote_address,
		uint32_t local_address, uint32_t remote_teid,
		uint32_t local_teid, uint64_t imsi, uint8_t ebi)
{
	int ret;
	struct sdnODLnbif_ring_entry_t *s11sdnODLnb_entry = NULL;
	if (s11_mtyp == CREATE_SESSION) {
		ret = rte_mempool_get(create_mempool,
				(void **) &s11sdnODLnb_entry);
		if (ret)
			rte_panic("Error getting create_mempool!!!...\n");

		++sdnODLcreateqnb;
		s11sdnODLnb_entry->sdnODLnbif_msgtyp = CREATE_SESSION;
	}
	if (s11_mtyp == MODIFY_BEARER) {
		ret = rte_mempool_get(modify_mempool,
				(void **) &s11sdnODLnb_entry);
		if (ret)
			rte_panic("Error getting modify_mempool!!!...\n");

		++sdnODLmodifyqnb;
		s11sdnODLnb_entry->sdnODLnbif_msgtyp = MODIFY_BEARER;
	}
	if (s11_mtyp == DELETE_SESSION) {
		ret = rte_mempool_get(delete_mempool,
				(void **) &s11sdnODLnb_entry);
		if (ret)
			rte_panic("Error getting delete_mempool!!!...\n");

		++sdnODLdeleteqnb;
		s11sdnODLnb_entry->sdnODLnbif_msgtyp = DELETE_SESSION;
	}
	s11sdnODLnb_entry->sess_id = sess_id;
	s11sdnODLnb_entry->assigned_ip = assigned_ip;
	s11sdnODLnb_entry->remote_address = remote_address;
	s11sdnODLnb_entry->local_address = local_address;
	s11sdnODLnb_entry->remote_teid = remote_teid;
	s11sdnODLnb_entry->local_teid = local_teid;
	s11sdnODLnb_entry->imsi = imsi;
	s11sdnODLnb_entry->ebi = ebi;

	rte_ring_enqueue(sdnODLnbif_ring, (void *) s11sdnODLnb_entry);

	return ret;
}

/**
 * @brief entry point for sdn post thread on northbound interface
 * @param arg
 * unused
 * @return
 * 0 indicates success
 */
static int
do_sdnODLnbif(__attribute__ ((unused)) void *arg)
{
	printf("do_sdnODLnbif polling sdnODLnbif_ring\n");
	struct sdnODLnbif_ring_entry_t *sdnODLnbif_entry;
	int ret;
	while (1) {
		do {
			ret = rte_ring_dequeue(sdnODLnbif_ring,
					(void **) &sdnODLnbif_entry);
		} while (ret);
		sdnODLpost(sdnODLnbif_entry);

		if (sdnODLnbif_entry->sdnODLnbif_msgtyp == CREATE_SESSION)
			rte_mempool_put(create_mempool, sdnODLnbif_entry);
		else if (sdnODLnbif_entry->sdnODLnbif_msgtyp == MODIFY_BEARER)
			rte_mempool_put(modify_mempool, sdnODLnbif_entry);
		else if (sdnODLnbif_entry->sdnODLnbif_msgtyp == DELETE_SESSION)
			rte_mempool_put(delete_mempool, sdnODLnbif_entry);
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
			 * connections */
			break;
		}
	}

	free(object);
	object = NULL;
	return size * nmemb;
}


int set_dpn_id(const char *dpn_id_from_json) {
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
	*list = curl_slist_append(*list, CONTENT_TYPE_HEADER);
	*list = curl_slist_append(*list, "Expect:");

	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_USERPWD, UIDPWD);

	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_CUSTOMREQUEST, request);
	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_HTTPHEADER, *list);
	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_WRITEFUNCTION, write_callback);

	snprintf(uri, sizeof(uri), "http://%s:%"PRIu16"%s", inet_ntoa(ip),
			port, uri_path);

	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_URL, uri);
}

void
sdnODLnbinit(void)
{

	rte_errno = 0;

	create_mempool = rte_mempool_create("create_mempool",
			S11_OBJ_MEMPOOL_SIZE,
			sizeof(struct sdnODLnbif_ring_entry_t),
			SDN_NB_CACHE_SIZE, 0, NULL, NULL, NULL, NULL,
			rte_socket_id(), MEMPOOL_F_NO_CACHE_ALIGN);
	if (rte_errno || !create_mempool) {
		rte_panic("Cannot create create_mempool - %s (%d)\n",
				rte_strerror(rte_errno), rte_errno);
	}

	modify_mempool = rte_mempool_create("modify_mempool",
				S11_OBJ_MEMPOOL_SIZE,
				sizeof(struct sdnODLnbif_ring_entry_t),
				SDN_NB_CACHE_SIZE, 0, NULL, NULL, NULL, NULL,
				rte_socket_id(), MEMPOOL_F_NO_CACHE_ALIGN);
	if (rte_errno || !modify_mempool)
		rte_panic("Cannot create modify_mempool - %s (%d)\n",
				rte_strerror(rte_errno), rte_errno);


	delete_mempool = rte_mempool_create("delete_mempool",
				S11_OBJ_MEMPOOL_SIZE,
				sizeof(struct sdnODLnbif_ring_entry_t),
				SDN_NB_CACHE_SIZE, 0, NULL, NULL, NULL, NULL,
				rte_socket_id(), MEMPOOL_F_NO_CACHE_ALIGN);
	if (rte_errno || !delete_mempool)
		rte_panic("Cannot create delete_mempool - %s (%d)\n",
				rte_strerror(rte_errno), rte_errno);


	sdnODLnbif_ring = rte_ring_create("sdnODLnbif_ring", SDN_NB_RING_SIZE,
				rte_lcore_to_socket_id(cp_params.sdn_lcore_id),
				RING_F_SP_ENQ | RING_F_SC_DEQ);

	init_curl(&curlnbhndl, &curlnbheaders, POST,
			SDN_SESSION_BEARER_URI_PATH,
			fpc_ip, fpc_port,
			&consume_output);
	init_curl(&curl_topology, &topology_list, GET,
			SDN_TOPOLOGY_URI_PATH,
			fpc_ip, fpc_port,
			&consume_topology_output);
	init_curl(&curl_bind_client, &bind_client_list, POST,
			BIND_CLIENT_URI_PATH,
			fpc_ip, fpc_port,
			&consume_bind_client_output);
	init_curl(&curl_unbind_client, &bind_unclient_list, POST,
			UNBIND_CLIENT_URI_PATH,
			fpc_ip, fpc_port,
			&consume_output_unbind_client);

	rte_eal_remote_launch(do_sdnODLnbif, NULL, cp_params.sdn_lcore_id);

	bind_client();

	get_topology();
}

void
sdnODLcleanup(void)
{
	char sdnODLjobjpost[JSON_BUF_SZ];
	snprintf(sdnODLjobjpost, JSON_BUF_SZ, UNBIND_CLIENT_FORMAT_STR,
			client_id);
	DEBUG_PUTS(sdnODLjobjpost);
	DO_CHECK_CURL_EASY_SETOPT(curl_unbind_client, CURLOPT_POSTFIELDS,
			sdnODLjobjpost);
	curl_easy_perform(curl_unbind_client);

	static int do_once = 0;

	if (!do_once) {
		do_once = 1;

		curl_easy_cleanup(curl_topology);
		curl_slist_free_all(topology_list);

		curl_easy_cleanup(curl_bind_client);
		curl_slist_free_all(bind_client_list);

		curl_easy_cleanup(curlnbhndl);
		curl_slist_free_all(curlnbheaders);
	}
}

