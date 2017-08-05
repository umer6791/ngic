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

#ifndef SDNODLNBCURL_H
#define SDNODLNBCURL_H

#include <stdint.h>
#include <curl/curl.h>

#include "interface.h"

#define JSON_BUF_SZ		(16*1024)
#define URL_SZ			(256)
#define OPID_MASK		(100)
#define CREATE_OPID_IDX		(1)
#define MODIFY_OPID_IDX		(2)
#define DELETE_OPID_IDX		(3)
#define CREATE_OPID_NBSPACE	(LDB_ENTRIES_DEFAULT*CREATE_OPID_IDX*OPID_MASK)
#define MODIFY_OPID_NBSPACE	(LDB_ENTRIES_DEFAULT*MODIFY_OPID_IDX*OPID_MASK)
#define DELETE_OPID_NBSPACE	(LDB_ENTRIES_DEFAULT*DELETE_OPID_IDX*OPID_MASK)
#define NUM_CURL_POST_PTHREADS  (20)
#define SDN_NB_MAX_QUEUE        (1024)


#define POST "POST"
#define GET  "GET"

#define SDN_SESSION_BEARER_URI_PATH \
	"/restconf/operations/ietf-dmm-fpcagent:configure"
#define SDN_TOPOLOGY_URI_PATH \
	"/restconf/config/ietf-dmm-fpcagent:tenants/tenant/default/fpc-topology"
#define BIND_CLIENT_URI_PATH \
	"/restconf/operations/fpc:register_client"
#define UNBIND_CLIENT_URI_PATH \
	"/restconf/operations/fpc:deregister_client"


#define CONTENT_TYPE_HEADER "Content-type: application/json"
#define UIDPWD "admin:admin"

#define ODL_INSTRUCTION_SESSION_UPLINK "session uplink"
#define ODL_INSTRUCTION_DOWNLINK       "downlink"
#define ODL_INSTRUCTION_SESSION        "session"
#define ODL_OP_TYPE_CREATE             "create"
#define ODL_OP_TYPE_UPDATE             "update"
#define ODL_OP_TYPE_DELETE             "delete"
#define ODL_OP_PREF_NONE               "none"

#define PRI_OP_ID_FORMAT PRIu64
#define PRI_ODL_INSTRUCTION "s"
#define PRI_CONTEXT_SESS_ID PRIu64
#define PRI_UE_IP "s"
#define PRI_TEID PRIu32
#define PRI_CLIENT_ID "s"
#define PRI_DPN_ID "s"
#define PRI_FPC_IP "s"
#define PRI_FPC_PORT PRIu16

#define POST_CREATE_UPDATE_FORMAT_STR \
"\n" \
"{\n" \
"   \"input\": {\n" \
"        \"op-id\": \"%"PRI_OP_ID_FORMAT"\",\n" \
"        \"contexts\": [\n" \
"            {\n" \
"                \"instructions\": {\n" \
"                    \"instr-3gpp-mob\": \"%"PRI_ODL_INSTRUCTION"\"\n" \
"                },\n" \
"                \"context-id\": %"PRI_CONTEXT_SESS_ID",\n" \
"                \"dpn-group\": \"site1-l3\",\n" \
"                \"delegating-ip-prefixes\": [\n" \
"                    \"%"PRI_UE_IP"/32\"\n" \
"                ],\n" \
"                \"ul\": {\n" \
"                    \"tunnel-local-address\": \"%s\",\n" \
"                    \"tunnel-remote-address\": \"%s\",\n" \
"                    \"mobility-tunnel-parameters\": {\n" \
"                        \"tunnel-type\": \"ietf-dmm-threegpp:gtpv1\",\n" \
"                        \"tunnel-identifier\": \"%"PRI_TEID"\"\n" \
"                    },\n" \
"                    \"dpn-parameters\": {}\n" \
"                },\n" \
"                \"dl\": {\n" \
"                    \"tunnel-local-address\": \"%s\",\n" \
"                    \"tunnel-remote-address\": \"%s\",\n" \
"                    \"mobility-tunnel-parameters\": {\n" \
"                        \"tunnel-type\": \"ietf-dmm-threegpp:gtpv1\",\n" \
"                        \"tunnel-identifier\": \"%"PRI_TEID"\"\n" \
"                    },\n" \
"                    \"dpn-parameters\": {}\n" \
"                },\n" \
"                \"dpns\": [\n" \
"                    {\n" \
"                        \"dpn-id\": \"%"PRI_DPN_ID"\",\n" \
"                        \"direction\": \"uplink\",\n" \
"                        \"dpn-parameters\": {}\n" \
"                    }\n" \
"                ],\n" \
"                \"imsi\": \"%"PRIu64"\",\n" \
"                \"ebi\": \"%"PRIu8"\",\n" \
"                \"lbi\": \"%"PRIu8"\"\n" \
"            }\n" \
"        ],\n" \
"        \"client-id\": \"%"PRI_CLIENT_ID"\",\n" \
"        \"session-state\": \"complete\",\n" \
"        \"admin-state\": \"enabled\",\n" \
"        \"op-type\": \"%s\",\n" \
"        \"op-ref-scope\": \"%s\"\n" \
"    }\n" \
"}\n"

#define POST_DELETE_TARGET_PREFIX \
	"/ietf-dmm-fpcagent:tenants/tenant/default/fpc-mobility/contexts/"
#define POST_DELETE_FORMAT_STR \
"\n" \
"{\n" \
"   \"input\": {\n" \
"        \"op-id\": \"%"PRI_OP_ID_FORMAT"\",\n" \
"        \"targets\": [\n" \
"            {\n" \
"                \"target\": \""POST_DELETE_TARGET_PREFIX"%"PRIu64"\"\n" \
"            }\n" \
"        ],\n" \
"        \"client-id\": \"%"PRI_CLIENT_ID"\",\n" \
"        \"session-state\": \"complete\",\n" \
"        \"admin-state\": \"enabled\",\n" \
"        \"op-type\": \"%s\",\n" \
"        \"op-ref-scope\": \"%s\"\n" \
"    }\n" \
"}\n"

#define BIND_CLIENT_FORMAT_STR \
"{\n" \
"    \"input\": {\n" \
"        \"client-id\": \"1\",\n" \
"        \"tenant-id\": \"default\",\n" \
"        \"supported-features\": [\n" \
"            \"urn:ietf:params:xml:ns:yang:fpcagent:fpc-bundles\",\n" \
"            \"urn:ietf:params:xml:ns:yang:fpcagent:operation-ref-scope\",\n" \
"            \"urn:ietf:params:xml:ns:yang:fpcagent:fpc-agent-assignments\",\n"\
"            \"urn:ietf:params:xml:ns:yang:fpcagent:instruction-bitset\"\n" \
"        ],\n" \
"        \"endpoint-uri\": \"http://%"PRI_FPC_IP":%"PRIu16"/\"\n" \
"    }\n" \
"}\n"

#define UNBIND_CLIENT_FORMAT_STR \
"{\n" \
"	\"input\": {\n" \
"		\"client-id\": \"%"PRI_CLIENT_ID"\"\n" \
"	}\n" \
"}\n"

/* DDN ACK not yet implemented */
/* TODO: verify op-id is int instead of string (as is with other messages) */
#define DDN_ACK_FORMAT_STR \
"{\n" \
"	\"dpn-id\": \"%"PRI_DPN_ID"\",\n" \
"	\"dl-buffering-suggested-count\": 16,\n" \
"	\"client-id\": \"%"PRI_CLIENT_ID"\"\n" \
"	\"op-id\": 1,\n" \
"	\"message-type\": \"Downlink-Data-Notification-Ack\",\n" \
"	\"dl-buffering-duration\": 5\n" \
"}\n"


/* s11 interface message type */
enum s11_msgtype {
	CREATE_SESSION = 1,
	MODIFY_BEARER = 2,
	DELETE_SESSION = 3,
	DPN_RESPONSE = 4,
	DDN = 5,
	ASSIGN_TOPIC = 10,
	ASSIGN_CONFLICT = 11,
	DPN_STATUS_INDICATION = 12,
	DPN_STATUS_ACK = 13,
	CONTROLLER_STATUS_INDICATION = 14,
};

enum topic_codes {
	BROADCAST_ALL_TOPIC = 1,
	BROADCAST_CONTROLLERS = 2,
};

enum dpn_status {
	HELLO = 1,
	GOODBYE = 2,
};

/* From rfc2616 */
enum http_status {
	HTTP_CONTINUE = 100,
	HTTP_SWITCHING_PROTOCOLS = 101,
	HTTP_OK = 200,
	HTTP_CREATED = 201,
	HTTP_ACCEPTED = 202,
	HTTP_NON_AUTHORITATIVE_INFORMATION = 203,
	HTTP_NO_CONTENT = 204,
	HTTP_RESET_CONTENT = 205,
	HTTP_PARTIAL_CONTENT = 206,
	HTTP_MULTIPLE_CHOICES = 300,
	HTTP_MOVED_PERMANENTLY = 301,
	HTTP_FOUND = 302,
	HTTP_SEE_OTHER = 303,
	HTTP_NOT_MODIFIED = 304,
	HTTP_USE_PROXY = 305,
	HTTP_TEMPORARY_REDIRECT = 307,
	HTTP_BAD_REQUEST = 400,
	HTTP_UNAUTHORIZED = 401,
	HTTP_PAYMENT_REQUIRED = 402,
	HTTP_FORBIDDEN = 403,
	HTTP_NOT_FOUND = 404,
	HTTP_METHOD_NOT_ALLOWED = 405,
	HTTP_NOT_ACCEPTABLE = 406,
	HTTP_PROXY_AUTHENTICATION_REQUIRED = 407,
	HTTP_REQUEST_TIMEOUT = 408,
	HTTP_CONFLICT = 409,
	HTTP_GONE = 410,
	HTTP_LENGTH_REQUIRED = 411,
	HTTP_PRECONDITION_FAILED = 412,
	HTTP_REQUEST_ENTITY_TOO_LARGE = 413,
	HTTP_REQUEST_URI_TOO_LONG = 414,
	HTTP_UNSUPPORTED_MEDIA_TYPE = 415,
	HTTP_REQUESTED_RANGE_NOT_SATISFIABLE = 416,
	HTTP_EXPECTATION_FAILED = 417,
	HTTP_INTERNAL_SERVER_ERROR = 500,
	HTTP_NOT_IMPLEMENTED = 501,
	HTTP_BAD_GATEWAY = 502,
	HTTP_SERVICE_UNAVAILABLE = 503,
	HTTP_GATEWAY_TIMEOUT = 504,
	HTTP_VERSION_NOT_SUPPORTED = 505,
};

extern char *dpn_id;
extern struct rte_ring *sdnODLnbif_ring[NUM_CURL_POST_PTHREADS];

/**
 *
 * @param set_dpn_id
 * @return
 * -1  dpn_id not set (dpn_id already set)
 *  0  dpn_id successfully set
 */
int
set_dpn_id(const char *dpn_id_from_json);

/**
 * @brief
 * initalizes curl handlers, memory allocation for northbound interface curl
 * operations, and begins the CP topology discovery
 */
void
sdnODLnbinit(void);

/**
 * @brief
 * deconstructor for allocated memory and curl handlers as well as unbinding the
 * contorl plane client from the FPC controller
 */
void
sdnODLcleanup(void);

/**
 * @brief
 * performs the POST to the FPC controller to discover network topology
 */
void
get_topology(void);

/**
 * @brief
 * processes messages destined to the data plane through the FPC controller
 * to install/modify/delete sessions
 * @param s11_mtyp
 * message type, e.g create/modify/delete
 * @param sess_id
 * session identifier used to create contex on FPC controller and associate
 * session between control and data planes
 * @param assigned_ip
 * UE ip assigned by the control plane
 * @param remote_address
 * eNB F-TEID ip address for use with this session/bearer
 * @param local_address
 * SGW F-TEID ip address for use with this session/bearer
 * @param remote_teid
 * eNB F-TEID teid for use with this session/bearer
 * @param local_teid
 * SGW F-TEID teid for use with this session/bearer
 * @param imsi
 * IMSI of session's UE
 * @param ebi
 * EPS Bearer Identifier
 * @return
 * 0 on success, error otherwise
 */
int
s11sdnODLprocess(enum s11_msgtype s11_mtyp, uint64_t sess_id,
		uint32_t assigned_ip, uint32_t remote_address,
		uint32_t local_address, uint32_t remote_teid,
		uint32_t local_teid, uint64_t imsi, uint8_t ebi);

/**
 * @brief entry point for sdn post thread on northbound interface
 * @param arg
 * unused
 * @return
 * 0 indicates success
 */
int
do_sdnODLnbif(__attribute__ ((unused)) void *arg);

#endif

