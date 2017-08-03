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

#ifndef _ZMQSUB_H
#define _ZMQSUB_H

#define ZMQ_MSG_BUF_PARSE
#define ZMQ_DEV_SIG "Ready"

#include <zmq.h>

#include <assert.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

#include "interface.h"

#define __FILENAME__ \
	(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define ZMQSUB_DEBUG (0)

#define MAX_NODE_ID_SIZE     (UINT8_MAX)
#define MAX_NETWORK_ID_SIZE  (UINT8_MAX)

struct max_node_network_id {
	uint8_t node_id_len;
	char node_id[MAX_NODE_ID_SIZE];
	uint8_t network_id_len;
	char network_id[MAX_NETWORK_ID_SIZE];
};
#define NN_ID_BUF_LEN (sizeof(struct max_node_network_id))

#pragma pack(1)
struct zmqbuf {
	uint8_t topic_id;
	uint8_t type;
	union message_t {
		struct create_session_t {
			uint64_t imsi;
			uint8_t  default_ebi;
			uint32_t ue_ipv4;
			uint32_t s1u_sgw_teid;
			uint32_t s1u_sgw_ipv4;
			uint64_t session_id;
			uint8_t  controller_topic;
			uint32_t client_id;
			uint32_t op_id;
		} create_session_msg;
		struct modify_bearer_t {
			uint32_t s1u_sgw_ipv4;
			uint32_t s1u_enodeb_teid;
			uint32_t s1u_enodeb_ipv4;
			uint64_t session_id;
			uint8_t  controller_topic;
			uint32_t client_id;
			uint32_t op_id;
		} modify_bearer_msg;
		struct delete_session_t {
			uint64_t session_id;
			uint8_t  controller_topic;
			uint32_t client_id;
			uint32_t op_id;
		} delete_session_msg;
		struct assign_topic_t {
			uint8_t  topic_generated;
			uint32_t source;
			/* variable length members
			 * uint8_t node_id_length;
			 * char node_id[node_id_length]
			 * uint8_t network_id_length;
			 * char network_id[network_id_length]
			 */

			/* we allocate the buffer length to be the maximum size
			 * for the network and node id fields
			 */
			uint8_t node_network_id_buffer[NN_ID_BUF_LEN];
		} assign_topic_msg;
		struct status_indication_t {
			uint8_t  source_topic_id; /* topic_id of sending node */
			uint8_t  status;   /* status of sending node */
			uint32_t source;
			uint8_t  node_network_id_buffer[NN_ID_BUF_LEN];
		} status_indication;
		struct dpn_status_ack_t {
			uint8_t  controller_topic;
			uint32_t source;
			uint8_t  node_network_id_buffer[NN_ID_BUF_LEN];
		} dpn_status_ack;
		struct dpn_response_t {
			uint8_t  cause;
			uint32_t client_id;
			uint32_t op_id;
		} dpn_response;
		struct ddn_t {
			uint64_t session_id;
			uint32_t client_id;
			uint32_t op_id;
			uint8_t  node_network_id_buffer[NN_ID_BUF_LEN];
		} ddn;

	} msg_union;
};
#pragma pack()

/**
 * @brief
 * creates zmq socket used for subscriber
 * @return
 * 0 on success, error otherwise
 */
int zmq_subsocket_create(void);

/**
 * @brief
 * destroys zmq subscriber socket
 */
void zmq_subsocket_destroy(void);

/**
 * @brief
 * receives zmq message from FPC controller
 * @param mbuf
 * zmq message buffer recieved
 * @param zmqbufsz
 * maximum size of zmq message recieved
 * @return
 * size of zmq message recieved
 */
int zmq_mbuf_rcv(struct zmqbuf *mbuf, uint32_t zmqbufsz);

/**
 * @brief
 * generates and sends goodbye message from the data plane to the FPC controller
 */
void zmq_status_goodbye(void);

/**
 * @brief
 * handler to perform downlink data notification of an idle session
 * @param sess_id
 * session identifier of the bearer/session that the data was recieved
 * @param client_id
 * control plane client identifier
 */
void zmq_ddn(uint64_t sess_id, uint32_t client_id);



/**
 * @brief
 * processes data plane lifecycle messages
 * @param mbuf
 * zmq message buffer to processes
 * @param rc
 * return code received with zmq message buffer
 * @return
 * 0 to indicate dp lifecycle message processed
 * > 0 to indicate not a dp lifecycle message - to be handled by session handler
 * < 0 to indicate error
 */
int
dp_lifecycle_process(struct zmqbuf *mbuf, int rc);

#if ZMQSUB_DEBUG
/**
 * @brief
 * prints zmq buffer message and decodes if known message type
 * @param buf
 * zmq message buffer to  print
 */
void
print_zmqbuf(struct zmqbuf *buf);

/**
 * @brief
 * hex dump to debug byte packed data, such as zmq messages
 * @param fileptr
 * file pointer used to write hex output
 * @param base
 * base pointer of data
 * @param data
 * data pointer to begin printing hex - must be base <= data
 * @param length
 * number of bytes to output
 * @param indent
 * indention of newlines
 */
void
hex_dump(FILE *fileptr, void *base, void *data, size_t length, int indent);

#define PRINT_ZMQBUF(buf, len) \
	do {\
		printf("%s (%s:%d)\n", \
			__FUNCTION__, __FILENAME__, __LINE__);\
		print_zmqbuf(buf);\
		hex_dump(stdout, buf, buf, len, 4);\
	} while (0)

#define PRINT_ZMQBUF_MESSAGE(buf, len, message) \
	do {\
		printf("%s - ", message);\
		PRINT_ZMQBUF(buf, len);\
	} while (0)
#else
#define PRINT_ZMQBUF(buf, len) do {} while (0)

#define PRINT_ZMQBUF_MESSAGE(buf, len, message) do {} while (0)
#endif
#endif

