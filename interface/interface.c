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

#include <stdint.h>
#include <arpa/inet.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_cfgfile.h>

#include "interface.h"
#include "util.h"
#include "meter.h"
#include "dp_ipc_api.h"
#include "gtpv2c_ie.h"
#ifdef SDN_ODL_BUILD
#include "zmqsub.h"
#ifdef CP_BUILD
#include "nb_listener.h"
#endif
#endif

/*
 * UDP Setup
 */
udp_sock_t my_sock;

struct in_addr dp_comm_ip;
struct in_addr cp_comm_ip;
uint16_t dp_comm_port;
uint16_t cp_comm_port;

#ifdef SDN_ODL_BUILD
struct in_addr fpc_ip;
uint16_t fpc_port;
struct in_addr cp_nb_server_ip;
uint16_t cp_nb_server_port;
#endif


extern struct ipc_node *basenode;

void register_comm_msg_cb(enum cp_dp_comm id,
			int (*init)(void),
			int (*send)(void *msg_payload, uint32_t size),
			int (*recv)(void *msg_payload, uint32_t size),
			int (*destroy)(void))
{
	struct comm_node *node;

	node = &comm_node[id];
	node->init = init;
	node->send = send;
	node->recv = recv;
	node->destroy = destroy;
	node->status = 0;
	node->init();
}

int set_comm_type(enum cp_dp_comm id)
{
	if (comm_node[id].status == 0 && comm_node[id].init != NULL) {
		active_comm_msg = &comm_node[id];
		comm_node[id].status = 1;
	} else {
		RTE_LOG(ERR, DP,"Error: Cannot set communication type\n");
		return -1;
	}
	return 0;
}

int unset_comm_type(enum cp_dp_comm id)
{
	if (comm_node[id].status) {
		active_comm_msg->destroy();
		comm_node[id].status = 0;
	} else {
		RTE_LOG(ERR, DP,"Error: Cannot unset communication type\n");
		return -1;
	}
	return 0;
}
int process_comm_msg(void *buf)
{
	struct msgbuf *rbuf = (struct msgbuf *)buf;
	struct ipc_node *cb;

	if (rbuf->mtype >= MSG_END)
		return -1;
	/* Callback APIs */
	cb = &basenode[rbuf->mtype];
	return cb->msg_cb(rbuf);
}
static int
udp_send_socket(void *msg_payload, uint32_t size)
{
	if (__send_udp_packet(&my_sock, msg_payload, size) < 0)
		RTE_LOG(ERR, DP, "Failed to send msg !!!\n");
	return 0;
}
#if !defined(CP_BUILD) || !defined(SDN_ODL_BUILD)
static int
udp_recv_socket(void *msg_payload, uint32_t size)
{
	uint32_t bytes = recvfrom(my_sock.sock_fd, msg_payload, size, 0,
			NULL, NULL);
	if (bytes < size) {
		RTE_LOG(ERR, DP, "Failed recv msg !!!\n");
		return -1;
	}
	return 0;
}
#endif
#ifdef CP_BUILD
/**
 * Init listen socket.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
static int
udp_init_cp_socket(void)
{
	/*
	 * UDP init
	 */
	/* TODO IP and port parameters */
	if (__create_udp_socket(dp_comm_ip, dp_comm_port, cp_comm_port,
			&my_sock) < 0)
		rte_exit(EXIT_FAILURE, "Create CP UDP Socket Failed "
			"for IP %s:%u!!!\n",
			inet_ntoa(dp_comm_ip), dp_comm_port);
	return 0;
}


#ifdef SDN_ODL_BUILD
static int
sdnODL_init(void)
{

	return udp_init_cp_socket();
}

static int
sdnODL_destroy(void)
{
	/*
	 * sdnODL destroy
	 */
	sdnODLcleanup();

	/* Here we wait for a couple seconds for a error response (if any) */
	sleep(2);

	return 0;
}
#endif		/* CP:SDN_ODL_BUILD */
#endif		/* CP_BUILD */

#ifndef CP_BUILD
/**
 * Init listen socket.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
static int
udp_init_dp_socket(void)
{
	if (__create_udp_socket(cp_comm_ip, cp_comm_port, dp_comm_port,
			&my_sock) < 0)
		rte_exit(EXIT_FAILURE, "Create DP UDP Socket "
			"Failed for IP %s:%d!!!\n",
			inet_ntoa(cp_comm_ip), cp_comm_port);
	return 0;
}

/**
 * UDP packet receive API.
 * @param msg_payload
 *	msg_payload - message payload from communication API.
 * @param size
 *	size - size of message payload.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
/**
 * Code Rel. Jan 30, 2017
 * UDP recvfrom used for PCC, ADC, Session table initialization.
 * Needs to be from SDN controller as code & data models evolve.
 */
#ifdef SDN_ODL_BUILD
static int
zmq_init_socket(void)
{
	/*
	 * zmqsub init
	 */
	zmq_pubsocket_create();
	return zmq_subsocket_create();
}
static int
zmq_send_socket(void *zmqmsgbuf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqsub recv
	 */
	return zmq_mbuf_send(zmqmsgbuf, sizeof(struct zmqbuf));
}

static int
zmq_recv_socket(void *buf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqsub recv
	 */
	int zmqmsglen = zmq_mbuf_rcv(buf, zmqmsgbufsz);

	if (zmqmsglen > 0)	{
		RTE_LOG(DEBUG, DP,
			"Rcvd zmqmsglen= %d:\t zmqmsgbufsz= %u",
			zmqmsglen, zmqmsgbufsz);
	}
	return zmqmsglen;
}

/**
 * @brief Converts zmq message type to session_info
 */
int
zmq_mbuf_process(struct zmqbuf *zmqmsgbuf_rx, int zmqmsglen)
{
	int ret;
	struct msgbuf buf = {0};
	struct zmqbuf zmqmsgbuf_tx;
	struct msgbuf *rbuf = &buf;
	struct session_info *sess = &rbuf->msg_union.sess_entry;

	memset(sess, 0, sizeof(*sess));

	rbuf->mtype = MSG_END;
	if (zmqmsgbuf_rx->type == CREATE_SESSION) {
		struct create_session_t *csm =
				&zmqmsgbuf_rx->msg_union.create_session_msg;

		rbuf->mtype = MSG_SESS_CRE;
		rbuf->dp_id.id = DPN_ID;

		sess->ue_addr.iptype = IPTYPE_IPV4;
		sess->ue_addr.u.ipv4_addr = ntohl(csm->ue_ipv4);
		sess->ul_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
		sess->ul_s1_info.sgw_addr.u.ipv4_addr =
				ntohl(csm->s1u_sgw_ipv4);
		sess->ul_s1_info.sgw_teid = csm->s1u_sgw_teid;
		sess->dl_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
		sess->dl_s1_info.sgw_addr.u.ipv4_addr =
				ntohl(csm->s1u_sgw_ipv4);
		sess->dl_s1_info.enb_teid = 0;

		sess->num_ul_pcc_rules = 1;
		sess->ul_pcc_rule_id[0] = 1;

		sess->sess_id = rte_bswap64(csm->session_id);
		sess->client_id = csm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.client_id = csm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.op_id = csm->op_id;
		zmqmsgbuf_tx.topic_id = csm->controller_topic;

	} else if (zmqmsgbuf_rx->type == MODIFY_BEARER) {
		struct modify_bearer_t *mbm =
				&zmqmsgbuf_rx->msg_union.modify_bearer_msg;
		rbuf->mtype = MSG_SESS_MOD;
		rbuf->dp_id.id = DPN_ID;

		sess->ue_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		sess->ul_s1_info.enb_addr.u.ipv4_addr =
				ntohl(mbm->s1u_enodeb_ipv4);
		sess->ul_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_teid = 0;
		sess->dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		sess->dl_s1_info.enb_addr.u.ipv4_addr =
				ntohl(mbm->s1u_enodeb_ipv4);
		sess->dl_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.enb_teid = mbm->s1u_enodeb_teid;

		sess->num_ul_pcc_rules = 1;
		sess->ul_pcc_rule_id[0] = 1;
		sess->num_dl_pcc_rules = 1;
		sess->dl_pcc_rule_id[0] = 1;

		sess->sess_id = rte_bswap64(mbm->session_id);
		zmqmsgbuf_tx.msg_union.dpn_response.client_id = mbm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.op_id = mbm->op_id;
		zmqmsgbuf_tx.topic_id = mbm->controller_topic;

	} else if (zmqmsgbuf_rx->type == DELETE_SESSION) {
		struct delete_session_t *dsm =
				&zmqmsgbuf_rx->msg_union.delete_session_msg;
		rbuf->mtype = MSG_SESS_DEL;
		rbuf->dp_id.id = DPN_ID;

		sess->ue_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_teid = 0;
		sess->dl_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.enb_teid = 0;

		sess->sess_id = rte_bswap64(dsm->session_id);

		zmqmsgbuf_tx.msg_union.dpn_response.client_id = dsm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.op_id = dsm->op_id;
		zmqmsgbuf_tx.topic_id = dsm->controller_topic;

	}

	ret = process_comm_msg((void *)rbuf);
	if (ret < 0)
		zmqmsgbuf_tx.msg_union.dpn_response.cause =
			GTPV2C_CAUSE_SYSTEM_FAILURE;
	else
		zmqmsgbuf_tx.msg_union.dpn_response.cause =
			GTPV2C_CAUSE_REQUEST_ACCEPTED;

	zmqmsgbuf_tx.type = DPN_RESPONSE;
	ret = do_zmq_mbuf_send(&zmqmsgbuf_tx);

	if (ret < 0)
		printf("do_zmq_mbuf_send failed for type: %"PRIu8"\n",
				zmqmsgbuf_rx->type);

	return ret;
}

static int
zmq_destroy(void)
{
	/*
	 * zmqsub destroy
	 */
	zmq_subsocket_destroy();
	return 0;
}

#endif		/* DP: SDN_ODL_BUILD */
#endif /* !CP_BUILD*/

#define IFACE_FILE "../config/interface.cfg"
#define SET_CONFIG_IP(ip, file, section, entry) \
	do {\
		entry = rte_cfgfile_get_entry(file, section, #ip);\
		if (entry == NULL)\
			rte_panic("%s not found in %s", #ip, IFACE_FILE);\
		if (inet_aton(entry, &ip) == 0)\
			rte_panic("Invalid %s in %s", #ip, IFACE_FILE);\
	} while (0)
#define SET_CONFIG_PORT(port, file, section, entry) \
	do {\
		entry = rte_cfgfile_get_entry(file, section, #port);\
		if (entry == NULL)\
			rte_panic("%s not found in %s", #port, IFACE_FILE);\
		if (sscanf(entry, "%"SCNu16, &port) != 1)\
			rte_panic("Invalid %s in %s", #port, IFACE_FILE);\
	} while (0)

static void read_interface_config(void)
{
	struct rte_cfgfile *file = rte_cfgfile_load(IFACE_FILE, 0);
	const char *file_entry;

	if (file == NULL)
		rte_exit(EXIT_FAILURE, "Cannot load configuration profile %s\n",
				IFACE_FILE);

	SET_CONFIG_IP(dp_comm_ip, file, "0", file_entry);
	SET_CONFIG_PORT(dp_comm_port, file, "0", file_entry);

	SET_CONFIG_IP(cp_comm_ip, file, "0", file_entry);
	SET_CONFIG_PORT(cp_comm_port, file, "0", file_entry);

#ifdef SDN_ODL_BUILD
	const char *zmq_proto = "tcp";
	struct in_addr zmq_sub_ip;
	struct in_addr zmq_pub_ip;
	uint16_t zmq_sub_port;
	uint16_t zmq_pub_port;

	SET_CONFIG_IP(fpc_ip, file, "0", file_entry);
	SET_CONFIG_PORT(fpc_port, file, "0", file_entry);

	SET_CONFIG_IP(cp_nb_server_ip, file, "0", file_entry);
	SET_CONFIG_PORT(cp_nb_server_port, file, "0", file_entry);

	SET_CONFIG_IP(zmq_sub_ip, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_sub_port, file, "0", file_entry);

	SET_CONFIG_IP(zmq_pub_ip, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_pub_port, file, "0", file_entry);

	snprintf(zmq_sub_ifconnect, sizeof(zmq_sub_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_sub_ip), zmq_sub_port);
	snprintf(zmq_pub_ifconnect, sizeof(zmq_pub_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_pub_ip), zmq_pub_port);
#endif
}


/**
 * @brief Initialize iface message passing
 *
 * This function is not thread safe and should only be called once by DP.
 */
void iface_module_constructor(void)
{
	/* Read and store ip and port for socket communication between cp and
	 * dp*/
	read_interface_config();
#ifdef CP_BUILD
	printf("IFACE: CP Initialization\n");
#if defined SDN_ODL_BUILD
	register_comm_msg_cb(COMM_SOCKET,
				sdnODL_init,
				udp_send_socket,
				NULL,
				sdnODL_destroy);
	set_comm_type(COMM_SOCKET);
#else
	register_comm_msg_cb(COMM_SOCKET,
				udp_init_cp_socket,
				udp_send_socket,
				udp_recv_socket,
				NULL);
	set_comm_type(COMM_SOCKET);
#endif		/* SDN_ODL_BUILD  */
#else		/* CP_BUILD */
	RTE_LOG(NOTICE, DP, "IFACE: DP Initialization\n");
	register_comm_msg_cb(COMM_SOCKET,
				udp_init_dp_socket,
				udp_send_socket,
				udp_recv_socket,
				NULL);
#if defined(SDN_ODL_BUILD)
/* Code Rel. Jan 30, 2017
* Note: PCC, ADC, Session table initial creation on the DP sent over UDP by CP
* Needs to be from SDN controller as code & data models evolve
* For Jan 30, 2017 release, for flow updates over SDN controller
* register ZMQSUB socket after dp_session_table_create.
*/
	register_comm_msg_cb(COMM_ZMQ,
			zmq_init_socket,
			zmq_send_socket,
			zmq_recv_socket,
			zmq_destroy);
#endif
#endif	/* !CP_BUILD*/
}

void sig_handler(int signo)
{
	if (signo == SIGINT) {
#ifdef SDN_ODL_BUILD
#ifdef CP_BUILD
		clean_nb_listener_on_signal(signo);
		comm_node[COMM_SOCKET].destroy();
#else
		zmq_status_goodbye();
#endif
#endif
		rte_exit(EXIT_SUCCESS, "received SIGINT\n");
	}
}

