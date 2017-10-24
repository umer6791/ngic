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

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <getopt.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <pcap.h>
#include <signal.h>

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_errno.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>

#include <rte_common.h>
#include <rte_acl.h>
#include <rte_ip.h>

#include "gtpv2c.h"
#include "gtpv2c_ie.h"
#include "debug_str.h"
#include "ue.h"
#include "interface.h"
#include "packet_filters.h"
#include "dp_ipc_api.h"
#include "cp.h"
#include "cp_stats.h"
#ifdef SDN_ODL_BUILD
#include "nb.h"
#endif

#define PCAP_TTL                     (64)
#define PCAP_VIHL                    (0x0045)

#define S11_SGW_IP_SET               (0x01)
#define S11_MME_IP_SET               (0x02)
#define S1U_SGW_IP_SET               (0x04)
#define IP_POOL_IP_SET               (0x08)
#define IP_POOL_MASK_SET             (0x10)
#define APN_NAME_SET                 (0x20)
#define REQ_ARGS                     (S11_SGW_IP_SET | S11_MME_IP_SET | \
					S1U_SGW_IP_SET | IP_POOL_IP_SET | \
					IP_POOL_MASK_SET | APN_NAME_SET)

int s11_fd = -1;
int s11_pcap_fd = -1;

pcap_dumper_t *pcap_dumper;
pcap_t *pcap_reader;

struct cp_params cp_params;


/**
 * Parses c-string containing dotted decimal ipv4 and stores the
 *   value within the in_addr type
 *
 * @param optarg
 *   c-string containing dotted decimal ipv4 address
 * @param addr
 *   destination of parsed IP string
 */
static void
parse_arg_ip(const char *optarg, struct in_addr *addr)
{
	if (!inet_aton(optarg, addr))
		rte_panic("Invalid argument - %s - Exiting.\n", optarg);
}

/**
 *
 * Parses non-dpdk command line program arguments for control plane
 *
 * @param argc
 *   number of arguments
 * @param argv
 *   array of c-string arguments
 */
static void
parse_arg(int argc, char **argv)
{
	char errbuff[PCAP_ERRBUF_SIZE];
	int args_set = 0;
	int c = 0;
	pcap_t *pcap;

	const struct option long_options[] = {
	  {"s11_sgw_ip",  required_argument, NULL, 's'},
	  {"s11_mme_ip",  required_argument, NULL, 'm'},
	  {"s1u_sgw_ip",  required_argument, NULL, 'w'},
	  {"ip_pool_ip",  required_argument, NULL, 'i'},
	  {"ip_pool_mask", required_argument, NULL, 'p'},
	  {"apn_name",   required_argument, NULL, 'a'},
	  {"pcap_file_in", required_argument, NULL, 'x'},
	  {"pcap_file_out", required_argument, NULL, 'y'},
	  {0, 0, 0, 0}
	};

	do {
		int option_index = 0;

		c = getopt_long(argc, argv, "s:m:w:i:p:a:x:y:", long_options,
		    &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 's':
			parse_arg_ip(optarg, &s11_sgw_ip);
			args_set |= S11_SGW_IP_SET;
			break;
		case 'm':
			parse_arg_ip(optarg, &s11_mme_ip);
			args_set |= S11_MME_IP_SET;
			break;
		case 'i':
			set_ip_pool_ip(optarg);
			args_set |= S1U_SGW_IP_SET;
			break;
		case 'p':
			set_ip_pool_mask(optarg);
			args_set |= IP_POOL_IP_SET;
			break;
		case 'w':
			parse_arg_ip(optarg, &s1u_sgw_ip);
			args_set |= IP_POOL_MASK_SET;
			break;
		case 'a':
			set_apn_name(&one_apn, optarg);
			args_set |= APN_NAME_SET;
			break;
		case 'x':
			pcap_reader = pcap_open_offline(optarg, errbuff);
			break;
		case 'y':
			pcap = pcap_open_dead(DLT_EN10MB, UINT16_MAX);
			pcap_dumper = pcap_dump_open(pcap, optarg);
			s11_pcap_fd = pcap_fileno(pcap);
			break;
		default:
			rte_panic("Unknown argument - %s.", argv[optind]);
			break;
		}
	} while (c != -1);
	if ((args_set & REQ_ARGS) != REQ_ARGS) {
		fprintf(stderr, "Usage: %s\n", argv[0]);
		for (c = 0; long_options[c].name; ++c) {
			fprintf(stderr, "\t[ -%s | -%c ] %s\n",
					long_options[c].name,
					long_options[c].val,
					long_options[c].name);
		}
		rte_panic("\n");
	}
}

void
initialize_tables_on_dp(void)
{
#ifdef CP_DP_TABLE_CONFIG
	struct dp_id dp_id = { .id = DPN_ID };

	sprintf(dp_id.name, SDF_FILTER_TABLE);
	if (sdf_filter_table_create(dp_id, SDF_FILTER_TABLE_SIZE))
		rte_panic("sdf_filter_table creation failed\n");

	sprintf(dp_id.name, ADC_TABLE);
	if (adc_table_create(dp_id, ADC_TABLE_SIZE))
		rte_panic("adc_table creation failed\n");

	sprintf(dp_id.name, PCC_TABLE);
	if (pcc_table_create(dp_id, PCC_TABLE_SIZE))
		rte_panic("pcc_table creation failed\n");

	sprintf(dp_id.name, METER_PROFILE_SDF_TABLE);
	if (meter_profile_table_create(dp_id, METER_PROFILE_SDF_TABLE_SIZE))
		rte_panic("meter_profile_sdf_table creation failed\n");

	sprintf(dp_id.name, SESSION_TABLE);

	if (session_table_create(dp_id, LDB_ENTRIES_DEFAULT))
		rte_panic("session_table creation failed\n");
#endif

}


/**
 * @brief Initalizes S11 interface if in use
 */
static void
init_s11(void)
{
	const in_port_t s11_port = htons(GTPC_UDP_PORT);
	struct sockaddr_in sgw_s11_sockaddr_in;
	int ret;

	if (pcap_reader != NULL && pcap_dumper != NULL)
		return;

	s11_fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (s11_fd < 0)
		rte_panic("Socket call error : %s", strerror(errno));

	bzero(sgw_s11_sockaddr_in.sin_zero,
			sizeof(sgw_s11_sockaddr_in.sin_zero));
	sgw_s11_sockaddr_in.sin_family = AF_INET;
	sgw_s11_sockaddr_in.sin_port = s11_port;
	sgw_s11_sockaddr_in.sin_addr = s11_sgw_ip;

	ret = bind(s11_fd, (struct sockaddr *) &sgw_s11_sockaddr_in,
			    sizeof(struct sockaddr_in));

	if (ret < 0) {
		rte_panic("Bind error for %s:%u - %s\n",
			inet_ntoa(sgw_s11_sockaddr_in.sin_addr),
			ntohs(sgw_s11_sockaddr_in.sin_port),
			strerror(errno));
	}
}


/**
 * @brief
 * Initializes Control Plane data structures, packet filters, and calls for the
 * Data Plane to create required tables
 */
static void
init_cp(void)
{
	init_s11();

	iface_module_constructor();

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		rte_exit(EXIT_FAILURE, "Error:can't catch SIGINT\n");


#ifndef SDN_ODL_BUILD
#ifdef CP_DP_TABLE_CONFIG
	initialize_tables_on_dp();
#endif
	parse_adc_rules();
	init_packet_filters();
#endif

	create_ue_hash();
}


/**
 * @brief
 * Writes packet at @tx_buf of length @payload_length to pcap file specified
 * in @pcap_dumper (global)
 */
static void
dump_pcap(uint16_t payload_length, uint8_t *tx_buf)
{
	static struct pcap_pkthdr pcap_tx_header;
	gettimeofday(&pcap_tx_header.ts, NULL);
	pcap_tx_header.caplen = payload_length
			+ sizeof(struct ether_hdr)
			+ sizeof(struct ipv4_hdr)
			+ sizeof(struct udp_hdr);
	pcap_tx_header.len = payload_length
			+ sizeof(struct ether_hdr)
			+ sizeof(struct ipv4_hdr)
			+ sizeof(struct udp_hdr);
	uint8_t dump_buf[MAX_GTPV2C_UDP_LEN
			+ sizeof(struct ether_hdr)
			+ sizeof(struct ipv4_hdr)
			+ sizeof(struct udp_hdr)];
	struct ether_hdr *eh = (struct ether_hdr *) dump_buf;

	memset(&eh->d_addr, '\0', sizeof(struct ether_addr));
	memset(&eh->s_addr, '\0', sizeof(struct ether_addr));
	eh->ether_type = htons(ETHER_TYPE_IPv4);

	struct ipv4_hdr *ih = (struct ipv4_hdr *) &eh[1];

	ih->dst_addr = s11_mme_ip.s_addr;
	ih->src_addr = s11_sgw_ip.s_addr;
	ih->next_proto_id = IPPROTO_UDP;
	ih->version_ihl = PCAP_VIHL;
	ih->total_length =
			ntohs(payload_length
				+ sizeof(struct udp_hdr)
				+ sizeof(struct ipv4_hdr));
	ih->time_to_live = PCAP_TTL;

	struct udp_hdr *uh = (struct udp_hdr *) &ih[1];

	uh->dgram_len = htons(
	    ntohs(ih->total_length) - sizeof(struct ipv4_hdr));
	uh->dst_port = htons(GTPC_UDP_PORT);
	uh->src_port = htons(GTPC_UDP_PORT);

	void *payload = &uh[1];
	memcpy(payload, tx_buf, payload_length);
	pcap_dump((u_char *) pcap_dumper, &pcap_tx_header,
			dump_buf);
	fflush(pcap_dump_file(pcap_dumper));
}


void
control_plane(void)
{
	int ret;
	uint8_t rx_buf[MAX_GTPV2C_UDP_LEN] = { 0 };
	uint8_t tx_buf[MAX_GTPV2C_UDP_LEN] = { 0 };
	gtpv2c_header *gtpv2c_rx = (gtpv2c_header *) rx_buf;
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *) tx_buf;

	uint16_t payload_length;
	struct sockaddr_in peer = { .sin_port = 0};
	socklen_t peer_len = sizeof(peer);

	uint8_t delay = 0; /*TODO move this when more implemented?*/
	int bytes_rx, bytes_tx;

	if (pcap_reader) {
		static struct pcap_pkthdr *pcap_rx_header;
		const u_char *t;
		const u_char **tmp = &t;
		ret = pcap_next_ex(pcap_reader, &pcap_rx_header, tmp);
		if (ret < 0) {
			printf("Finished reading from pcap file"
					" - exiting\n");
			exit(0);
		}
		bytes_rx = pcap_rx_header->caplen
				- (sizeof(struct ether_hdr)
				+ sizeof(struct ipv4_hdr)
				+ sizeof(struct udp_hdr));
		memcpy(gtpv2c_rx, *tmp
				+ (sizeof(struct ether_hdr)
				+ sizeof(struct ipv4_hdr)
				+ sizeof(struct udp_hdr)), bytes_rx);

	} else {
		bytes_rx = recvfrom(s11_fd, rx_buf,
				MAX_GTPV2C_UDP_LEN, MSG_DONTWAIT,
				(struct sockaddr *) &peer, &peer_len);
		if (bytes_rx < 0 && (errno == EAGAIN  || errno == EWOULDBLOCK))
			return;
	}

	if (bytes_rx == 0) {
		fprintf(stderr, "recvfrom error for %s:%u - %s\n",
				inet_ntoa(peer.sin_addr), peer.sin_port,
				strerror(errno));
		return;
	} else if ((unsigned)bytes_rx != (ntohs(gtpv2c_rx->gtpc.length)
			+ sizeof(gtpv2c_rx->gtpc))) {
		ret = GTPV2C_CAUSE_INVALID_LENGTH;
		/* According to 29.274 7.7.7, if message is request,
		 * reply with cause = GTPV2C_CAUSE_INVALID_LENGTH
		 *  should be sent - ignoring packet for now
		 */
		fprintf(stderr, "Received UDP Payload (%d bytes) with gtpv2c + "
				"header (%u + %lu) = %lu bytes\n",
				bytes_rx, ntohs(gtpv2c_rx->gtpc.length),
				sizeof(gtpv2c_rx->gtpc),
				ntohs(gtpv2c_rx->gtpc.length)
				+ sizeof(gtpv2c_rx->gtpc));
		return;
	}

	++cp_stats.rx;

	if (!pcap_reader && (peer.sin_addr.s_addr != s11_mme_ip.s_addr
			|| gtpv2c_rx->gtpc.version != GTP_VERSION_GTPV2C)) {
		fprintf(stderr, "Discarding packet from %s:%u - "
				"Expected S11_MME_IP = %s\n",
				inet_ntoa(peer.sin_addr), ntohs(peer.sin_port),
				inet_ntoa(s11_mme_ip));
		return;
	}

	switch (gtpv2c_rx->gtpc.type) {
	case GTP_CREATE_SESSION_REQ:
		ret = process_create_session_request(
				gtpv2c_rx, gtpv2c_tx);
		break;
	case GTP_DELETE_SESSION_REQ:
		ret = process_delete_session_request(
				gtpv2c_rx, gtpv2c_tx);
		break;
	case GTP_MODIFY_BEARER_REQ:
		ret = process_modify_bearer_request(
				gtpv2c_rx, gtpv2c_tx);
		break;
	case GTP_RELEASE_ACCESS_BEARERS_REQ:
		ret = process_release_access_bearer_request(
				gtpv2c_rx, gtpv2c_tx);
		break;
	case GTP_BEARER_RESOURCE_CMD:
		ret = process_bearer_resource_command(
				gtpv2c_rx, gtpv2c_tx);
		break;
	case GTP_ECHO_REQ:
		ret = process_echo_request(gtpv2c_rx, gtpv2c_tx);
		break;
	case GTP_CREATE_BEARER_RSP:
		ret = process_create_bearer_response(gtpv2c_rx);
		break;
	case GTP_DELETE_BEARER_RSP:
		ret = process_delete_bearer_response(gtpv2c_rx);
		break;
	case GTP_DOWNLINK_DATA_NOTIFICATION_ACK:
		ret = process_ddn_ack(gtpv2c_rx, &delay);
		/* TODO something with delay if set */
		break;
	default:
		fprintf(stderr, "Received unprocessed GTPv2c Message Type: "
				"%s (%u 0x%x)... Discarding\n",
				gtp_type_str(gtpv2c_rx->gtpc.type),
				gtpv2c_rx->gtpc.type,
				gtpv2c_rx->gtpc.type);
		return;
	}

	if (ret) {
		fprintf(stderr, "Error on message %s: (%d) %s\n",
				gtp_type_str(gtpv2c_rx->gtpc.type), ret,
				(ret < 0 ? strerror(-ret) : cause_str(ret)));
		/* S11 error handling not implemented */
		return;
	}

	switch (gtpv2c_rx->gtpc.type) {
	case GTP_CREATE_BEARER_RSP:
		cp_stats.create_bearer++;
		return;
	case GTP_DELETE_BEARER_RSP:
		cp_stats.delete_bearer++;
		return;
	case GTP_DOWNLINK_DATA_NOTIFICATION_ACK:
		cp_stats.ddn_ack++;
		return;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.length)
			+ sizeof(gtpv2c_tx->gtpc);

	if (pcap_dumper) {
		dump_pcap(payload_length, tx_buf);
	} else {
		bytes_tx = sendto(s11_fd, tx_buf, payload_length, 0,
			(struct sockaddr *) &peer, peer_len);

		if (bytes_tx != (int) payload_length) {
			fprintf(stderr, "Transmitted Incomplete GTPv2c Message:"
					"%u of %d tx bytes\n",
					payload_length, bytes_tx);
		}
	}

	++cp_stats.tx;

	switch (gtpv2c_rx->gtpc.type) {
	case GTP_CREATE_SESSION_REQ:
		cp_stats.create_session++;
		break;
	case GTP_DELETE_SESSION_REQ:
		cp_stats.delete_session++;
		break;
	case GTP_MODIFY_BEARER_REQ:
		cp_stats.modify_bearer++;
		break;
	case GTP_RELEASE_ACCESS_BEARERS_REQ:
		cp_stats.rel_access_bearer++;
		break;
	case GTP_ECHO_REQ:
		cp_stats.echo++;
		break;
	case GTP_BEARER_RESOURCE_CMD:
		cp_stats.bearer_resource++;
		break;
	}

	bzero(&tx_buf, sizeof(tx_buf));

}

int
ddn_by_session_id(uint64_t session_id) {
	uint8_t tx_buf[MAX_GTPV2C_UDP_LEN] = { 0 };
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *) tx_buf;
	uint32_t sgw_s11_gtpc_teid = UE_SESS_ID(session_id);
	ue_context *context = NULL;
	static uint32_t ddn_sequence = 1;

	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &sgw_s11_gtpc_teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	ret = create_downlink_data_notification(context,
			UE_BEAR_ID(session_id),
			ddn_sequence,
			gtpv2c_tx);

	if (ret)
		return ret;

	struct sockaddr_in mme_s11_sockaddr_in = {
		.sin_family = AF_INET,
		.sin_port = htons(GTPC_UDP_PORT),
		.sin_addr = context->s11_mme_gtpc_ipv4,
		.sin_zero = {0},
	};

	uint16_t payload_length = ntohs(gtpv2c_tx->gtpc.length)
			+ sizeof(gtpv2c_tx->gtpc);

	if (pcap_dumper) {
		dump_pcap(payload_length, tx_buf);
	} else {
		uint32_t bytes_tx = sendto(s11_fd, tx_buf, payload_length, 0,
		    (struct sockaddr *) &mme_s11_sockaddr_in,
		    sizeof(mme_s11_sockaddr_in));

		if (bytes_tx != (int) payload_length) {
			fprintf(stderr, "Transmitted Incomplete GTPv2c Message:"
					"%u of %d tx bytes\n",
					payload_length, bytes_tx);
		}
	}
	ddn_sequence += 2;
	++cp_stats.ddn;

	return 0;
}

#ifndef SDN_ODL_BUILD
/**
 * @brief callback to handle downlink data notification messages from the
 * data plane
 * @param msg_payload
 * message payload received by control plane from the data plane
 * @return
 * 0 inicates success, error otherwise
 */
static int
cb_ddn(struct msgbuf *msg_payload)
{
	int ret = ddn_by_session_id(msg_payload->msg_union.sess_entry.sess_id);

	if (ret) {
		fprintf(stderr, "Error on DDN Handling %s: (%d) %s\n",
				gtp_type_str(ret), ret,
				(ret < 0 ? strerror(-ret) : cause_str(ret)));
	}
	return ret;
}

/**
 * @brief callback initated by nb listener thread
 * @param arg
 * unused
 * @return
 * never returns
 */
static int
listener(__rte_unused void *arg)
{
	iface_init_ipc_node();
	iface_ipc_register_msg_cb(MSG_DDN, cb_ddn);
	while (1)
		iface_process_ipc_msgs();
	return 0;
}
#endif

/**
 * @brief initializes the core assignments for various control plane threads
 */
static void
init_cp_params(void) {
	unsigned last_lcore = rte_get_master_lcore();

#ifndef SDN_ODL_BUILD
	cp_params.nb_core_id = rte_get_next_lcore(last_lcore, 1, 0);

	if (cp_params.nb_core_id == RTE_MAX_LCORE)
		rte_panic("Insufficient cores in coremask to "
				"spawn nb thread\n");
	last_lcore = cp_params.nb_core_id;
#endif

	cp_params.stats_core_id = rte_get_next_lcore(last_lcore, 1, 0);
	if (cp_params.stats_core_id == RTE_MAX_LCORE)
		fprintf(stderr, "Insufficient cores in coremask to "
				"spawn stats thread\n");
	last_lcore = cp_params.stats_core_id;
}

/**
 * Main function - initializes dpdk environment, parses command line arguments,
 * calls initialization function, and spawns stats and control plane function
 * @param argc
 *   number of arguments
 * @param argv
 *   array of c-string arguments
 * @return
 *   returns 0
 */
int
main(int argc, char **argv)
{
	int ret;
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	parse_arg(argc - ret, argv + ret);
	printf("s11_sgw_ip:  %s\n", inet_ntoa(s11_sgw_ip));
	printf("s11_mme_ip:  %s\n", inet_ntoa(s11_mme_ip));
	printf("s1u_sgw_ip:  %s\n", inet_ntoa(s1u_sgw_ip));

	init_cp_params();
	init_cp();

	if (cp_params.stats_core_id != RTE_MAX_LCORE)
		rte_eal_remote_launch(do_stats, NULL, cp_params.stats_core_id);

#ifdef SDN_ODL_BUILD
	init_nb();
	server();
#else
	if (cp_params.nb_core_id != RTE_MAX_LCORE)
		rte_eal_remote_launch(listener, NULL, cp_params.nb_core_id);

	while (1)
		control_plane();
#endif

	return 0;
}

