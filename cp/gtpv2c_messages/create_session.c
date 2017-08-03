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

#include <errno.h>

#include "packet_filters.h"
#include "gtpv2c_set_ie.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"

/** Table 7.2.1-1: Information Elements in a Create Session Request -
 *  incomplete list */
struct parse_create_session_request_t {
	uint8_t *bearer_context_to_be_created_ebi;
	fteid_ie *sender_fteid_ie_for_control_plane;
	fteid_ie *pgw_s5s8_gtpc_fteid;
	gtpv2c_ie *apn_ie;
	gtpv2c_ie *apn_restriction_ie;
	gtpv2c_ie *imsi_ie;
	gtpv2c_ie *mei_ie;
	gtpv2c_ie *msisdn_ie;
	gtpv2c_ie *apn_ambr_ie;
	gtpv2c_ie *pdn_type_ie;
	gtpv2c_ie *charging_characteristics_ie;
	gtpv2c_ie *bearer_qos_ie;
	gtpv2c_ie *bearer_tft_ie;
	gtpv2c_ie *indication_ie;
};

/**
 * parses gtpv2c message and populates parse_create_session_request_t structure
 * @param gtpv2c_rx
 *   buffer containing create bearer response message
 * @param csr
 *   data structure to contain required information elements from create
 *   create session response message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */

static int
parse_create_session_request(gtpv2c_header *gtpv2c_rx,
		struct parse_create_session_request_t *csr)
{
	gtpv2c_ie *current_ie;
	gtpv2c_ie *current_group_ie;
	gtpv2c_ie *limit_ie;
	gtpv2c_ie *limit_group_ie;

	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_ie, limit_ie)
	{
		if (current_ie->type == IE_BEARER_CONTEXT &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			FOR_EACH_GROUPED_IE(current_ie, current_group_ie,
					limit_group_ie)
			{
				if (current_group_ie->type == IE_EBI &&
					current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					csr->bearer_context_to_be_created_ebi =
					    IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t,
							    current_group_ie);
				} else if (current_group_ie->type ==
						IE_BEARER_QOS &&
						current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					csr->bearer_qos_ie = current_group_ie;
				} else if (current_group_ie->type == IE_EBI &&
						current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					csr->bearer_tft_ie = current_group_ie;
				}

			}
		} else if (current_ie->type == IE_FTEID &&
				current_ie->instance == IE_INSTANCE_ONE) {
			csr->pgw_s5s8_gtpc_fteid =
				IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie, current_ie);
		} else if (current_ie->type == IE_FTEID &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->sender_fteid_ie_for_control_plane =
			    IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie, current_ie);
		} else if (current_ie->type == IE_APN &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->apn_ie = current_ie;
		} else if (current_ie->type == IE_APN_RESTRICTION &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->apn_restriction_ie = current_ie;
		} else if (current_ie->type == IE_IMSI &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->imsi_ie = current_ie;
		} else if (current_ie->type == IE_AMBR &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->apn_ambr_ie = current_ie;
		} else if (current_ie->type == IE_PDN_TYPE &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->pdn_type_ie = current_ie;
		} else if (current_ie->type == IE_CHARGING_CHARACTERISTICS &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->charging_characteristics_ie = current_ie;
		} else if (current_ie->type == IE_INDICATION &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->indication_ie = current_ie;
		} else if (current_ie->type == IE_MEI &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->mei_ie = current_ie;
		} else if (current_ie->type == IE_MSISDN &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->msisdn_ie = current_ie;
		}
	}


	if (csr->indication_ie &&
			IE_TYPE_PTR_FROM_GTPV2C_IE(indication_ie,
					csr->indication_ie)->uimsi) {
		fprintf(stderr,
		    "Unauthenticated IMSI Not Yet Implemented - "
		    "Dropping packet\n");
		return -EPERM;
	}
	if (!csr->indication_ie
		|| !csr->apn_ie
		|| !csr->apn_restriction_ie
		|| !csr->bearer_context_to_be_created_ebi
		|| !csr->sender_fteid_ie_for_control_plane
		|| !csr->pgw_s5s8_gtpc_fteid
		|| !csr->imsi_ie
		|| !csr->apn_ambr_ie
		|| !csr->pdn_type_ie
		|| !csr->bearer_qos_ie
		|| !csr->msisdn_ie
		|| !IE_TYPE_PTR_FROM_GTPV2C_IE(pdn_type_ie,
				csr->pdn_type_ie)->ipv4) {
		fprintf(stderr, "Dropping packet\n");
		return -EPERM;
	}
	if (IE_TYPE_PTR_FROM_GTPV2C_IE(pdn_type_ie, csr->pdn_type_ie)->ipv6) {
		fprintf(stderr, "IPv6 Not Yet Implemented - Dropping packet\n");
		return GTPV2C_CAUSE_PREFERRED_PDN_TYPE_UNSUPPORTED;
	}
	return 0;
}

/**
 * from parameters, populates gtpv2c message 'create session response' and
 * populates required information elements as defined by
 * clause 7.2.2 3gpp 29.274
 * @param gtpv2c_tx
 *   transmission buffer to contain 'create session response' message
 * @param sequence
 *   sequence number as described by clause 7.6 3gpp 29.274
 * @param context
 *   UE Context data structure pertaining to the session to be created
 * @param pdn
 *   PDN Connection data structure pertaining to the session to be created
 * @param bearer
 *   Default EPS Bearer corresponding to the PDN Connection to be created
 */
static void
set_create_session_response(gtpv2c_header *gtpv2c_tx,
		uint32_t sequence, ue_context *context, pdn_connection *pdn,
		eps_bearer *bearer)
{

	set_gtpv2c_teid_header(gtpv2c_tx, GTP_CREATE_SESSION_RSP,
	    context->s11_mme_gtpc_teid, sequence);

	set_cause_accepted_ie(gtpv2c_tx, IE_INSTANCE_ZERO);
	set_ipv4_fteid_ie(gtpv2c_tx, GTPV2C_IFTYPE_S11S4_SGW_GTPC,
			IE_INSTANCE_ZERO,
			s11_sgw_ip, context->s11_sgw_gtpc_teid);
	set_ipv4_fteid_ie(gtpv2c_tx, GTPV2C_IFTYPE_S5S8_PGW_GTPC,
			IE_INSTANCE_ONE,
			pdn->s5s8_pgw_gtpc_ipv4, pdn->s5s8_pgw_gtpc_teid);
	set_ipv4_paa_ie(gtpv2c_tx, IE_INSTANCE_ZERO, pdn->ipv4);
	set_apn_restriction_ie(gtpv2c_tx, IE_INSTANCE_ZERO,
			pdn->apn_restriction);
	{
		gtpv2c_ie *bearer_context_group =
				create_bearer_context_ie(gtpv2c_tx,
		    IE_INSTANCE_ZERO);
		add_grouped_ie_length(bearer_context_group,
		    set_ebi_ie(gtpv2c_tx, IE_INSTANCE_ZERO,
				    bearer->eps_bearer_id));
		add_grouped_ie_length(bearer_context_group,
		    set_cause_accepted_ie(gtpv2c_tx, IE_INSTANCE_ZERO));
		add_grouped_ie_length(bearer_context_group,
		    set_ipv4_fteid_ie(gtpv2c_tx, GTPV2C_IFTYPE_S1U_SGW_GTPU,
				    IE_INSTANCE_ZERO, s1u_sgw_ip,
				    bearer->s1u_sgw_gtpu_teid));
		add_grouped_ie_length(bearer_context_group,
		    set_ipv4_fteid_ie(gtpv2c_tx, GTPV2C_IFTYPE_S5S8_PGW_GTPU,
				    IE_INSTANCE_TWO, pdn->s5s8_pgw_gtpc_ipv4,
				    bearer->s1u_sgw_gtpu_teid));
	}
}


int
process_create_session_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_tx)
{
	struct parse_create_session_request_t create_session_request = { 0 };
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;
	struct in_addr ue_ip;

	int ret = parse_create_session_request(gtpv2c_rx,
			&create_session_request);
	if (ret)
		return ret;

	apn *apn_requested = get_apn(
	    APN_PTR_FROM_APN_IE(create_session_request.apn_ie),
	    ntohs(create_session_request.apn_ie->length));

	if (!apn_requested)
		return GTPV2C_CAUSE_MISSING_UNKNOWN_APN;

	uint8_t ebi_index =
		*create_session_request.bearer_context_to_be_created_ebi - 5;

	ret = acquire_ip(&ue_ip);
	if (ret)
		return GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED;

	ret = create_ue_context(create_session_request.imsi_ie,
	    *create_session_request.bearer_context_to_be_created_ebi, &context);
	if (ret)
		return ret;

	if (create_session_request.mei_ie) {
		memcpy(&context->mei,
		    IE_TYPE_PTR_FROM_GTPV2C_IE(uint64_t,
				    create_session_request.mei_ie),
		    ntohs(create_session_request.mei_ie->length));
	}
	if (create_session_request.msisdn_ie) {
		memcpy(&context->msisdn,
		    IE_TYPE_PTR_FROM_GTPV2C_IE(uint64_t,
				    create_session_request.msisdn_ie),
		    ntohs(create_session_request.msisdn_ie->length));
	}

	context->s11_sgw_gtpc_ipv4 = s11_sgw_ip;
	context->s11_mme_gtpc_teid =
	    create_session_request.sender_fteid_ie_for_control_plane->
	    fteid_ie_hdr.teid_or_gre;
	context->s11_mme_gtpc_ipv4 = s11_mme_ip;

	pdn = context->pdns[ebi_index];
	{
		pdn->apn_in_use = apn_requested;
		pdn->apn_ambr = *IE_TYPE_PTR_FROM_GTPV2C_IE(ambr_ie,
		    create_session_request.apn_ambr_ie);
		pdn->apn_restriction = *IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t,
		    create_session_request.apn_restriction_ie);
		pdn->ipv4 = ue_ip;
		pdn->pdn_type = *IE_TYPE_PTR_FROM_GTPV2C_IE(pdn_type_ie,
		    create_session_request.pdn_type_ie);
		if (create_session_request.charging_characteristics_ie) {
			pdn->charging_characteristics =
				*IE_TYPE_PTR_FROM_GTPV2C_IE(
						charging_characteristics_ie,
						create_session_request.
						charging_characteristics_ie);
		}

		pdn->s5s8_pgw_gtpc_ipv4 =
				create_session_request.
				pgw_s5s8_gtpc_fteid->ip_u.ipv4;
		pdn->s5s8_pgw_gtpc_teid = context->s11_sgw_gtpc_teid;
	}
	bearer = context->eps_bearers[ebi_index];
	{
		/* TODO: Implement TFTs on default bearers
		if (create_session_request.bearer_tft_ie) {
		}
		*/
		bearer->qos = *IE_TYPE_PTR_FROM_GTPV2C_IE(bearer_qos_ie,
		    create_session_request.bearer_qos_ie);

		bearer->s1u_sgw_gtpu_ipv4 = s1u_sgw_ip;
		set_s1u_sgw_gtpu_teid(bearer, context);
	}

	set_create_session_response(gtpv2c_tx, gtpv2c_rx->teid_u.has_teid.seq,
			context, pdn, bearer);

	/* using the s1u_sgw_gtpu_teid as unique identifier to the session */
	struct session_info session;
	memset(&session, 0, sizeof(session));

	session.ue_addr.iptype = IPTYPE_IPV4;
	session.ue_addr.u.ipv4_addr = ntohl(pdn->ipv4.s_addr);
	session.ul_s1_info.sgw_teid = ntohl(bearer->s1u_sgw_gtpu_teid);
	session.ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
	session.ul_s1_info.sgw_addr.u.ipv4_addr =
			ntohl(bearer->s1u_sgw_gtpu_ipv4.s_addr);
	session.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
	session.ul_s1_info.enb_addr.u.ipv4_addr =
			ntohl(bearer->s1u_enb_gtpu_ipv4.s_addr);
	session.dl_s1_info.enb_teid = ntohl(bearer->s1u_enb_gtpu_teid);
	session.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
	session.dl_s1_info.enb_addr.u.ipv4_addr =
			ntohl(bearer->s1u_enb_gtpu_ipv4.s_addr);
	session.dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
	session.dl_s1_info.sgw_addr.u.ipv4_addr =
			ntohl(bearer->s1u_sgw_gtpu_ipv4.s_addr);
	session.apn_mtr_idx = 0;
	session.num_ul_pcc_rules = 1;
	session.ul_pcc_rule_id[0] = FIRST_FILTER_ID;
	session.num_dl_pcc_rules = 0;

	/* using ue ipv4 addr as unique identifier for an UE.
	 * and sess_id is combination of ue addr and bearer id.
	 * formula to set sess_id = (ue_ipv4_addr << 4) | bearer_id
	 */
	session.sess_id = SESS_ID(context->s11_sgw_gtpc_teid,
						bearer->eps_bearer_id);

	struct dp_id dp_id = { .id = DPN_ID };

	if (session_create(dp_id, session) < 0)
		rte_exit(EXIT_FAILURE,"Bearer Session create fail !!!");
	return 0;
}
