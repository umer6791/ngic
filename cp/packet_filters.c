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
#include <inttypes.h>

#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_acl.h>
#include <rte_cfgfile.h>

#include "packet_filters.h"
#include "vepc_cp_dp_api.h"
#include "ue.h"
#include "util.h"
#ifdef SDN_ODL_BUILD
#include "nb.h"
#endif

#define C_BURST_SIZE 3072
#define E_BURST_SIZE 3072

const char *direction_str[] = {
		[TFT_DIRECTION_DOWNLINK_ONLY] = "DOWNLINK_ONLY ",
		[TFT_DIRECTION_UPLINK_ONLY] = "UPLINK_ONLY   ",
		[TFT_DIRECTION_BIDIRECTIONAL] = "BIDIRECTIONAL " };

const packet_filter catch_all = {
		.direction = TFT_DIRECTION_BIDIRECTIONAL,
		.precedence = 0,
		.remote_ip_addr.s_addr = 0,
		.remote_ip_mask = 0,
		.remote_port_low = 0,
		.remote_port_high = UINT16_MAX,
		.proto = 0,
		.proto_mask = 0,
		.local_ip_addr.s_addr = 0,
		.local_ip_mask = 0,
		.local_port_low = 0,
		.local_port_high = UINT16_MAX, };

packet_filter *packet_filters[SDF_FILTER_TABLE_SIZE] = {
		[0] = NULL, /* index = 0 is invalid */
};

uint16_t num_packet_filters = FIRST_FILTER_ID;
uint32_t num_adc_rules;
uint32_t adc_rule_id[MAX_ADC_RULES];

static uint32_t name_to_num(char *name)
{
	uint32_t num = 0;
	int i;

	for (i = strlen(name) - 1; i >= 0; i--)
		num = (num << 4) | (name[i] - 'a');
	return num;
}
/**
 * Adds meter entry in the DP meter table
 * @param dl_gbr
 *   downlink guaranteed bit rate
 * @param index
 *   meter profile index
 */
static void
add_mtr_entry(uint64_t dl_gbr, uint16_t index)
{
	struct mtr_entry mtr_entry;
	struct dp_id dp_id = { .id = DPN_ID };
	/*cir expected value in Bytes, hence divide mbr by 8 */
	mtr_entry.mtr_param.cir = dl_gbr / 8;

	mtr_entry.mtr_param.cbs = C_BURST_SIZE;
	mtr_entry.mtr_param.ebs = E_BURST_SIZE;

	mtr_entry.metering_method = SRTCM_COLOR_BLIND;
	mtr_entry.mtr_profile_index = index;
	meter_profile_entry_add(dp_id, mtr_entry);
}

void
push_all_packet_filters(void)
{
	uint16_t i;

	for (i = FIRST_FILTER_ID; i < num_packet_filters; ++i)
		push_packet_filter(i);
}

void
push_packet_filter(uint16_t index)
{
	struct dp_id dp_id = { .id = DPN_ID };
	packet_filter *filter = packet_filters[index];

	char local_ip[INET_ADDRSTRLEN];
	char remote_ip[INET_ADDRSTRLEN];

	snprintf(local_ip, sizeof(local_ip), "%s",
	    inet_ntoa(filter->local_ip_addr));
	snprintf(remote_ip, sizeof(remote_ip), "%s",
	    inet_ntoa(filter->remote_ip_addr));

	struct pkt_filter pktf = {
			.pcc_rule_id = index,
			.precedence = filter->precedence,
	};

	if (filter->direction & TFT_DIRECTION_DOWNLINK_ONLY) {
		snprintf(pktf.u.rule_str, MAX_LEN, "%s/%"PRIu8" %s/%"PRIu8
			" %"PRIu16" : %"PRIu16" %"PRIu16" : %"PRIu16
			" 0x%"PRIx8"/0x%"PRIx8"\n",
			remote_ip, filter->remote_ip_mask, local_ip,
			filter->local_ip_mask,
			ntohs(filter->remote_port_low),
			ntohs(filter->remote_port_high),
			ntohs(filter->local_port_low),
			ntohs(filter->local_port_high),
			filter->proto, filter->proto_mask);
		if (filter->direction ==
				TFT_DIRECTION_BIDIRECTIONAL)
			fprintf(stderr, "Ignoring uplink portion of packet "
					"filter for now\n");
	} else if (filter->direction & TFT_DIRECTION_UPLINK_ONLY) {
		snprintf(pktf.u.rule_str, MAX_LEN, "%s/%"PRIu8" %s/%"PRIu8" %"
			PRIu16" : %"PRIu16" %"PRIu16" : %"PRIu16" 0x%"
			PRIx8"/0x%"PRIx8"\n",
			local_ip, filter->local_ip_mask, remote_ip,
			filter->remote_ip_mask,
			ntohs(filter->local_port_low),
			ntohs(filter->local_port_high),
			ntohs(filter->remote_port_low),
			ntohs(filter->remote_port_high),
			filter->proto, filter->proto_mask);
	}

	printf("Installing %s pkt_filter #%"PRIu16" p-%"PRIu8": %s",
	    direction_str[filter->direction], index, filter->precedence,
	    pktf.u.rule_str);

	struct pcc_rules pcc_entry = {
			.gate_status = OPEN,
			.rating_group = filter->rating_group,
			.monitoring_key = 0,
			.rule_status = 0,
			.report_level = 0,
			.charging_mode = 0,
			.drop_pkt_count = 0,
			.mute_notify = 0,
			.metering_method = 0,
			.session_cont = 0,
			.precedence = filter->precedence,
			.redirect_info.info = 0,
			.service_id = 0,
			.rule_id = index,
			.mtr_profile_index = index,
	};

	memset(pcc_entry.sponsor_id, 0, sizeof(pcc_entry.sponsor_id));
	strncpy(pcc_entry.rule_name, "SimuRule", sizeof(pcc_entry.rule_name));

	if (pcc_entry_add(dp_id, pcc_entry) < 0 )
		rte_exit(EXIT_FAILURE,"PCC entry add fail !!!");

	if (sdf_filter_entry_add(dp_id, pktf) < 0)
		rte_exit(EXIT_FAILURE,"SDF filter entry add fail !!!");
}

int
install_packet_filter(const packet_filter *new_packet_filter,
		uint64_t dl_mbr)
{
	if (num_packet_filters >= SDF_FILTER_TABLE_SIZE)
		return -ENOMEM;

	packet_filter *filter = rte_zmalloc_socket(NULL, sizeof(packet_filter),
	    RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (filter == NULL) {
		fprintf(stderr, "Failure to allocate dedicated packet filter "
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return -ENOMEM;
	}

	memcpy(filter, new_packet_filter, sizeof(packet_filter));
	uint16_t index = num_packet_filters;

	add_mtr_entry(dl_mbr, index);
	num_packet_filters++;
	packet_filters[index] = filter;

#ifdef SDN_ODL_BUILD
	if (dpn_id)
		push_packet_filter(index);
#else
	push_packet_filter(index);
#endif
	return index;
}

int
get_packet_filter_id(const packet_filter *pf)
{
	uint16_t index;
	for (index = FIRST_FILTER_ID; index < num_packet_filters; ++index) {
		if (!memcmp(pf, packet_filters[index], sizeof(packet_filter)))
			return index;
	}
	return -ENOENT;
}


uint8_t
get_packet_filter_direction(uint16_t index)
{
	return packet_filters[index]->direction;
}


packet_filter *
get_packet_filter(uint16_t index)
{
	if (unlikely(index >= num_packet_filters))
		return NULL;
	return packet_filters[index];
}


void
reset_packet_filter(packet_filter *pf)
{
	memcpy(pf, &catch_all, sizeof(packet_filter));
}


void
init_packet_filters(void)
{
	unsigned num_packet_filters = 0;
	unsigned i = 0;
	struct rte_cfgfile *file = rte_cfgfile_load(STATIC_PCC_FILE, 0);
	const char *entry;

	if (file == NULL)
		rte_panic("Cannot load configuration file %s\n",
				STATIC_PCC_FILE);

	entry = rte_cfgfile_get_entry(file, "GLOBAL", "NUM_PACKET_FILTERS");

	if (!entry)
		rte_panic("Invalid pcc configuration file format\n");


	num_packet_filters = atoi(entry);

	for (i = 0; i < num_packet_filters; ++i) {
		char sectionname[64];
		uint64_t mbr = 0xffffffff;
		int ret;
		struct in_addr tmp_addr;
		packet_filter pf;
		reset_packet_filter(&pf);
		snprintf(sectionname, sizeof(sectionname),
				"PACKET_FILTER_%u", i);

		entry = rte_cfgfile_get_entry(file, sectionname,
				"RATING_GROUP");
		if (!entry)
			rte_panic(
			    "Invalid pcc configuration file format - "
			    "each filter must contain RATING_GROUP entry\n");

		pf.rating_group = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "MBR");
		if (!entry)
			rte_panic(
			    "Invalid pcc configuration file format - "
			    "each filter must contain MBR entry\n");

		mbr = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "DIRECTION");
		if (entry) {
			if (strcmp(entry, "bidirectional") == 0)
				pf.direction = TFT_DIRECTION_BIDIRECTIONAL;
			else if (strcmp(entry, "uplink_only") == 0)
				pf.direction = TFT_DIRECTION_UPLINK_ONLY;
			else if (strcmp(entry, "downlink_only") == 0)
				pf.direction = TFT_DIRECTION_DOWNLINK_ONLY;
		}

		entry = rte_cfgfile_get_entry(file, sectionname, "PRECEDENCE");
		if (entry)
			pf.precedence = atoi(entry);


		entry = rte_cfgfile_get_entry(file, sectionname, "IPV4_REMOTE");
		if (entry) {
			if (inet_aton(entry, &pf.remote_ip_addr) == 0)
				rte_panic("Invalid address %s in section %s "
						"pcc config file %s\n",
				    entry, sectionname, STATIC_PCC_FILE);
		}

		entry = rte_cfgfile_get_entry(file, sectionname,
				"IPV4_REMOTE_MASK");
		if (entry) {
			ret = inet_aton(entry, &tmp_addr);
			if (ret == 0
			    || __builtin_clzl(~tmp_addr.s_addr)
			    + __builtin_ctzl(tmp_addr.s_addr) != 32)
				rte_panic("Invalid address %s in section %s "
					"pcc config file %s\n",
					entry, sectionname, STATIC_PCC_FILE);
			pf.remote_ip_mask =
					__builtin_popcountl(tmp_addr.s_addr);
		}

		entry = rte_cfgfile_get_entry(file, sectionname,
				"REMOTE_LOW_LIMIT_PORT");
		if (entry)
			pf.remote_port_low = htons((uint16_t) atoi(entry));


		entry = rte_cfgfile_get_entry(file, sectionname,
				"REMOTE_HIGH_LIMIT_PORT");
		if (entry)
			pf.remote_port_high = htons((uint16_t) atoi(entry));


		entry = rte_cfgfile_get_entry(file, sectionname, "PROTOCOL");
		if (entry) {
			pf.proto = atoi(entry);
			pf.proto_mask = UINT8_MAX;
		}

		entry = rte_cfgfile_get_entry(file, sectionname, "IPV4_LOCAL");
		if (entry) {
			if (inet_aton(entry, &pf.local_ip_addr) == 0)
				rte_panic("Invalid address %s in section %s "
						"pcc config file %s\n",
				    entry, sectionname, STATIC_PCC_FILE);
		}

		entry = rte_cfgfile_get_entry(file, sectionname,
				"IPV4_LOCAL_MASK");
		if (entry) {
			ret = inet_aton(entry, &tmp_addr);
			if (ret == 0
			    || __builtin_clzl(~tmp_addr.s_addr)
			    + __builtin_ctzl(tmp_addr.s_addr) != 32)
				rte_panic("Invalid address %s in section %s "
						"pcc config file %s\n",
				    entry, sectionname, STATIC_PCC_FILE);
			pf.local_ip_mask = __builtin_popcountl(tmp_addr.s_addr);
		}

		entry = rte_cfgfile_get_entry(file, sectionname,
				"LOCAL_LOW_LIMIT_PORT");
		if (entry)
			pf.local_port_low = htons((uint16_t) atoi(entry));


		entry = rte_cfgfile_get_entry(file, sectionname,
				"LOCAL_HIGH_LIMIT_PORT");
		if (entry)
			pf.local_port_high = htons((uint16_t) atoi(entry));


		ret = install_packet_filter(&pf, mbr);
		if (ret < 0) {
			rte_panic("Failure to install packet filters: "
					"%s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);
		}
	}
}

static void print_adc_rule(struct adc_rules *adc_rule)
{
	printf("%-8u ", adc_rule->rule_id);
	switch (adc_rule->sel_type) {
	case DOMAIN_IP_ADDR:
		printf("%-10s " IPV4_ADDR, "IP",
			IPV4_ADDR_HOST_FORMAT(adc_rule->u.domain_ip.u.ipv4_addr));
		break;
	case DOMAIN_IP_ADDR_PREFIX:
		printf("%-10s " IPV4_ADDR"/%d ", "IP_PREFIX",
			IPV4_ADDR_HOST_FORMAT(adc_rule->u.domain_prefix.ip_addr.u.ipv4_addr),
			adc_rule->u.domain_prefix.prefix);
		break;
	case DOMAIN_NAME:
		printf("%-10s %-35s ", "DOMAIN", adc_rule->u.domain_name);
		break;
	default:
		printf("ERROR IN ADC RULE");
	}
	printf("%8s %15s %15u %15u %15s %15s <\n",
			(adc_rule->gate_status == CLOSE) ? "CLOSE" : "OPEN",
			adc_rule->sponsor_id,
			adc_rule->service_id,
			adc_rule->rating_group,
			adc_rule->tarriff_group,
			adc_rule->tarriff_time);
}

void parse_adc_rules(void)
{
	FILE *adc_rule_file = fopen(ADC_RULE_FILE, "r");
	struct dp_id dp_id = { .id = DPN_ID };

	if (!adc_rule_file)
		rte_exit(EXIT_FAILURE, "Cannot open file: %s\n",
				ADC_RULE_FILE);

	uint32_t lines = 1, line = 0;
	uint32_t longest_line = 0, line_length = 0;
	const char *delimit = " \n\t";
	struct in_addr addr;

	while (!feof(adc_rule_file)) {
		char ch = fgetc(adc_rule_file);

		if (ch == '\n') {
			++lines;
			if (longest_line < line_length)
				longest_line = line_length + 1;
			line_length = 0;
		} else {
			line_length++;
		}
	}
	rewind(adc_rule_file);
	clearerr(adc_rule_file);
	char *buffer = (char *)rte_malloc_socket(NULL, sizeof(char) * longest_line,
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (buffer == NULL)
		rte_panic("Failure to allocate adc file buffer: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);

	uint32_t rule_id = 1;

	for (line = 0; line < lines && !feof(adc_rule_file); ++line) {
		struct adc_rules entry = { 0 };
		char in;
		*buffer = '\0';
		while (fread(&in, 1, 1, adc_rule_file)) {
			if (in == '\n')
				break;
			strncat(buffer, &in, 1);
		}

		if (*buffer == '#' || *buffer == '\n')
			continue;

		{ /* determine rule (if any)*/
			char *rule_str = strtok(buffer, delimit);

			if (rule_str != NULL) {
				char *t;

				/* assume IP unless '/' or alpha is encountered*/
				entry.sel_type = DOMAIN_IP_ADDR;
				for (t = rule_str; *t; ++t) {
					if (isalpha(*t)) {
						entry.sel_type = DOMAIN_NAME;
						strcpy(entry.u.domain_name, rule_str);
						break;
					} else if (*t == '/') {
						*t = '\0';
						entry.sel_type = DOMAIN_IP_ADDR_PREFIX;
						entry.u.domain_prefix.prefix =
							strtol(t+1, NULL, 10);

						inet_aton(rule_str, &addr);
						entry.u.domain_prefix.ip_addr.u.ipv4_addr = ntohl(addr.s_addr);

						break;
					} else if (*t != '.' && !isdigit(*t)) {
						rte_exit(EXIT_FAILURE, "Unexpected char in %s file :%s\n", ADC_RULE_FILE, rule_str);
						break;
					}
				}

				if (entry.sel_type == DOMAIN_IP_ADDR) {
					inet_aton(rule_str, &addr);
					entry.u.domain_ip.u.ipv4_addr = ntohl(addr.s_addr);
					entry.u.domain_ip.iptype = IPTYPE_IPV4;
				}
			} else
				continue;
		}
		{
			char *sponsor_id = strtok(NULL, delimit);

			if (sponsor_id != NULL) {
				entry.gate_status = strcmp(sponsor_id, "DROP");
				if (entry.gate_status == CLOSE)
					sponsor_id = strtok(NULL, delimit);
				if (sponsor_id != NULL)
					strcpy(entry.sponsor_id, sponsor_id);
			}
		}
		{
			char *service_id = strtok(NULL, delimit);

			if (service_id != NULL) {
				entry.service_id = name_to_num(service_id);

				if (!strcmp(service_id, "CIPA"))
					puts("CIPA Rule");
			}
		}
		{
			char *rate_group = strtok(NULL, delimit);

			if (rate_group)
				entry.rating_group = name_to_num(rate_group);
		}
		{
			char *tarriff_group = strtok(NULL, delimit);

			if (tarriff_group)
				strcpy(entry.tarriff_group, tarriff_group);
		}
		{
			char *tarriff_time = strtok(NULL, delimit);

			if (tarriff_time)
				strcpy(entry.tarriff_time, tarriff_time);
		}

		entry.precedence = 0x1ffffffe;
		memset(entry.rule_name, 0, sizeof(entry.rule_name));
		/* Add default rule */
		adc_rule_id[rule_id - 1] = rule_id;
		entry.rule_id = rule_id++;
		if (adc_entry_add(dp_id, entry) < 0)
			rte_exit(EXIT_FAILURE, "ADC entry add fail !!!");
		print_adc_rule(&entry);
	}
	num_adc_rules = rule_id - 1;
	rte_free(buffer);
}
