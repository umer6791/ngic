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

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>

#include <rte_ether.h>
#include <rte_debug.h>

#include "cdr.h"
#include "util.h"

FILE *cdr_file;


const char *
iptoa(struct ip_addr addr)
{
	static char buffer[40];
	switch (addr.iptype) {
	case IPTYPE_IPV4:
		snprintf(buffer, sizeof(buffer), IPV4_ADDR,
				IPV4_ADDR_HOST_FORMAT(addr.u.ipv4_addr));
		break;
	case IPTYPE_IPV6:
		strcpy(buffer, "TODO");
		break;
	default:
		strcpy(buffer, "Invalid IP");
		break;
	}
	return buffer;
}

void cdr_init(void)
{
	char filename[30] = "./cdr/cdr_";
	DIR *cdr_dir = opendir("./cdr");
	if (cdr_dir)
		closedir(cdr_dir);
	else if (errno == ENOENT) {
		errno = 0;
		mkdir("./cdr", S_IRWXU);
	}

	size_t filename_prefix_len = strlen(filename);
	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);

	if (tmp != NULL)
		strftime(filename + filename_prefix_len,
			sizeof(filename) - filename_prefix_len,
			"%y%m%d_%H%M%S.csv", tmp);
	printf("Logging CDR Records to %s\n", filename);

	cdr_file = fopen(filename, "w");
	if (!cdr_file)
		rte_panic("CDR file %s failed to open for writing\n - %s (%d)",
					filename, strerror(errno), errno);

	if (fprintf(cdr_file, "#%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
				"time",
				"ue_ip",
				"dl_pkt_cnt",
				"dl_bytes",
				"ul_pkt_cnt",
				"ul_bytes",
				"rule_id",
				"rule_type",
				"rule",
				"action",
				"sponsor_id",
				"service_id",
				"rate_group",
				"tarriff_group",
				"tarriff_time") < 0)
		rte_panic("%s [%d] fprintf(cdr_file header failed - %s (%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);
	if (fflush(cdr_file))
		rte_panic("%s [%d] fflush(cdr_file failed - %s (%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);
}

void export_session_pcc_record(struct dp_pcc_rules *pcc_rule,
				struct ipcan_dp_bearer_cdr *charge_record,
				struct dp_session_info *session)
{
	if (!session)
		return;
	if (!(charge_record->data_vol.dl_cdr.pkt_count
				|| charge_record->data_vol.ul_cdr.pkt_count
				|| charge_record->data_vol.dl_drop.pkt_count
				|| charge_record->data_vol.ul_drop.pkt_count))
		return;

	/* create time string */
	char time_str[30];
	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);
	if (tmp == NULL)
		return;
	strftime(time_str, sizeof(time_str), "%y%m%d_%H%M%S", tmp);

	if (pcc_rule->gate_status == OPEN)
		fprintf(cdr_file, "%s,%s,%"PRIu64",%"PRIu64
				",%"PRIu64",%"PRIu64",%u,%s,%s,%s,",
				time_str,
				iptoa(session->ue_addr),
				charge_record->data_vol.dl_cdr.pkt_count,
				charge_record->data_vol.dl_cdr.bytes,
				charge_record->data_vol.ul_cdr.pkt_count,
				charge_record->data_vol.ul_cdr.bytes,
				pcc_rule->rule_id,
				"PCC",
				pcc_rule->rule_name,
				"CHARGED");
	else
		fprintf(cdr_file, "%s,%s,%"PRIu64",%"PRIu64
				",%"PRIu64",%"PRIu64",%u,%s,%s,%s,",
				time_str,
				iptoa(session->ue_addr),
				charge_record->data_vol.dl_drop.pkt_count,
				charge_record->data_vol.dl_drop.bytes,
				charge_record->data_vol.ul_drop.pkt_count,
				charge_record->data_vol.ul_drop.bytes,
				pcc_rule->rule_id,
				"PCC",
				pcc_rule->rule_name,
				"DROPPED");

	fprintf(cdr_file, "%s,%u,%u,%s,%s\n",
			pcc_rule->sponsor_id,
			pcc_rule->service_id,
			pcc_rule->rating_group,
				"(null)",
				"(null)");

	if (fflush(cdr_file))
		rte_panic("%s [%d] fflush(cdr_file failed - %s (%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);
}
void export_session_adc_record(struct adc_rules *adc_rule,
				struct ipcan_dp_bearer_cdr *charge_record,
				struct dp_session_info *session)
{
	if (!session)
		return;
	if (!(charge_record->data_vol.dl_cdr.pkt_count
				|| charge_record->data_vol.ul_cdr.pkt_count
				|| charge_record->data_vol.dl_drop.pkt_count
				|| charge_record->data_vol.ul_drop.pkt_count))
		return;

	/* create time string */
	char time_str[30];
	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);
	if (tmp == NULL)
		return;
	strftime(time_str, sizeof(time_str), "%y%m%d_%H%M%S", tmp);

	if (adc_rule->gate_status == OPEN)
		fprintf(cdr_file, "%s,%s,%"PRIu64",%"PRIu64
				",%"PRIu64",%"PRIu64",%u,%s,",
				time_str,
				iptoa(session->ue_addr),
				charge_record->data_vol.dl_cdr.pkt_count,
				charge_record->data_vol.dl_cdr.bytes,
				charge_record->data_vol.ul_cdr.pkt_count,
				charge_record->data_vol.ul_cdr.bytes,
				adc_rule->rule_id,
				"ADC");
	else
		fprintf(cdr_file, "%s,%s,%"PRIu64",%"PRIu64
				",%"PRIu64",%"PRIu64",%u,%s,",
				time_str,
				iptoa(session->ue_addr),
				charge_record->data_vol.dl_drop.pkt_count,
				charge_record->data_vol.dl_drop.bytes,
				charge_record->data_vol.ul_drop.pkt_count,
				charge_record->data_vol.ul_drop.bytes,
				adc_rule->rule_id,
				"ADC");

	switch (adc_rule->sel_type) {
	case DOMAIN_IP_ADDR:
		fprintf(cdr_file, IPV4_ADDR",", IPV4_ADDR_HOST_FORMAT(adc_rule->u.domain_ip.u.ipv4_addr));
		break;
	case DOMAIN_IP_ADDR_PREFIX:
		fprintf(cdr_file, IPV4_ADDR"/%u,",
			IPV4_ADDR_HOST_FORMAT(adc_rule->u.domain_prefix.ip_addr.u.ipv4_addr),
			adc_rule->u.domain_prefix.prefix);
		break;
	case DOMAIN_NAME:
		fprintf(cdr_file, "%s,", adc_rule->u.domain_name);
		break;
	default:
		fprintf(cdr_file, "%s,", "ERROR IN ADC RULE");
		break;
	}
	switch (adc_rule->gate_status) {
	case OPEN:
		fprintf(cdr_file, "%s,", "CHARGED");
		break;
	case CLOSE:
		fprintf(cdr_file, "%s,", "DROPPED");
		break;
	default:
		fprintf(cdr_file, "%s,", "ERROR IN ADC RULE");
		break;
	}

	fprintf(cdr_file, "%s,%u,%u,%s,%s\n",
			adc_rule->sponsor_id,
			adc_rule->service_id,
			adc_rule->rating_group,
			adc_rule->tarriff_group,
			adc_rule->tarriff_time);

	if (fflush(cdr_file))
		rte_panic("%s [%d] fflush(cdr_file failed - %s (%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);
}
