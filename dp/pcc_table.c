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

#include <rte_mbuf.h>

#include "vepc_cp_dp_api.h"
#include "main.h"
#include "util.h"
#include "acl.h"
#include "meter.h"
#include "interface.h"

struct rte_hash *rte_pcc_hash;
/**
 * @brief Called by DP to lookup key-value in PCC table.
 *
 * This function is thread safe (Read Only).
 */
int iface_lookup_pcc_data(const uint32_t key32,
					struct dp_pcc_rules **value)
{
	return rte_hash_lookup_data(rte_pcc_hash, &key32, (void **)value);
}

int
dp_pcc_table_create(struct dp_id dp_id, uint32_t max_elements)
{
	if (rte_pcc_hash) {
		RTE_LOG(INFO, DP, "PCC table: \"%s\" exist\n", dp_id.name);
		return 0;
	}

	return hash_create(dp_id.name, &rte_pcc_hash, max_elements * 4,
				   sizeof(uint32_t));
}

int
dp_pcc_table_delete(struct dp_id dp_id)
{
	RTE_SET_USED(dp_id);
	rte_hash_free(rte_pcc_hash);
	return 0;
}

int
dp_pcc_entry_add(struct dp_id dp_id, struct pcc_rules *entry)
{
	struct dp_pcc_rules *pcc;
	uint32_t key32;
	int ret;

	pcc = rte_zmalloc("data", sizeof(struct dp_pcc_rules),
			   RTE_CACHE_LINE_SIZE);
	if (pcc == NULL)
		return -1;
	memcpy(pcc, entry, sizeof(struct pcc_rules));

	key32 = entry->rule_id;
	ret = rte_hash_add_key_data(rte_pcc_hash, &key32,
				  pcc);
	if (ret < 0) {
		RTE_LOG(ERR, DP, "Failed to add entry in hash table");
		return -1;
	}

	RTE_LOG(INFO, DP, "PCC_TBL ADD: rule_id:%u, addr:0x%"PRIx64
			", ul_mtr_idx:%u, dl_mtr_idx:%u\n",
			pcc->rule_id, (uint64_t)pcc,
			pcc->qos.ul_mtr_profile_index,
			pcc->qos.dl_mtr_profile_index);
	return 0;
}
int
dp_pcc_entry_delete(struct dp_id dp_id, struct pcc_rules *entry)
{
	struct dp_pcc_rules *pcc;
	uint32_t key32;
	int ret;
	key32 = entry->rule_id;
	ret = rte_hash_lookup_data(rte_pcc_hash, &key32,
				  (void **)&pcc);
	if (ret < 0) {
		RTE_LOG(ERR, DP, "Failed to del\n"
			"pcc key 0x%x to hash table\n",
			 key32);
		return -1;
	}
	ret = rte_hash_del_key(rte_pcc_hash, &key32);
	if (ret < 0)
		return -1;
	rte_free(pcc);
	return 0;
}

/******************** Call back functions **********************/
/**
 *  Call back to parse msg to create pcc rules table
 *
 * @param msg_payload
 *	payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_pcc_table_create(struct msgbuf *msg_payload)
{
	return pcc_table_create(msg_payload->dp_id,
				msg_payload->msg_union.msg_table.max_elements);
}

/**
 *  Call back to parse msg to delete table
 *
 * @param msg_payload
 *	payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_pcc_table_delete(struct msgbuf *msg_payload)
{
	return pcc_table_delete(msg_payload->dp_id);
}

/**
 *  Call back to parse msg to add pcc rules.
 *
 * @param msg_payload
 *	payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_pcc_entry_add(struct msgbuf *msg_payload)
{
	return pcc_entry_add(msg_payload->dp_id,
					msg_payload->msg_union.pcc_entry);
}

/**
 * Call back to delete pcc rules.
 * @param msg_payload
 *	payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_pcc_entry_delete(struct msgbuf *msg_payload)
{
	return pcc_entry_delete(msg_payload->dp_id,
					msg_payload->msg_union.pcc_entry);
}

/**
 * Initialization of PCC Table Callback functions.
 */
void app_pcc_tbl_init(void)
{
	/* register msg type in DB*/
	iface_ipc_register_msg_cb(MSG_PCC_TBL_CRE, cb_pcc_table_create);
	iface_ipc_register_msg_cb(MSG_PCC_TBL_DES, cb_pcc_table_delete);
	iface_ipc_register_msg_cb(MSG_PCC_TBL_ADD, cb_pcc_entry_add);
	iface_ipc_register_msg_cb(MSG_PCC_TBL_DEL, cb_pcc_entry_delete);
}

