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

#ifndef _CDR_H
#define _CDR_H
/**
 * @file
 * This file contains function prototypes of User data
 * charging record.
 */
#include "main.h"

/**
 * Initialize Charging data record file.
 */
void cdr_init(void);

/**
 * Open Session Charging data record file.
 */
void sess_cdr_init(void);
/**
 * Clear the record file content.
 */
void sess_cdr_reset(void);
/**
 * Export PCC record to file
 * @param pcc_rule
 *	PCC rule.
 * @param cdr
 *	charge data record.
 * @param session
 *	bearer session info.
 *
 * @return
 * Void
 */
void export_session_pcc_record(struct dp_pcc_rules *pcc_rule,
					struct ipcan_dp_bearer_cdr *cdr,
					struct dp_session_info *session);

/**
 * Export ADC record to file
 * @param adc_rule
 *	ADC rule.
 * @param cdr
 *	charge data record.
 * @param session
 *	bearer session info.
 *
 * @return
 * Void
 */
void export_session_adc_record(struct adc_rules *adc_rule,
					struct ipcan_dp_bearer_cdr *cdr,
					struct dp_session_info *session);
/**
 * Export CDR record to file.
 * @param session
 *	dp bearer session.
 * @param name
 *	string to identify the type of CDR.
 * @param id
 *	identification number based on cdr type. It can be
 *	either bearerid, adc rule id, flow id or rating group.
 * @param charge_record
 *	cdr structure which holds the pkt counts and bytes.
 *
 * @return
 * Void
 */
void export_cdr_record(struct dp_session_info *session, char *name,
			uint32_t id, struct ipcan_dp_bearer_cdr *charge_record);
#endif /* _CDR_H */
