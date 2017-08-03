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

#ifndef _CP_H_
#define _CP_H_

/**
 * @file
 *
 * Control Plane specific declarations
 */

/**
 * @brief core identifiers for control plane threads
 */
struct cp_params {
	unsigned stats_core_id;
	unsigned listener_core_id;
	unsigned sdn_lcore_id;
};

extern struct cp_params cp_params;

/**
 * @brief creates and sends downlink data notification according to session
 * identifier
 * @param session_id - session identifier pertaining to downlink data packets
 * arrived at data plane
 * @return
 * 0 - indicates success, failure otherwise
 */
int
ddn_by_session_id(uint64_t session_id);

/**
 * @brief initializes data plane by creating and adding default entries to
 * various tables including session, pcc, metering, etc
 */
void
initialize_tables_on_dp(void);


#endif
