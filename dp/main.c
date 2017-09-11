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

#include <unistd.h>
#include <locale.h>
#include <signal.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_branch_prediction.h>

#include "main.h"
#include "interface.h"
#include "cdr.h"
#include "session_cdr.h"

/**
 * Main function.
 */
int main(int argc, char **argv)
{
	int ret;

	/* Initialize the Environment Abstraction Layer */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		rte_exit(EXIT_FAILURE, "Error:can't catch SIGINT\n");
	argc -= ret;
	argv += ret;

	dp_port_init();

	/* DP Init */
	dp_init(argc, argv);

	sess_cdr_init();

	/* Pipeline Init */
	epc_init_packet_framework(app.sgi_port, app.s1u_port);

	register_worker(sgi_pkt_handler, app.sgi_port);
	register_worker(s1u_pkt_handler, app.s1u_port);

	iface_module_constructor();
	dp_table_init();

	packet_framework_launch();

	rte_eal_mp_wait_lcore();

	return 0;
}
