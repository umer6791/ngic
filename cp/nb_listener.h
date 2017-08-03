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

#ifndef _NB_LISTENER_H_
#define _NB_LISTENER_H_

#include <rte_common.h>

int
listener(__rte_unused void *ptr);

void
clean_nb_listener_on_signal(int signo);

void
init_nb_listener(void);


void
add_nb_op_id(uint32_t op_id);

#endif
