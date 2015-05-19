/*
 * Copyright 2012-2014 Intel Corporation All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMMON_H
#define COMMON_H 1

#include <stdint.h>

#include <rte_string_fns.h>

#define MAX_DIGITS_UNSIGNED_INT    20

#define MAX_VPORTS                 80

#define VLAN_ID_MASK               0xFFF
#define VLAN_PRIO_SHIFT            13

#define DPDK_PORT_PREFIX           "ovs_dpdk_"
#define DPDK_PORT_PREFIX_LEN       9
#define DPDK_PORT_MAX_STRING_LEN   12
#define BASE10                     10

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

#endif /* common.h */
