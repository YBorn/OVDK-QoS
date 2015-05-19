/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
 * Copyright (c) 2013-2014 Intel Corporation
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

#include <rte_mbuf.h>

#include "ut.h"

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

void
run_command(int argc, char *argv[], const struct command commands[])
{
    const struct command *p;

    if (argc < 1) {
		RTE_LOG(INFO, APP, "missing command name; use --help for help\n");
		return;
    }

    for (p = commands; p->name != NULL; p++) {
        if (!strcmp(p->name, argv[0])) {
            int n_arg = argc - 1;
            if (n_arg < p->min_args) {
				RTE_LOG(ERR, APP, "'%s' command requires at least "
					"%d arguments\n", p->name, p->min_args);
            } else if (n_arg > p->max_args) {
				RTE_LOG(ERR, APP, "'%s' command takes at most "
					"%d arguments\n", p->name, p->max_args);
            } else {
                p->handler(argc, argv);
                return;
            }
        }
    }

    RTE_LOG(INFO, APP, "unknown command '%s'; use --help for help\n", argv[0]);
}

