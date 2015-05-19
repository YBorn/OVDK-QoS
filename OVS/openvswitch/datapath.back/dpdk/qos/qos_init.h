#ifndef __QOS_INIT_H_
#define __QOS_INIT_H_

#include <string.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>

#include "../vport_define.h"
#include "core/sch_qdisc.h"
#include "core/sch_generic.h"
#include "core/sch_rtnetlink.h"

// Reference qdisc ops, You can add your own Qdisc_ops here!
extern struct Qdisc_ops pfifo_qdisc_ops;
extern struct Qdisc_ops drr_qdisc_ops;
extern struct Qdisc_ops htb_qdisc_ops;

extern struct vport_info *vports;

static void attach_vports_default_qdisc(struct Qdisc_ops *ops) {
    vports[16].vportid = 16;
    vports[17].vportid = 17;
    vports[16].qdisc = qdisc_create_dflt(&vports[16], ops, TC_H_ROOT);
    vports[17].qdisc = qdisc_create_dflt(&vports[17], ops, TC_H_ROOT);
}

static int pktsched_init() {

//    rte_timer_subsystem_init();

    register_qdisc(&pfifo_qdisc_ops);
    register_qdisc(&drr_qdisc_ops);
    register_qdisc(&htb_qdisc_ops);

    rtnl_register(PF_UNSPEC, RTM_NEWQDISC, tc_modify_qdisc, NULL, NULL);
    rtnl_register(PF_UNSPEC, RTM_DELQDISC, tc_get_qdisc, NULL, NULL);
    rtnl_register(PF_UNSPEC, RTM_GETQDISC, tc_get_qdisc, tc_dump_qdisc, NULL);
    rtnl_register(PF_UNSPEC, RTM_NEWTCLASS, tc_ctl_tclass, NULL, NULL);
    rtnl_register(PF_UNSPEC, RTM_DELTCLASS, tc_ctl_tclass, NULL, NULL);
    rtnl_register(PF_UNSPEC, RTM_GETTCLASS, tc_ctl_tclass, tc_dump_tclass, NULL);

//    attach_vports_default_qdisc(&pfifo_qdisc_ops);
    vports[16].vportid = 16;
    vports[17].vportid = 17;
    dev_init_scheduler(&vports[16]);
    dev_init_scheduler(&vports[17]);
    dev_activate(&vports[16]);
    dev_activate(&vports[17]);
    return 0;
}

#endif /* __QOS_INIT_H_ */
