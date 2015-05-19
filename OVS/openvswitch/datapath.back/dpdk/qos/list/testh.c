/*
 * =====================================================================================
 *
 *       Filename:  test.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年04月21日 19时12分38秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Kamfai (), jinhui.wu.kf@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */

#include <stdio.h>

#include "list.h"

struct Class {
    int member;
    struct hlist_node node;
};

struct Class_head {
    int num;
    struct hlist_head head;
};

int
main() {
    struct Class_head clh;
    struct Class cl1, cl2, cl3, cl4, cl5;
    INIT_HLIST_HEAD(&clh.head);
    INIT_HLIST_NODE(&cl1.node);
    cl1.member = 1;
    INIT_HLIST_NODE(&cl2.node);
    cl2.member = 2;
    INIT_HLIST_NODE(&cl3.node);
    cl3.member = 3;
    INIT_HLIST_NODE(&cl4.node);
    cl4.member = 4;
    INIT_HLIST_NODE(&cl5.node);
    cl5.member = 5;

    hlist_add_head(&clh.head, &cl1.node);
    hlist_add_after(&cl1.node, &cl2.node);
    hlist_add_before(&cl1.node, &cl3.node);
    hlist_add_before(&cl2.node, &cl4.node);
    hlist_add_after(&cl2.node, &cl5.node);

//    hlist_del(&cl1.node);
//    hlist_del(&cl5.node);

    struct Class *pos;
//    for(pos = list_entry((&clh.head)->next, typeof(*(pos)), node); &(pos->node) != &clh.head; pos = list_entry(pos->node.next, typeof(*pos), node))
    hlist_for_each_entry(pos, &clh.head, node)
        printf("member: %d\n", pos->member);
}
