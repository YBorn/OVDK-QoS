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
    struct list_head node;
};

struct Class_head {
    int num;
    struct list_head head;
};

int
main() {
    struct Class_head clh;
    struct Class cl1, cl2, cl3, cl4, cl5;
    INIT_LIST_HEAD(&clh.head);
    INIT_LIST_NODE(&cl1.node);
    cl1.member = 1;
    INIT_LIST_NODE(&cl2.node);
    cl2.member = 2;
    INIT_LIST_NODE(&cl3.node);
    cl3.member = 3;
    INIT_LIST_NODE(&cl4.node);
    cl4.member = 4;
    INIT_LIST_NODE(&cl5.node);
    cl5.member = 5;

    list_add_after(&clh.head, &cl1.node);
    list_add_after(&cl1.node, &cl2.node);
    list_add_after(&cl2.node, &cl3.node);
    list_add_after(&cl3.node, &cl4.node);
    list_add_after(&cl4.node, &cl5.node);

 //   list_del(&cl1.node);
 //   list_del(&cl5.node);
 //   list_del(&cl3.node);

    struct Class *pos;
//    for(pos = list_entry((&clh.head)->next, typeof(*(pos)), node); &(pos->node) != &clh.head; pos = list_entry(pos->node.next, typeof(*pos), node))
    list_for_each_entry(pos, &clh.head, node)
        printf("member: %d\n", pos->member);
    
    printf("member: %d\n", list_empty(&clh.head));
}
