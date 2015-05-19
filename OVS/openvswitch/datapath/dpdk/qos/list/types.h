/*
 *              Reference
 *  Data Structure :  include/linux/types.h
 *      Operation  :  include/linux/list.h
 *
 */

#ifndef __LIST_TYPES_H__
#define __LIST_TYPES_H__

struct list_head {
    struct list_head    *next;
    struct list_head    *prev;
};

struct hlist_head {
    struct hlist_node   *first;
};

struct hlist_node {
    struct hlist_node   *next;
    struct hlist_node   **pprev;
};

#endif /* __LIST_TYPES_H__ */
