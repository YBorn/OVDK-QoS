/*
 * =====================================================================================
 *
 *       Filename:  hlist.h
 *
 *    Description:  Operations for hlist
 *
 *        Version:  1.0
 *        Created:  2014年04月07日 22时02分07秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Y.Born (CD), llyangborn@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */

#ifndef __LIST_H__
#define __LIST_H__

#include "../core/basic.h"


/** Simple Doubly Linked List Implemention **/

#define LIST_HEAD_INIT(name) { &(name), &(name) }
/*******
#define LIST_HEAD(name) \
        struct list_head name = LIST_HEAD_INIT(name)
*******/

static inline void
INIT_LIST_HEAD(struct list_head *h) {
    h->next = h;
    h->prev = h;
}

static inline void
INIT_LIST_NODE(struct list_head *n) {
    n->next = NULL;
    n->prev = NULL;
}

static inline void
list_add_after(struct list_head *n, struct list_head *new) {
    struct list_head *next = n->next;
    
    new->next = next;
    new->prev = n;
    n->next = new;
    next->prev = new;
}

static inline void
list_add_before(struct list_head *n, struct list_head *new) {
    struct list_head *prev = n->prev;
    
    new->next = n;
    new->prev = prev;
    n->prev = new;
    prev->next = new;
}

static inline void
list_add_tail(struct list_head *h, struct list_head *new) {
    list_add_before(h, new);
}

static inline void
list_del(struct list_head *n) {
    struct list_head *prev = n->prev;
    struct list_head *next = n->next;
    
    prev->next = next;
    next->prev = prev;
}
static inline void
list_del_init(struct list_head *entry) {
    list_del(entry);
    INIT_LIST_HEAD(entry);
}

static inline int
list_empty(const struct list_head *h) {
    return h->next == h;
}

#define list_entry(ptr, type, member)   \
    container_of(ptr, type, member)

#define list_for_each(pos, head)    \
    for(pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_entry(pos, head, member)   \
    for(pos = list_entry( (head)->next, typeof(*(pos)), member );    \
        &((pos)->member) != head;    \
        pos = list_entry( (pos)->member.next, typeof(*(pos)), member ))


/** Double Linked lists with a single pointer list head **/

#define HLIST_HEAD_INIT { .first = NULL }
#define HLIST_HEAD(name) struct hlist_head name = { .first = NULL }


/** 
 *  init_hlist_head - Initialize the hlist head
 *  Parameter:
 *  @h:     point to hlist_head
 */

static inline void
INIT_HLIST_HEAD(struct hlist_head *h) {
    h->first = NULL;
}

/** 
 *  init_hlist_node - Initialize the hlist node
 *  Parameter:
 *  @h:     point to hlist_node
 */

static inline void
INIT_HLIST_NODE(struct hlist_node *n) {
    n->next = NULL;
    n->pprev = NULL;
}

static inline void
hlist_add_head(struct hlist_head *h,
               struct hlist_node *new) {
    new->next = h->first;
    new->pprev = &h->first;
    if(h->first)
        h->first->pprev = &new->next;
    h->first = new;
}

/** 
 *  hlist_add_before - Add the hlist node after the Specified node 
 *  Parameter:
 *  @h:     point to hlist_node
 */
static inline void
hlist_add_before(struct hlist_node *n,
                 struct hlist_node *new) {
    new->next = n;
    new->pprev = n->pprev;
    *(new->pprev) = new;
    n->pprev = &new->next;
}

/** 
 *  hlist_add_after - Add the hlist node after the Specified node 
 *  Parameter:
 *  @h:     point to hlist_node
 */
static inline void
hlist_add_after(struct hlist_node *n,
                 struct hlist_node *new) {
    new->next = n->next;
    new->pprev = &n->next;
    n->next = new;
    if(new->next)
        new->next->pprev=&new->next;
}

/** 
 *  hlist_del - Delete the Specified node 
 *  Parameter:
 *  @n:     point to hlist_node
 */
static inline void
hlist_del(struct hlist_node *n) {
    *n->pprev = n->next;
    if(n->next)
        n->next->pprev = n->pprev;
}

static inline int
hlist_empty(struct hlist_head *h) {
    return h->first == NULL;
}
/**
 *  hlist_entry - Access the entry
 *  Parameter:
 *  @ptr:   point to hlist_node
 *  @type:  struct type which contain the hlist node
 *  @member:the name of the hlist_node within the struct
 */
#define hlist_entry(ptr, type, member)  \
    container_of(ptr, type, member)

/**
 *  hlist_for_each - Iterate over hlist of given type
 *  Parameter:
 *  @pos:   the type * to use as a loop curse
 *  @head:  the hlist head
 */
#define hlist_for_each(pos, head)   \
    for(pos = (head)->next; pos ; pos = pos->next)

/**
 *  hlist_for_each - Iterate over hlist of given type
 *  Parameter:
 *  @pos:   the type * to use as a loop curse
 *  @head:  the hlist head
 *  @member: the name of hlist node within the struct
 */
#define hlist_for_each_entry(pos, head, member)   \
    for(pos = hlist_entry( (head)->first, typeof(*(pos)), member );    \
        pos;    \
        pos = (pos)->member.next ? hlist_entry( (pos)->member.next, typeof(*(pos)), member ):NULL)

/**
 *
 *  #define hlist_add_entry_after
 *  #define hlist_add_entry_before
 *
 */

#endif /* __LIST_H__ */
