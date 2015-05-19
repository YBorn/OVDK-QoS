#ifndef __RTE_GENERIC_H__
#define __RTE_GENERIC_H__

#define QUEUE_RINGSIZE 4096

struct rte_ring;
struct rte_mbuf;

void* secure_malloc(const char *type, size_t size, unsigned align);

void* secure_zmalloc(const char *type, size_t size, unsigned align);

struct rte_ring* q_create(const char *ring_name, int flags);

unsigned packet_sc_do_dequeue(struct rte_ring *r, struct rte_mbuf **obj_table,
                              uint32_t *total);

#endif /* __RTE_GENERIC_H__ */
