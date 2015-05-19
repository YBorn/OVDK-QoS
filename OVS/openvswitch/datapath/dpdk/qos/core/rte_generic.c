#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_mbuf.h>

#include "rte_generic.h"

#define SOCKET0         0

/**
 * Attempts to malloc or exit
 *
 */
void *secure_malloc(const char *type, size_t size, unsigned align)
{
    void *addr;

    addr = rte_malloc(type, size, align);
    if (addr == NULL)
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for %s \n", type);

    return addr;
}

/**
 * Attempts to malloc and set to zero or exit
 *
 */
void *secure_zmalloc(const char *type, size_t size, unsigned align)
{
    void *addr;

    addr = rte_zmalloc(type, size, align);
    if (addr == NULL)
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for %s \n", type);

    return addr;
}

/**
 * Attempts to create a ring or exit
 *
 */
struct rte_ring *q_create(const char *ring_name, int flags)
{
    struct rte_ring *ring;
    flags = RING_F_SC_DEQ | RING_F_SP_ENQ;                 
    ring = rte_ring_create(ring_name, QUEUE_RINGSIZE, SOCKET0, flags);
    if (ring == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create '%s' ring \n", ring_name);

    return ring;
}

unsigned packet_sc_do_dequeue(struct rte_ring *r, struct rte_mbuf **obj_table,
                     uint32_t *total)
{
    uint32_t idx = (r->cons.head) & (r->prod.mask);
    uint32_t sum = 0, len = 0, SUM = *total;
    unsigned n;

    uint32_t entries = r->prod.tail - r->cons.head;

    if(entries == 0 || SUM < 64)
        return 0;

    for(n = 0; n < entries; n++) {
        len = ((struct rte_mbuf *)r->ring[idx++])->pkt.pkt_len;
        sum += len;
        
        if(sum > SUM) {
            sum -= len;
            break;
        }
    }
    __rte_ring_sc_do_dequeue(r, (void **)obj_table, rte_ring_count(r), RTE_RING_QUEUE_VARIABLE);
    *total = SUM - sum;
    
    return n;
}
