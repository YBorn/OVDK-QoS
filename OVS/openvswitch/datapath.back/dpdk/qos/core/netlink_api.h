#ifndef __NETLINK_API_H_
#define __NETLINK_API_H_

#include <stdio.h>
#include <sys/uio.h>
#include <string.h>
#include <linux/netlink.h>

#include <rte_memcpy.h>
#include <rte_log.h>

#include "errno-base.h"
#include "typedefs.h"
#include "basic.h"

#define  RTE_LOGTYPE_QoS RTE_LOGTYPE_USER1

#define NLMSG_GOODSIZE 4096UL

/* ========================================================================
 *         Netlink Messages and Attributes Interface (As Seen On TV)
 * ------------------------------------------------------------------------
 *                          Messages Interface
 * ------------------------------------------------------------------------
 *
 * Message Format:
 *    <--- nlmsg_total_size(payload)  --->
 *    <-- nlmsg_msg_size(payload) ->
 *   +----------+- - -+-------------+- - -+-------- - -
 *   | nlmsghdr | Pad |   Payload   | Pad | nlmsghdr
 *   +----------+- - -+-------------+- - -+-------- - -
 *   nlmsg_data(nlh)---^                   ^
 *   nlmsg_next(nlh)-----------------------+
 *
 * Payload Format:
 *    <---------------------- nlmsg_len(nlh) --------------------->
 *    <------ hdrlen ------>       <- nlmsg_attrlen(nlh, hdrlen) ->
 *   +----------------------+- - -+--------------------------------+
 *   |     Family Header    | Pad |           Attributes           |
 *   +----------------------+- - -+--------------------------------+
 *   nlmsg_attrdata(nlh, hdrlen)---^
 *
 * Data Structures:
 *   struct nlmsghdr                    netlink message header
 *
 * Message Construction:
 *   nlmsg_new()                        create a new netlink message
 *   nlmsg_put()                        add a netlink message to an skb
 *   nlmsg_put_answer()                 callback based nlmsg_put()
 *   nlmsg_end()                        finalize netlink message
 *   nlmsg_get_pos()                    return current position in message
 *   nlmsg_trim()                       trim part of message
 *   nlmsg_cancel()                     cancel message construction
 *   nlmsg_free()                       free a netlink message
 *
 * Message Sending:
 *   nlmsg_multicast()                  multicast message to several groups
 *   nlmsg_unicast()                    unicast a message to a single socket
 *   nlmsg_notify()                     send notification message
 *
 * Message Length Calculations:
 *   nlmsg_msg_size(payload)            length of message w/o padding
 *   nlmsg_total_size(payload)          length of message w/ padding
 *   nlmsg_padlen(payload)              length of padding at tail
 *
 * Message Payload Access:
 *   nlmsg_data(nlh)                    head of message payload
 *   nlmsg_len(nlh)                     length of message payload
 *   nlmsg_attrdata(nlh, hdrlen)        head of attributes data
 *   nlmsg_attrlen(nlh, hdrlen)         length of attributes data
 *
 * Message Parsing:
 *   nlmsg_ok(nlh, remaining)           does nlh fit into remaining bytes?
 *   nlmsg_next(nlh, remaining)         get next netlink message
 *   nlmsg_parse()                      parse attributes of a message
 *   nlmsg_find_attr()                  find an attribute in a message
 *   nlmsg_for_each_msg()               loop over all messages
 *   nlmsg_validate()                   validate netlink message incl. attrs
 *   nlmsg_for_each_attr()              loop over all attributes
 *
 * Misc:
 *   nlmsg_report()                     report back to application?
 *
 * ------------------------------------------------------------------------
 *                          Attributes Interface
 * ------------------------------------------------------------------------
 *
 * Attribute Format:
 *    <------- nla_total_size(payload) ------->
 *    <---- nla_attr_size(payload) ----->
 *   +----------+- - -+- - - - - - - - - +- - -+-------- - -
 *   |  Header  | Pad |     Payload      | Pad |  Header
 *   +----------+- - -+- - - - - - - - - +- - -+-------- - -
 *                     <- nla_len(nla) ->      ^
 *   nla_data(nla)----^                        |
 *   nla_next(nla)-----------------------------'
 *
 * Data Structures:
 *   struct nlattr                      netlink attribute header
 *
 * Attribute Construction:
 *   nla_reserve(skb, type, len)        reserve room for an attribute
 *   nla_reserve_nohdr(skb, len)        reserve room for an attribute w/o hdr
 *   nla_put(skb, type, len, data)      add attribute to skb
 *   nla_put_nohdr(skb, len, data)      add attribute w/o hdr
 *   nla_append(skb, len, data)         append data to skb
 *
 * Attribute Construction for Basic Types:
 *   nla_put_u8(skb, type, value)       add u8 attribute to skb
 *   nla_put_u16(skb, type, value)      add u16 attribute to skb
 *   nla_put_u32(skb, type, value)      add u32 attribute to skb
 *   nla_put_u64(skb, type, value)      add u64 attribute to skb
 *   nla_put_s8(skb, type, value)       add s8 attribute to skb
 *   nla_put_s16(skb, type, value)      add s16 attribute to skb
 *   nla_put_s32(skb, type, value)      add s32 attribute to skb
 *   nla_put_s64(skb, type, value)      add s64 attribute to skb
 *   nla_put_string(skb, type, str)     add string attribute to skb
 *   nla_put_flag(skb, type)            add flag attribute to skb
 *   nla_put_msecs(skb, type, jiffies)  add msecs attribute to skb
 *
 * Nested Attributes Construction:
 *   nla_nest_start(skb, type)          start a nested attribute
 *   nla_nest_end(skb, nla)             finalize a nested attribute
 *   nla_nest_cancel(skb, nla)          cancel nested attribute construction
 *
 * Attribute Length Calculations:
 *   nla_attr_size(payload)             length of attribute w/o padding
 *   nla_total_size(payload)            length of attribute w/ padding
 *   nla_padlen(payload)                length of padding
 *
 * Attribute Payload Access:
 *   nla_data(nla)                      head of attribute payload
 *   nla_len(nla)                       length of attribute payload
 *
 * Attribute Payload Access for Basic Types:
 *   nla_get_u8(nla)                    get payload for a u8 attribute
 *   nla_get_u16(nla)                   get payload for a u16 attribute
 *   nla_get_u32(nla)                   get payload for a u32 attribute
 *   nla_get_u64(nla)                   get payload for a u64 attribute
 *   nla_get_s8(nla)                    get payload for a s8 attribute
 *   nla_get_s16(nla)                   get payload for a s16 attribute
 *   nla_get_s32(nla)                   get payload for a s32 attribute
 *   nla_get_s64(nla)                   get payload for a s64 attribute
 *   nla_get_flag(nla)                  return 1 if flag is true
 *   nla_get_msecs(nla)                 get payload for a msecs attribute
 *
 * Attribute Misc:
 *   nla_memcpy(dest, nla, count)       copy attribute into memory
 *   nla_memcmp(nla, data, size)        compare attribute with memory area
 *   nla_strlcpy(dst, nla, size)        copy attribute to a sized string
 *   nla_strcmp(nla, str)               compare attribute with string
 *
 * Attribute Parsing:
 *   nla_ok(nla, remaining)             does nla fit into remaining bytes?
 *   nla_next(nla, remaining)           get next netlink attribute
 *   nla_validate()                     validate a stream of attributes
 *   nla_validate_nested()              validate a stream of nested attributes
 *   nla_find()                         find attribute in stream of attributes
 *   nla_find_nested()                  find attribute in nested attributes
 *   nla_parse()                        parse and validate stream of attrs
 *   nla_parse_nested()                 parse nested attribuets
 *   nla_for_each_attr()                loop over all attributes
 *   nla_for_each_nested()              loop over the nested attributes
 *=========================================================================
 */

 /**
  * Standard attribute types to specify validation policy
  */
enum {
        NLA_UNSPEC,
        NLA_U8,
        NLA_U16,
        NLA_U32,
        NLA_U64,
        NLA_STRING,
        NLA_FLAG,
        NLA_MSECS,
        NLA_NESTED,
        NLA_NESTED_COMPAT,
        NLA_NUL_STRING,
        NLA_BINARY,
        NLA_S8,
        NLA_S16,
        NLA_S32,
        NLA_S64,
        __NLA_TYPE_MAX,
};

#define NLA_TYPE_MAX (__NLA_TYPE_MAX - 1)

/**
 * struct nla_policy - attribute validation policy
 * @type: Type of attribute or NLA_UNSPEC
 * @len: Type specific length of payload
 *
 * Policies are defined as arrays of this struct, the array must be
 * accessible by attribute type up to the highest identifier to be expected.
 *
 * Meaning of `len' field:
 *    NLA_STRING           Maximum length of string
 *    NLA_NUL_STRING       Maximum length of string (excluding NUL)
 *    NLA_FLAG             Unused
 *    NLA_BINARY           Maximum length of attribute payload
 *    NLA_NESTED           Don't use `len' field -- length verification is
 *                         done by checking len of nested header (or empty)
 *    NLA_NESTED_COMPAT    Minimum length of structure payload
 *    NLA_U8, NLA_U16,
 *    NLA_U32, NLA_U64,
 *    NLA_S8, NLA_S16,
 *    NLA_S32, NLA_S64,
 *    NLA_MSECS            Leaving the length field zero will verify the
 *                         given type fits, using it verifies minimum length
 *                         just like "All other"
 *    All other            Minimum length of attribute payload
 *
 * Example:
 * static const struct nla_policy my_policy[ATTR_MAX+1] = {
 *      [ATTR_FOO] = { .type = NLA_U16 },
 *      [ATTR_BAR] = { .type = NLA_STRING, .len = BARSIZ },
 *      [ATTR_BAZ] = { .len = sizeof(struct mystruct) },
 * };
 */
struct nla_policy {
        u16             type;
        u16             len;
};

/**
 * struct nl_info - netlink source information
 * @nlh: Netlink message header of original request
 * @portid: Netlink PORTID of requesting application
 */
struct nl_info {
        struct nlmsghdr         *nlh;
        struct net              *nl_net;
        u32                     portid;
};

struct sk_buf {
    void *iov_base;
    size_t iov_len;
    size_t max_len;
};

static inline unsigned char * skb_tail_pointer(const struct sk_buf *skb)
{
    return (unsigned char *)skb->iov_base + skb->iov_len;
}

/**
 *      skb_trim - remove end from a buffer
 *      @skb: buffer to alter
 *      @len: new length
 *
 *      Cut the length of a buffer down by removing data from the tail. If
 *      the buffer is already under the length specified it is not modified.
 *      The skb must be linear.
 */
static inline void skb_trim(struct sk_buf *skb, unsigned int len)
{
        if (skb->iov_len > len)
                skb->iov_len = len;
}


/**************************************************************************
 * Netlink Messages
 **************************************************************************/
/********** http://lxr.oss.org.cn/source/include/net/netlink.h ************/
/**
 * nlmsg_msg_size - length of netlink message not including padding
 * @payload: length of message payload
 */
static inline int nlmsg_msg_size(int payload)
{
        return NLMSG_HDRLEN + payload;
}

/**
 * nlmsg_total_size - length of netlink message including padding
 * @payload: length of message payload
 */
static inline int nlmsg_total_size(int payload)
{
        return NLMSG_ALIGN(nlmsg_msg_size(payload));
}

/**
 * nlmsg_padlen - length of padding at the message's tail
 * @payload: length of message payload
 */
static inline int nlmsg_padlen(int payload)
{
        return nlmsg_total_size(payload) - nlmsg_msg_size(payload);
}

/**
 * nlmsg_data - head of message payload
 * @nlh: netlink message header
 */
static inline void *nlmsg_data(const struct nlmsghdr *nlh)
{
        return (unsigned char *) nlh + NLMSG_HDRLEN;
}

/**
 * nlmsg_len - length of message payload
 * @nlh: netlink message header
 */
static inline int nlmsg_len(const struct nlmsghdr *nlh)
{
        return nlh->nlmsg_len - NLMSG_HDRLEN;
}

/**
 * nlmsg_attrdata - head of attributes data
 * @nlh: netlink message header
 * @hdrlen: length of family specific header
 */
static inline struct nlattr *nlmsg_attrdata(const struct nlmsghdr *nlh,
                                            int hdrlen)
{
        unsigned char *data = nlmsg_data(nlh);
        return (struct nlattr *) (data + NLMSG_ALIGN(hdrlen));
}

/**
 * nlmsg_attrlen - length of attributes data
 * @nlh: netlink message header
 * @hdrlen: length of family specific header
 */
static inline int nlmsg_attrlen(const struct nlmsghdr *nlh, int hdrlen)
{
        return nlmsg_len(nlh) - NLMSG_ALIGN(hdrlen);
}

/**
 * nlmsg_ok - check if the netlink message fits into the remaining bytes
 * @nlh: netlink message header
 * @remaining: number of bytes remaining in message stream
 */
static inline int nlmsg_ok(const struct nlmsghdr *nlh, uint32_t remaining)
{
        return (remaining >= sizeof(struct nlmsghdr) &&
                nlh->nlmsg_len >= sizeof(struct nlmsghdr) &&
                nlh->nlmsg_len <= remaining);
}

static inline struct nlmsghdr *nlmsg_hdr(const struct sk_buf *skb)
{
        return (struct nlmsghdr *)(skb->iov_base);
}

/**
 * nlmsg_trim - Trim message to a mark
 * @skb: socket buffer the message is stored in
 * @mark: mark to trim to
 *
 * Trims the message to the provided mark.
 */
static inline void nlmsg_trim(struct sk_buf *skb, const void *mark)
{
        if (mark)
//                skb_trim(skb, (unsigned char *) mark - skb->data);
                skb_trim(skb, (unsigned char *) mark - (unsigned char *)skb->iov_base);
}

/**
 * nla_nest_cancel - Cancel nesting of attributes
 * @skb: socket buffer the message is stored in
 * @start: container attribute
 *
 * Removes the container attribute and including all nested
 * attributes. Returns -EMSGSIZE
 */
static inline void nla_nest_cancel(struct sk_buf *skb, struct nlattr *start)
{
        nlmsg_trim(skb, start);
}

/**
 * nlmsg_parse - parse attributes of a netlink message
 * @nlh: netlink message header
 * @hdrlen: length of family specific header
 * @tb: destination array with maxtype+1 elements
 * @maxtype: maximum attribute type to be expected
 * @policy: validation policy
 *
 * See nla_parse()
 */
static int nla_parse(struct nlattr **tb, int maxtype, const struct nlattr *head,
               int len, const struct nla_policy *policy);

static inline int nlmsg_parse(const struct nlmsghdr *nlh, int hdrlen,
                              struct nlattr *tb[], int maxtype,
                              const struct nla_policy *policy)
{
        if (nlh->nlmsg_len < (uint32_t) nlmsg_msg_size(hdrlen))
                return -EINVAL;

        return nla_parse(tb, maxtype, nlmsg_attrdata(nlh, hdrlen),
                         nlmsg_attrlen(nlh, hdrlen), policy);
}

static inline struct nlmsghdr * __nlmsg_put(struct sk_buf *skb, uint32_t pid, uint32_t seq, int type, int len, int flags)
{
    struct nlmsghdr *nlh;
    int size = nlmsg_msg_size(len);

    nlh = (struct nlmsghdr *)skb_tail_pointer(skb);
    nlh->nlmsg_type = type;
    nlh->nlmsg_len = size;
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_pid = pid;
    nlh->nlmsg_seq = seq;
    if(!__builtin_constant_p(size) || NLMSG_ALIGN(size) -size != 0) {
        memset(nlmsg_data(nlh) + len, 0, NLMSG_ALIGN(size) - size);
    }
    skb->iov_len += NLMSG_ALIGN(size);
    return nlh;
}

static inline int skb_tailroom(const struct sk_buf *skb) {
    return skb->max_len - skb->iov_len;
}

// Checked
static inline struct nlmsghdr *nlmsg_put(struct sk_buf *skb, uint32_t portid, uint32_t seq,
                                         int type, int payload, int flags)
{
//        if (unlikely(skb_tailroom(skb) < nlmsg_total_size(payload)))
//                return NULL;
        if(skb_tailroom(skb) < nlmsg_total_size(payload))
            return NULL;

        return __nlmsg_put(skb, portid, seq, type, payload, flags);
}

/**************************************************************************
 * Netlink Attributes
 **************************************************************************/

/**
 * nla_attr_size - length of attribute not including padding
 * @payload: length of payload
 */
static inline int nla_attr_size(int payload)
{
        return NLA_HDRLEN + payload;
}

/**
 * nla_total_size - total length of attribute including padding
 * @payload: length of payload
 */
static inline int nla_total_size(int payload)
{
        return NLA_ALIGN(nla_attr_size(payload));
}

/**
 * nla_padlen - length of padding at the tail of attribute
 * @payload: length of payload
 */
static inline int nla_padlen(int payload)
{
        return nla_total_size(payload) - nla_attr_size(payload);
}

/**
 * nla_type - attribute type
 * @nla: netlink attribute
 */
static inline int nla_type(const struct nlattr *nla)
{
        return nla->nla_type & NLA_TYPE_MASK;
}

/**
 * nla_len - length of payload
 * @nla: netlink attribute
 */
static inline int nla_len(const struct nlattr *nla)
{
        return nla->nla_len - NLA_HDRLEN;
}

/**
 * nla_data - head of payload
 * @nla: netlink attribute
 */
static inline void *nla_data(const struct nlattr *nla)
{
        return (char *) nla + NLA_HDRLEN;
}

/**
 * nla_get_u32 - return payload of u32 attribute
 * @nla: u32 netlink attribute
 */
static inline u32 nla_get_u32(const struct nlattr *nla)
{
        return *(u32 *) nla_data(nla);
}

/**
 * nla_memcpy - Copy a netlink attribute into another memory area
 * @dest: where to copy to memcpy
 * @src: netlink attribute to copy from
 * @count: size of the destination area
 *
 * Note: The number of bytes copied is limited by the length of
 *       attribute's payload. memcpy
 *
 * Returns the number of bytes copied.
 */
static inline int nla_memcpy(void *dest, const struct nlattr *src, int count)
{
        int minlen = min_t(int, count, nla_len(src));

        memcpy(dest, nla_data(src), minlen);

        return minlen;
}

/**
 * nla_get_u64 - return payload of u64 attribute
 * @nla: u64 netlink attribute
 */
static inline u64 nla_get_u64(const struct nlattr *nla)
{
        u64 tmp;

        nla_memcpy(&tmp, nla, sizeof(tmp));

        return tmp;
}

/**
 * nla_ok - check if the netlink attribute fits into the remaining bytes
 * @nla: netlink attribute
 * @remaining: number of bytes remaining in attribute stream
 */
static inline int nla_ok(const struct nlattr *nla, int remaining)
{
        return remaining >= (int) sizeof(*nla) &&
               nla->nla_len >= sizeof(*nla) &&
               nla->nla_len <= remaining;
}

/**
 * nla_next - next netlink attribute in attribute stream
 * @nla: netlink attribute
 * @remaining: number of bytes remaining in attribute stream
 *
 * Returns the next netlink attribute in the attribute stream and
 * decrements remaining by the size of the current attribute.
 */
static inline struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
{
        int totlen = NLA_ALIGN(nla->nla_len);

        *remaining -= totlen;
        return (struct nlattr *) ((char *) nla + totlen);
}

/**
 * nla_for_each_attr - iterate over a stream of attributes
 * @pos: loop counter, set to current attribute
 * @head: head of attribute stream
 * @len: length of attribute stream
 * @rem: initialized to len, holds bytes currently remaining in stream
 */
#define nla_for_each_attr(pos, head, len, rem) \
        for (pos = head, rem = len; \
             nla_ok(pos, rem); \
             pos = nla_next(pos, &(rem)))

static const u16 nla_attr_minlen[NLA_TYPE_MAX+1] = {
        [NLA_U8]        = sizeof(u8),
        [NLA_U16]       = sizeof(u16),
        [NLA_U32]       = sizeof(u32),
        [NLA_U64]       = sizeof(u64),
        [NLA_MSECS]     = sizeof(u64),
        [NLA_NESTED]    = NLA_HDRLEN,
        [NLA_S8]        = sizeof(s8),
        [NLA_S16]       = sizeof(s16),
        [NLA_S32]       = sizeof(s32),
        [NLA_S64]       = sizeof(s64),
};

static int validate_nla(const struct nlattr *nla, int maxtype,
                        const struct nla_policy *policy)
{
        const struct nla_policy *pt;
        int minlen = 0, attrlen = nla_len(nla), type = nla_type(nla);

        if (type <= 0 || type > maxtype)
                return 0;

        pt = &policy[type];

        if (pt->type > NLA_TYPE_MAX)
            RTE_LOG(ERR, QoS, "%s[%d]: It is a BUG\n", __FILE__, __LINE__);

        switch (pt->type) {
        case NLA_FLAG:
                if (attrlen > 0)
                        return -ERANGE;
                break;

        case NLA_NUL_STRING:
                if (pt->len)
                        minlen = min_t(int, attrlen, pt->len + 1);
                else
                        minlen = attrlen;

                if (!minlen || memchr(nla_data(nla), '\0', minlen) == NULL)
                        return -EINVAL;
                /* fall through */

        case NLA_STRING:
                if (attrlen < 1)
                        return -ERANGE;

                if (pt->len) {
                        char *buf = nla_data(nla);

                        if (buf[attrlen - 1] == '\0')
                                attrlen--;

                        if (attrlen > pt->len)
                                return -ERANGE;
                }
                break;

        case NLA_BINARY:
                if (pt->len && attrlen > pt->len)
                        return -ERANGE;
                break;

        case NLA_NESTED_COMPAT:
                if (attrlen < pt->len)
                        return -ERANGE;
                if (attrlen < NLA_ALIGN(pt->len))
                        break;
                if (attrlen < NLA_ALIGN(pt->len) + NLA_HDRLEN)
                        return -ERANGE;
                nla = nla_data(nla) + NLA_ALIGN(pt->len);
                if (attrlen < NLA_ALIGN(pt->len) + NLA_HDRLEN + nla_len(nla))
                        return -ERANGE;
                break;
        case NLA_NESTED:
                /* a nested attributes is allowed to be empty; if its not,
                 * it must have a size of at least NLA_HDRLEN.
                 */
                if (attrlen == 0)
                        break;
        default:
                if (pt->len)
                        minlen = pt->len;
                else if (pt->type != NLA_UNSPEC)
                        minlen = nla_attr_minlen[pt->type];

                if (attrlen < minlen)
                        return -ERANGE;
        }

        return 0;
}

/**
 * nla_parse - Parse a stream of attributes into a tb buffer
 * @tb: destination array with maxtype+1 elements
 * @maxtype: maximum attribute type to be expected
 * @head: head of attribute stream
 * @len: length of attribute stream
 * @policy: validation policy
 *
 * Parses a stream of attributes and stores a pointer to each attribute in
 * the tb array accessible via the attribute type. Attributes with a type
 * exceeding maxtype will be silently ignored for backwards compatibility
 * reasons. policy may be set to NULL if no validation is required.
 *
 * Returns 0 on success or a negative error code.
 */
static int nla_parse(struct nlattr **tb, int maxtype, const struct nlattr *head,
              int len, const struct nla_policy *policy)
{
        const struct nlattr *nla;
        int rem, err;

        memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));

        nla_for_each_attr(nla, head, len, rem) {
                u16 type = nla_type(nla);

                if (type > 0 && type <= maxtype) {
                        if (policy) {
                                err = validate_nla(nla, maxtype, policy);
                                if (err < 0)
                                        goto errout;
                        }

                        tb[type] = (struct nlattr *)nla;
                }
        }

//        if (unlikely(rem > 0))
        if (rem > 0)
                RTE_LOG(ERR, QoS, "%s[%d]: netlink: %d bytes leftover after parsing attributes\n", __FILE__, __LINE__, rem);

        err = 0;
errout:
        return err;
}

static int nla_strcmp(const struct nlattr *nla, const char *str) {
    int len = strlen(str);
    char *buf = nla_data(nla);
    int attrlen =nla_len(nla);
    int d;

    if(attrlen > 0 && buf[attrlen-1] == '\0')
        attrlen--;

    d = attrlen -len;
    if(d == 0)
        d = memcmp(nla_data(nla), str, len);

    return d;
}

static inline int nla_parse_nested(struct nlattr *tb[], int maxtype,
                                   const struct nlattr *nla,
                                   const struct nla_policy *policy)
{
    return nla_parse(tb, maxtype, nla_data(nla), nla_len(nla), policy);
}

// 预留一个nla属性的内存空间
static inline struct nlattr *__nla_reserve(struct sk_buf *skb, int attrtype, int attrlen)
{
        struct nlattr *nla;

//        nla = (struct nlattr *) skb_put(skb, nla_total_size(attrlen)); 
        nla = (struct nlattr *)skb_tail_pointer(skb); 
        nla->nla_type = attrtype;
        nla->nla_len = nla_attr_size(attrlen);

        memset((unsigned char *) nla + nla->nla_len, 0, nla_padlen(attrlen));

        skb->iov_len += nla_total_size(attrlen);
        return nla;
}

static inline void __nla_put(struct sk_buf *skb, int attrtype, int attrlen,
                             const void *data)
{
        struct nlattr *nla;

        nla = __nla_reserve(skb, attrtype, attrlen);
        memcpy(nla_data(nla), data, attrlen);
}

static inline int nla_put(struct sk_buf *skb, int attrtype, int attrlen, const void *data)
{
        if (skb_tailroom(skb) < nla_total_size(attrlen))
                return -EMSGSIZE;

        __nla_put(skb, attrtype, attrlen, data);
        return 0;
}

/**
 * nla_put_u32 - Add a u32 netlink attribute to a socket buffer
 * @skb: socket buffer to add attribute to
 * @attrtype: attribute type
 * @value: numeric value
 */
static inline int nla_put_u32(struct sk_buf *skb, int attrtype, u32 value)
{
        return nla_put(skb, attrtype, sizeof(u32), &value);
}

/**
 * nla_put_u64 - Add a u64 netlink attribute to a socket buffer
 * @skb: socket buffer to add attribute to
 * @attrtype: attribute type
 * @value: numeric value
 */
static inline int nla_put_u64(struct sk_buf *skb, int attrtype, u64 value)
{
        return nla_put(skb, attrtype, sizeof(u64), &value);
}

static inline int nla_put_string(struct sk_buf *skb, int attrtype,
                                 const char *str)
{
        return nla_put(skb, attrtype, strlen(str) + 1, str);
}

/**
 * nla_nest_start - Start a new level of nested attributes
 * @skb: socket buffer to add attributes to
 * @attrtype: attribute type of container
 *
 * Returns the container attribute
 */
static inline struct nlattr *nla_nest_start(struct sk_buf *skb, int attrtype)
{
        struct nlattr *start = (struct nlattr *)skb_tail_pointer(skb);

        if (nla_put(skb, attrtype, 0, NULL) < 0)
                return NULL;

        return start;
}

/**
 * nla_nest_end - Finalize nesting of attributes
 * @skb: socket buffer the attributes are stored in
 * @start: container attribute
 *
 * Corrects the container attribute header to include the all
 * appeneded attributes.
 *
 * Returns the total data length of the skb.
 */
static inline int nla_nest_end(struct sk_buf *skb, struct nlattr *start)
{
        start->nla_len = skb_tail_pointer(skb) - (unsigned char *)start;
        return skb->iov_len;
}

#endif /* __NETLINK_API_H_ */
