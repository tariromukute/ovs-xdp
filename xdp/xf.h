/* This file contains the struct definition and util functions for managing xdp flows (xf)
 * and their actions.
 */

#ifndef XF_H
#define XF_H 1

/* Adding the new xf structs and functions */
#define XFA_MAX_SIZE 24 /* 128 bits */
#define XFA_BUF_MAX_NUM 4
#define XFA_BUF_MAX_SIZE (XFA_MAX_SIZE) * XFA_BUF_MAX_NUM

struct xf_key {
    __u32 valid;
};

/* xdp flow header */
struct xf_hdr {
    __u32 type;
    __u32 len;
} __attribute__((packed));

/* xdp flow action */
struct xf_act {
    struct xf_hdr hdr;
    __u8 data[XFA_MAX_SIZE];
};

/* xdp flow action cursor for keeping track of the action being executed */
struct xfa_cursor {
    __u16 len;
    __u16 num;
    __u16 cnt;
    __u16 offset;
};

/* xdp flow actions buffer for storing the list of action for a given flow */
struct xfa_buf {
    struct xfa_cursor cursor;
    __u8 data[XFA_BUF_MAX_SIZE];
};

/* extracts and returns the type of action being pointed to by the cursor (current action) */
static __always_inline int xfa_type(struct xfa_buf *acts)
{
    __u16 pos = 0;
    if (pos + acts->cursor.offset > XFA_BUF_MAX_SIZE)
        return -1;

    pos += acts->cursor.offset;

    // Point cursor to current action header
    if (pos + sizeof (struct xf_hdr) > XFA_BUF_MAX_SIZE) {
        return -1;
    }

    struct xf_hdr *hdr = (struct xf_hdr *) &acts->data[pos];

    return hdr->type;
}

/* extracts the length of the action being pointed to by the cursor (current action) */
static __always_inline int xfa_len(struct xfa_buf *acts)
{
    __u16 pos = 0;
    if (pos + acts->cursor.offset > XFA_BUF_MAX_SIZE)
        return -1;

    pos += acts->cursor.offset;

    // Point cursor to current action header
    if (pos + sizeof (struct xf_hdr) > XFA_BUF_MAX_SIZE) {
        return -1;
    }

    struct xf_hdr *hdr = (struct xf_hdr *) &acts->data[pos];

    return hdr->len;
}

/* extracts the action being pointed to by the cursor (current action) */
static __always_inline int xfa_data(struct xfa_buf *acts, void *act, __u32 size)
{
    __u16 pos = 0;
    if (pos + acts->cursor.offset > XFA_BUF_MAX_SIZE)
        return -1;

    pos += acts->cursor.offset;

    // Point cursor to current action header
    if (pos + sizeof (struct xf_hdr) > XFA_BUF_MAX_SIZE) {
        return -1;
    }

    struct xf_hdr *hdr = (struct xf_hdr *) &acts->data[pos];

    // check if the length is the same as size of act ptr
    if (hdr->len != size)
        return -1;

    // bound check access to act
    if (pos + sizeof (struct xf_hdr) + size > XFA_BUF_MAX_SIZE)
        return -1;

    pos += sizeof (struct xf_hdr);
    // memcpy(act, &acts->data[pos], size);

    return hdr->type;
}

/* advances to the cursor to point to the next action extracts the type of action  
 * returns -1 when there is no next */
static __always_inline int xfa_next(struct xfa_buf *acts)
{
    __u16 pos = 0;
    if (pos + acts->cursor.offset > XFA_BUF_MAX_SIZE)
        return -1;

    pos += acts->cursor.offset;

    // Point cursor to current action header
    if (pos + sizeof (struct xf_hdr) > XFA_BUF_MAX_SIZE) {
        return -1;
    }

    struct xf_hdr *hdr = (struct xf_hdr *) &acts->data[pos];

    acts->cursor.offset += hdr->len;
    acts->cursor.cnt += 1;

    return hdr->type; 
}

/* advances the cursor to the next action and puts the action in the buf and
 * returns the type of the action. The initial call will advance the cursor to
 * the first action in the buffer */
static __always_inline __u32 xfa_next_data(void *data, struct xf_act *act)
{
    struct xfa_buf *acts = data;
    __u32 pos = 0;
    if (pos + acts->cursor.offset > XFA_BUF_MAX_SIZE)
        return 0;

    pos += acts->cursor.offset;

    // Point cursor to current action header
    if (pos + sizeof (struct xf_act) > XFA_BUF_MAX_SIZE) {
        return 0;
    }
    // void *ptr = (void *) &acts->data[pos];
    if (&acts->data[pos] + sizeof (struct xf_act) > &acts->data[XFA_BUF_MAX_SIZE])
        return 0;

    void *ptr = (void *)acts->data;
    struct xf_hdr *hdr = ptr;
    hdr->len++;

    // hdr.type = (__u32) acts->data[pos];
    // hdr.len = (__u32) acts->data[pos++];
    // __u32 *ptr = (__u32 *)&acts->data[pos];
    // struct xf_hdr *hdr = ptr;
    
    // acts->cursor.offset += hdr->len;
    // acts->cursor.cnt += 1;

    // if (hdr->len > sizeof(struct xf_hdr) && 
    //     pos + sizeof(struct xf_hdr) + hdr->len > XFA_BUF_MAX_SIZE)
    //     return -1;

    // pos += sizeof(struct xf_hdr);

    // memcpy(act, &acts->data[pos], hdr->len);
    // int err = *ptr;
    // err++;
    return hdr->type; 
    // return 0;
}

/* puts an action into the xdp actions buffer */
static __always_inline int xfa_put(struct xfa_buf *acts, void *data, __u32 size)
{
    if (sizeof(struct xf_hdr) > size)
        return -1;

    __u16 pos = 0;
    if (pos + acts->cursor.len > XFA_BUF_MAX_SIZE)
        return -1;

    pos += acts->cursor.len;

    // Point cursor to current action header
    if (pos + size > XFA_BUF_MAX_SIZE) {
        return -1;
    }

    // memcpy(&acts->data[pos], data, size);

    acts->cursor.len += size;
    acts->cursor.num += 1;
    
    return acts->cursor.num;
}

#endif /* XF_H: XDP FLOW*/