#ifndef XDP_DATAPATH_H
#define XDP_DATAPATH_H 1

#include <unistd.h>
#include <libgen.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/if_xdp.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/xsk.h>
#include <bpf/libbpf.h>
// #include <linux/netdevice.h>
// #include <net/net_namespace.h>
// #include <net/ip_tunnels.h>

#include "logging.h"
#include "flow.h"
#include "util.h"
#include "flow-table.h"
#include "libxdp.h"
#include "xf.h"
#include "xf_map.h"

/* Exit return codes */
#define EXIT_OK 0   /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40

#ifndef NAME_MAX
#define NAME_MAX 1096
#endif

#ifndef PATH_MAX
#define PATH_MAX    4096
#endif

#define STRERR_BUFSIZE 1024

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

static const char *pin_basedir = "/sys/fs/bpf";
static const char *stats_map = "stats_map";
static const char *flow_map = "xf_micro_map";
static const char *macro_flow_map = "_xf_macro_map";
static const char *tx_port = "tx_port";
static const char *xsks_map = "xsks_map";
static const char *default_filename = "ep_inline_actions.o";

struct xdp_datapath {
    char *name;
};

struct xdp_ep_stats {

};

struct xdp_dp_stats {

};

/* For getting the details of the entry point configured on a port*/
struct xdp_ep {
    char *mode; /* Native, Generic, Offloaded */
    int ep_id; /* Id for the ep, using the flow_map_fd as id may change in future */
    int prog_fd; /* The loaded xdp program */
    int devmap_fd; /* map with destination interfaces for batch flushing */
    int flow_map_fd; /* Flow table, shared map. TODO: if possible make it readonly reference */
    int stats_map_fd; /* table for stats on the performance of the ep */
};

struct xport {

};

struct ovs_xdp_md {

};

struct xs_cfg {
    const char *path; // path to where the xdp program files are located
    const char *ifname; // name of interface to load on
    char ifname_buf[IF_NAMESIZE];
    const char *brname;
    char brname_buf[IF_NAMESIZE];
    struct multistring *filenames; // for custom actions
    enum xdp_attach_mode mode;
    int xsk_if_queue;
};

static const struct loadopt {
    bool help;
    struct iface iface;
    char *pin_path;
    char *section_name;
    // struct multistring filenames;
    enum xdp_attach_mode mode;
} defaults_load = {
    .mode = XDP_MODE_UNSPEC
};

static const struct unloadopt {
    bool all;
    __u32 prog_id;
    struct iface iface;
} defaults_unload = {};

struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct stats_record {
    uint64_t timestamp;
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
};

struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;

    uint64_t umem_frame_addr[NUM_FRAMES];
    uint32_t umem_frame_free;

    uint32_t outstanding_tx;

    struct stats_record stats;
    struct stats_record prev_stats;
};

static int opt_xsk_frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
static int opt_mmap_flags;
static __u32 opt_umem_flags;

// static int handle_multistring(const char *str, void *tgt)
// {
//     pr_info("handle_multistring");
//     struct multistring *opt_set = tgt;
//     void *ptr;

//     ptr = reallocarray(opt_set->strings, sizeof(*opt_set->strings),
//                opt_set->num_strings + 1);
//     if (!ptr)
//         return -errno;

//     opt_set->strings = ptr;
//     opt_set->strings[opt_set->num_strings++] = str;
//     return 0;
// }

#define min(x, y) ((x) < (y) ? x : y)
#define max(x, y) ((x) > (y) ? x : y)

static int set_rlimit(unsigned int min_limit)
{
    struct rlimit limit;
    int err = 0;

    err = getrlimit(RLIMIT_MEMLOCK, &limit);
    if (err) {
        err = -errno;
        pr_warn("Couldn't get current rlimit\n");
        return err;
    }

    if (limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur == 0) {
        pr_debug("Current rlimit is infinity or 0. Not raising\n");
        return -ENOMEM;
    }

    if (min_limit) {
        if (limit.rlim_cur >= min_limit) {
            pr_debug("Current rlimit %lu already >= minimum %u\n",
                 limit.rlim_cur, min_limit);
            return 0;
        }
        pr_debug("Setting rlimit to minimum %u\n", min_limit);
        limit.rlim_cur = min_limit;
    } else {
        pr_debug("Doubling current rlimit of %lu\n", limit.rlim_cur);
        limit.rlim_cur <<= 1;
    }
    limit.rlim_max = max(limit.rlim_cur, limit.rlim_max);

    err = setrlimit(RLIMIT_MEMLOCK, &limit);
    if (err) {
        err = -errno;
        pr_warn("Couldn't raise rlimit\n");
        return err;
    }

    return 0;
}

// static int double_rlimit()
// {
//     pr_debug("Permission denied when loading eBPF object; "
//          "raising rlimit and retrying\n");

//     return set_rlimit(0);
// }



#define OVS_CB(xdp_md) ((struct ovs_xdp_md *)(xdp_md)->cb)

/**
 * struct dp_upcall - metadata to include with a packet to send to userspace
 * @cmd: One of %OVS_PACKET_CMD_*.
 * @userdata: If nonnull, its variable-length value is passed to userspace as
 * %OVS_PACKET_ATTR_USERDATA.
 * @portid: Netlink portid to which packet should be sent.  If @portid is 0
 * then no packet is sent and the packet is accounted in the datapath's @n_lost
 * counter.
 * @egress_tun_info: If nonnull, becomes %OVS_PACKET_ATTR_EGRESS_TUN_KEY.
 * @mru: If not zero, Maximum received IP fragment size.
 */
struct dp_downcall_info {
    struct ip_tunnel_info *egress_tun_info;
    const struct nlattr *userdata;
    const struct nlattr *actions;
    int actions_len;
    __u32 portid;
    __u8 cmd;
    __u16 mru;
};

int xdp_test_prog(void);
/* TODO: need to convert some of the arg in this file to pointer of pointer */

int xdp_dp_downcall(struct xdp_datapath *, const struct xdp_flow_key *,
            const struct dp_downcall_info *);

const char *xdp_dp_name(const struct xdp_datapath *dp);

/* program operations - load, unload, status etc */
int
xdp_prog_load(struct xdp_ep *xdp_ep, struct xs_cfg *cfg);


int // avoids the use of multipath string which is breaking our code above
xdp_prog_default_load(struct xdp_ep *xdp_ep, struct xs_cfg *cfg);

int
xdp_prog_unload(__u32 prog_fd, char *ifname, char *brname);

int
xdp_prog_status(struct xs_cfg *cfg);

/* datapath crud */
int
xdp_dp_create(struct xdp_datapath *dp);

int
xdp_dp_update(struct xdp_datapath *dp);

int
xdp_dp_delete(struct xdp_datapath *dp);

int
xdp_dp_fetch(struct xdp_datapath *dp);

/* datapath port actions */
int
xdp_dp_port_add(struct xdp_datapath *dp, struct xport *xport);

int
xdp_dp_port_del(struct xdp_datapath *dp, struct xport *xport);

int
xdp_dp_port_lookup(struct xdp_datapath *dp, struct xport *xport);

int
xdp_dp_port_next(struct xdp_datapath *dp, struct xport *xport);

/* upcall sockets */
int
xswitch_xsk__create_umem(struct xsk_umem_info **umem);

int
xswitch_xsk__create_umem__v2(struct xsk_umem_info **umem);

int
xdp_xsk_create(struct xsk_socket_info **sockp, struct xs_cfg *cfg, struct xsk_umem_info *umem);

int
xdp_xsk_create__v2(struct xsk_socket_info **sockp, struct xs_cfg *cfg, struct xsk_umem_info *umem);

int
xdp_xsk_close(struct xsk_socket_info *sock);

void
xdp_xsk_destroy(struct xsk_socket_info *sock);

/* entry point flows */
int
xdp_ep_flow_lookup(int map_fd, struct xdp_flow_key *key, struct xdp_flow **flowp);

int
xdp_ep_flow_insert(int map_fd, struct xdp_flow *flow);

int
xdp_ep_flow_next(int map_fd, struct xdp_flow_key *key, struct xdp_flow **flowp);

int
xdp_ep_flow_remove(int map_fd, struct xdp_flow_key *key);

int
xdp_ep_flow_flush(int map_fd);

/* flows based on entry point */
int xswitch_ep_flow_lookup(int map_fd, struct xf_key *key, struct xf **flowp);

int
xswitch_ep_flow_insert(int map_fd, struct xf *flow);

int
xswitch_ep_flow_next(int map_fd, struct xf_key *pkey, struct xf **flowp);

int
xswitch_ep_flow_remove(int map_fd, struct xf_key *key);

int
xswitch_ep_flow_flush(int map_fd);

/* flows based on the bridge name */
int 
xswitch_br__flow_lookup(char *brname, struct xf_key *key, struct xf **flowp);

int
xswitch_br__flow_insert(char *brname, struct xf *flow);

int
xswitch_br__flow_next(char *brname, struct xf_key *pkey, struct xf **flowp);

int
xswitch_br__flow_remove(char *brname, struct xf_key *key);

int
xswitch_br__flow_flush(char *brname);

/* management of bridge */
// int
// xswitch_br__create(const char *brname);

// int
// xswitch_br__delete(const char *brname);

// int
// xswitch_br__add_port(const char *brname, const char *ifname);

// int
// xswitch_br__remove_port(const char *brname, const char *ifname);

/* arp table */
int
xswitch_arp__add_entry(char *dev, __be32 ip, __u8 mac[ETH_ALEN]);

/* entry point flow stats */
int
xdp_ep_flow_stats_lookup(int map_fd, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_ep_flow_stats_next(int map_fd, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_ep_flow_stats_flush(int map_fd);

/* interface flows */
int
xdp_if_flow_lookup(int if_index, struct xdp_flow_key *key, struct xdp_flow **flowp);

int
xdp_if_flow_insert(int if_index, struct xdp_flow *flow);

int
xdp_if_flow_next(int if_index, struct xdp_flow_key *key, struct xdp_flow **flowp);

int
xdp_if_flow_remove(int if_index, struct xdp_flow_key *key);

int
xdp_if_flow_flush(int if_index);

/* interface flow stats */
int
xdp_if_flow_stats_lookup(int if_index, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_if_flow_stats_next(int if_index, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_if_flow_stats_flush(int if_index);

/* datapath flows */
int
xdp_dp_flow_lookup(struct xdp_datapath *dp, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_dp_flow_insert(struct xdp_datapath *dp, struct xdp_flow *flow);

int
xdp_dp_flow_next(struct xdp_datapath *dp, struct xdp_flow_key *key, struct xdp_flow **flowp);

int
xdp_dp_flow_remove(struct xdp_datapath *dp, struct xdp_flow_key *key);

int
xdp_dp_flow_flush(struct xdp_datapath *dp, struct xdp_flow_key *key);

/* datapath flow stats */
int
xdp_dp_flow_stats_lookup(int map_fd, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_dp_flow_stats_next(int map_fd, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_dp_flow_stats_flush(int map_fd);



#endif /* xdp_datapath.h */