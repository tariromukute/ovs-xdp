#include <config.h>
#include "dpif-xdp.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <net/if.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/xsk.h>
#include <netinet/ether.h>

#include "bitmap.h"
#include "cmap.h"
#include "conntrack.h"
#include "coverage.h"
#include "ct-dpif.h"
#include "csum.h"
#include "dp-packet.h"
#include "dpif.h"
#include "dpif-netdev-perf.h"
#include "dpif-provider.h"
#include "dummy.h"
#include "fat-rwlock.h"
#include "flow.h"
#include "hmapx.h"
#include "id-pool.h"
#include "ipf.h"
#include "netdev.h"
#include "netdev-offload.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "netlink.h"
#include "odp-execute.h"
#include "odp-util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovs-numa.h"
#include "ovs-rcu.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "pvector.h"
#include "random.h"
#include "seq.h"
#include "smap.h"
#include "sset.h"
#include "timeval.h"
#include "tnl-neigh-cache.h"
#include "tnl-ports.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"
#include "hash.h"
#include "uuid.h"
#include "loader.h"
#include "dirs.h"
#include "datapath.h"
#include "xdp_user_helpers.h"
#include "xf.h"

/* ================================================================
    The xdp uses more or less the same datapath as netdev, only
    that it attaches a program on it. Hence the datapath shash  and
    other datapath attributes might be similar or the same and/or
    are handled in a similar way. Therefore this file 'might' 
    contain the same dp(s), this might need to be factored in and 
    will contribute to some code reuse or similar code.
   ================================================================ */
VLOG_DEFINE_THIS_MODULE(dpif_xdp);

#define FLOW_DUMP_MAX_BATCH 50

#define MAX_SOCKS 16

#define UPCALL_MAX_READ 1

/* Note: don't set to -1 else it will hold on to the upcall key 
   if timeout of 0 then there is no waiting */
static int opt_timeout = 100;

/* Protects against changes to 'dp_netdevs'. */
static struct ovs_mutex dp_xdp_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dp_netdev's. */
static struct shash dp_xdps OVS_GUARDED_BY(dp_xdp_mutex)
    = SHASH_INITIALIZER(&dp_xdps);

/* An AF_XDP channel to communicate between the kernel and userspace */
struct dp_channel {
    struct xsk_socket_info *sock;
    long long int last_poll;    /* Last time this channel was polled. */
};

struct dp_handler {
    struct epoll_event *epoll_events;
    int epoll_fd;                 /* epoll fd that includes channel socks. */
    int n_events;                 /* Num events returned by epoll_wait(). */
    int event_offset;             /* Offset into 'epoll_events'. */
    struct pollfd *fds;
};

struct dp_xdp {
    struct dpif *dpif;
    const struct dpif_class *const class;
    const char *const name;
    struct ovs_refcount ref_cnt;
    atomic_flag destroyed;

    // /* UMEM for AF_XDP */
    // struct xsk_umem_info *umem;
    /* Ports.
     *
     * Any lookup into 'ports' or any access to the dp_netdev_ports found
     * through 'ports' requires taking 'port_mutex'. */
    struct ovs_mutex port_mutex;
    struct hmap ports;
    struct seq *port_seq;       /* Incremented whenever a port changes. */

    /* TODO: Implement Meters. */
    
    /* Stores all the 'struct dp_xdp_entry_points's (where hooks/progs are attached) */
    struct cmap entry_points;

    /* Handlers */
    struct fat_rwlock upcall_lock;
    uint32_t n_handlers;            /* Num of upcall handlers. */
    struct dp_handler *handlers;   /* Array of handlers */

    /* Upcall channels. */
    int n_channels;
    struct dp_channel *channels; /* Array of channels */

};

/* TODO: check if there will be any difference in the dp_xdp_port
 * and the dp_netdev_port which is a port in a netdev-based datapath. 
 * if there is no difference should probably use the same. */
struct dp_xdp_port {
    odp_port_t port_no;
    int ifindex;
    int ep_id; /* Id for the ep, using the flow_map_fd as id may change in future */
    struct hmap_node epnode;    /* Node in dp_xdp_entry_point */
    const char *name;
    bool dynamic_txqs;          /* If true XPS will be used. */
    bool need_reconfigure;      /* True if we should reconfigure netdev. */
    struct netdev *netdev;
    struct hmap_node node;      /* Node in dp_netdev's 'ports'. */
    struct netdev_saved_flags *sf;
    // struct dp_netdev_rxq *rxqs;
    unsigned n_rxq;             /* Number of elements in 'rxqs' */
    unsigned *txq_used;         /* Number of threads that use each tx queue. */
    struct ovs_mutex txq_used_mutex;
    bool emc_enabled;           /* If true EMC will be used. */
    char *type;                 /* Port type as requested by user. */
    char *rxq_affinity_list;    /* Requested affinity of rx queues. */
    
    /* TODO: check if we need a lock for upcalls */
    /* The list of upcall ids for the port. These correspond to the xsk sockets
     * used for upcalls. */
    uint32_t *upcall_pids; /* The upcall id, using the id of the afxdp */

    uint32_t n_upcall_pids;
    /* TODO: consider putting a flag to check port is entry point
       the adapt it in the necessary methods like:
       - create_put 
       - do_del_port
       - deleteing of entry points 
       - etc */
};

/* Interface to xdp-based datapath. */
struct dpif_xdp {
    struct dpif dpif;
    struct dp_xdp *dp;
    uint64_t last_port_seq;
    /* TODO: check if we need a lock when making upcalls to afxdp */

    /* IMPORTANT: when we add attributes here we will need to update some methods
       - create_dpif_xdp 
       - etc */
};

/* These are the points where the xdp programs can be attached, which can be
 * every interface on the datapath, or designated interfaces or tap devices.
 * The entry points contains a reference to the flow tables which is a shared
 * map and a flow cache table for the entry entry point. It first checks the 
 * flow cache table (map) for the flow then the shared flow table seen by all
 * entry points. 
 * 
 * For forwarding in contains a reference to a devmap with records for destination
 * interfaces to allow for batch flushing which increasing throughput. This 
 * is a shared map too.
 * 
 * It also contains maps for stats, device and flow stats which are used when
 * collecting the datapath statistics.
 *  
 * It also contains other attributes for the xdp like, the program loaded, tails
 * xdp type etc. And may contain a mutex will see if needed.
 * 
 * Since this is also a network device we will keep the port_no too
 */
struct dp_xdp_entry_point {
    struct dp_xdp *dp;
    /* for af_xdp */
    struct xsk_umem_info *umem;

    int ep_id; 
    struct hmap ports; // list of port_no with this entry_point
    struct ovs_refcount ref_cnt;    /* Every reference must be refcount'ed. */

    struct cmap_node node; // reference to the node in dp->entry_points

    // TODO: check the tyoe of mode, likely not char
    char *mode; /* Native, Generic, Offloaded */

    int prog_fd; /* The loaded xdp program */
    
    int devmap_fd; /* map with destination interfaces for batch flushing */

    // struct ovs_mutex flow_mutex; /* TODO: check if mutex for flow_table_cache is needed and init it in relevant methods. */
    int flow_map_fd; /* Flow table, shared map. TODO: if possible make it readonly reference */
    int stats_map_fd; /* table for stats on the performance of the ep */
    struct xdp_ep_stats stats; /* Keeps track of the entry point's performance */

};

struct dpif_xdp_port_state {
    struct hmap_position position;
    char *name;
};

struct dpif_xf_dump {
    struct dpif_flow_dump up;
    struct cmap_position entry_point_pos;
    // struct xf_key flow_pos; /* TODO: define the type for a bpf_map position when looping */
    struct xf_key flow_pos; /* position in map when looping */
    struct dp_xdp_entry_point *cur_ep;
    int status;
    struct ovs_mutex mutex; /* TODO: *verify if needed */
    // struct dpif_flow_dump_types types; /* TODO: check if we need it */
};

struct dp_xdp_actions {
    /* TODO: define struct, for each action we might need a reference to
       the corresponding  bpf_prog, if empty we know we make an upcall 
       of DPIF_UC_ACTION */
    /* These members are immutable: they do not change during the struct's
     * lifetime.  */
    unsigned int size;          /* Size of 'actions', in bytes. */
    struct nlattr actions[];    /* Sequence of OVS_ACTION_ATTR_* attributes. */
};

struct dpif_xf_dump_thread {
    struct dpif_flow_dump_thread up;
    struct dpif_xf_dump *dump;

    /* TODO: confirm if this is all we need */

    /* (Key/Mask/Actions) Buffers for netdev dumping */
    struct odputil_keybuf keybuf[FLOW_DUMP_MAX_BATCH];
    struct odputil_keybuf maskbuf[FLOW_DUMP_MAX_BATCH];
    struct odputil_keybuf actbuf[FLOW_DUMP_MAX_BATCH];
};

struct ovs_xsk_event {
    struct xf_upcall header;
    uint8_t data[];
};

static struct odp_support dp_xdp_support = {
    .max_vlan_headers = 2,
    .max_mpls_depth = 2,
    .recirc = false,
    .ct_state = false,
    .ct_zone = false,
    .ct_mark = false,
    .ct_label = false,
    .ct_state_nat = false,
    .ct_orig_tuple = false,
    .ct_orig_tuple6 = false,
};

static int dpif_xdp_open(const struct dpif_class *dpif_class,
                const char *name, bool create, struct dpif **dpifp);
static const char * dpif_xdp_port_open_type(const struct dpif_class *dpif_class,
                                  const char *type);
static bool is_dp_xdp(struct dp_xdp *dp);            
static int get_port_by_name(struct dp_xdp *dp,
                 const char *devname, struct dp_xdp_port **portp)
    OVS_REQUIRES(dp->port_mutex);
static int get_port_by_ifindex(struct dp_xdp *dp,
                 const int ifindex, struct dp_xdp_port **portp)
    OVS_REQUIRES(dp->port_mutex);
static void answer_port_query(const struct dp_xdp_port *port,
                  struct dpif_port *dpif_port);
static uint32_t hash_port_no(odp_port_t port_no);                  
static struct dp_xdp_port * dp_xdp_lookup_port(const struct dp_xdp *dp, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex);
static bool is_valid_port_number(odp_port_t port_no);
static int get_port_by_number(struct dp_xdp *dp,
                   odp_port_t port_no, struct dp_xdp_port **portp)
    OVS_REQUIRES(dp->port_mutex);
static int dpif_xdp_port_dump_next__(const struct dp_xdp *dp, struct dpif_xdp_port_state *state,
                          struct dp_xdp_port *port);
bool dpif_is_xdp(const struct dpif *dpif);
static struct dpif_xdp * dpif_xdp_cast(const struct dpif *dpif);
static struct dp_xdp * get_dp_xdp(const struct dpif *dpif);
static void port_destroy(struct dp_xdp_port *port);
static void do_del_port(struct dp_xdp *dp, struct dp_xdp_port *port)
    OVS_REQUIRES(dp->port_mutex);
static int port_add_channel(struct dp_xdp *dp, odp_port_t port_no,
                  struct xsk_socket_info *sock);
static odp_port_t choose_port(struct dp_xdp *dp, const char *name)
    OVS_REQUIRES(dp->port_mutex);
static int port_create(const char *devname, const char *type,
            odp_port_t port_no, struct dp_xdp_port **portp);
static int do_add_port(struct dp_xdp *dp, const char *devname, const char *type,
            odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex);
static bool port_get_pid(struct dp_xdp *dp, uint32_t port_idx,
               uint32_t *upcall_pids);
static int dpif_xdp_port_dump_start__(struct dp_xdp *dp, struct dpif_xdp_port_state *state);
static void destroy_all_channels(struct dp_xdp *dp)
    OVS_REQ_WRLOCK(dp->upcall_lock);
static int dp_xdp_refresh_channels(struct dp_xdp *dp, uint32_t n_handlers)
    OVS_REQ_WRLOCK(dp->upcall_lock);
static void dp_xdp_free(struct dp_xdp *dp)
    OVS_REQUIRES(dp_xdp_mutex);
static void dp_xdp_unref(struct dp_xdp *dp);
static struct dpif * create_dpif_xdp(struct dp_xdp *dp);
static int dp_xdp_handler_init(struct dp_handler *handler);
static void dp_xdp_handler_uninit(struct dp_handler *handler);
static int create_dp_xdp(const char *name, const struct dpif_class *class,
                 struct dp_xdp **dpp)
    OVS_REQUIRES(dp_xdp_mutex);
static int dpif_xf_key_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              struct xf_key *xdp_key, bool probe);
// static int dpif_xdp_mask_from_nlattrs(const struct nlattr *key, uint32_t key_len,
//                               const struct nlattr *mask_key,
//                               uint32_t mask_key_len, const struct flow *flow,
//                               struct flow_wildcards *wc, bool probe);
static void dp_xf_hash(const void *key, size_t key_len, ovs_u128 *hash);
static void dp_xdp_ep_remove_flow(struct dp_xdp_entry_point *ep,
                      struct xf *flow);
static void dp_xdp_ep_flow_flush(struct dp_xdp_entry_point *ep);
static struct xf * dp_xdp_ep_lookup_flow(struct dp_xdp_entry_point *ep,
                          struct xf_key *key,
                          int *lookup_num_p);
static struct xf * dp_xdp_ep_find_flow(const struct dp_xdp_entry_point *ep,
                        const ovs_u128 *ufidp, const struct nlattr *key,
                        size_t key_len);
// static struct xf * dp_xdp_ep_next_flow(const struct dp_xdp_entry_point *ep,
//                         struct xf_key *key);
static int dp_xdp_ep_update_flow(const struct dp_xdp_entry_point *ep,
                        struct xf *flow);
static struct dpif_xf_dump * dpif_xf_dump_cast(struct dpif_flow_dump *dump);
static struct dpif_xf_dump_thread * dpif_xf_dump_thread_cast(struct dpif_flow_dump_thread *thread);
static int dp_xdp_configure_ep(struct dp_xdp_entry_point **epp, struct dp_xdp *dp,
                        struct dp_xdp_port *port, struct xs_cfg *cfg);
static void dp_xdp_destroy_ep(struct dp_xdp_entry_point *ep);
static bool dp_xdp_ep_try_ref(struct dp_xdp_entry_point *ep);
static void dp_xdp_ep_unref(struct dp_xdp_entry_point *ep);
static void dp_xdp_actions_free(struct dp_xdp_actions *actions);
struct dp_xdp_actions * dp_xdp_actions_create(const struct nlattr *actions, size_t size);
struct dp_xdp_actions * dp_xf_get_actions(const struct xf *flow);
static struct dp_xdp_entry_point * dp_xdp_get_ep(struct dp_xdp *dp, int ep_id);
static struct dp_xdp_entry_point * dp_xdp_ep_get_next(struct dp_xdp *dp, struct cmap_position *pos);
static void dp_xf_to_dpif_flow(const struct dp_xdp *dp, int ep_id,
                            const struct xf *xf,
                            struct ofpbuf *key_buf, struct ofpbuf *mask_buf,
                            struct dpif_flow *flow, bool terse);
static void dp_xf_to_dpif_flow__(const struct dp_xdp *dp, int ep_id,
                            const struct xf *xf,
                            struct ofpbuf *key_buf, struct ofpbuf *mask_buf, struct ofpbuf *act_buf,
                            struct dpif_flow *flow, bool terse);
static void dpif_xf_get_stats(const struct xf *flow,
                            struct dpif_flow_stats *stats);
static int flow_put_on_ep(struct dp_xdp_entry_point *ep,
                struct xf_key *key,
                ovs_u128 *ufid,
                const struct dpif_flow_put *put,
                struct dpif_flow_stats *stats);
static int dpif_xf_put(struct dpif *dpif, const struct dpif_flow_put *put);
#pragma GCC diagnostic ignored "-Wunused-function"
static int flow_del_on_ep(struct dp_xdp_entry_point *ep,
                struct dpif_flow_stats *stats,
                const struct dpif_flow_del *del);
static int dpif_xf_del(struct dpif *dpif, const struct dpif_flow_del *del);
static int dpif_xdp_execute(struct dpif *dpif, struct dpif_execute *execute)
    OVS_NO_THREAD_SAFETY_ANALYSIS;
static int dpif_xf_get(const struct dpif *dpif, const struct dpif_flow_get *get);

enum odp_key_fitness xf_key_to_flow(const struct xf_key *key, struct flow *flow);
static int xf_actions_to_odp_actions(const struct dp_xdp *dp, const struct xfa_buf *xdp_acts,
                struct ofpbuf *out);

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
    ovs_assert(xsk->umem_frame_free < NUM_FRAMES);

    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
    return xsk->umem_frame_free;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
    uint64_t frame;
    if (xsk->umem_frame_free == 0)
        return INVALID_UMEM_FRAME;

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
    return frame;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
// IMPORTANT: port type not common (dp_xdp_port vs dp_netdev_port)
static int
get_port_by_name(struct dp_xdp *dp,
                 const char *devname, struct dp_xdp_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp_port *port; // IMPORTANT: port type not common

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!strcmp(netdev_get_name(port->netdev), devname)) {
            *portp = port;
            return 0;
        }
    }

    *portp = NULL;
    /* Callers of dpif_netdev_port_query_by_name() expect ENODEV for a non
     * existing port. */
    return ENODEV;
}

static int
get_port_by_ifindex(struct dp_xdp *dp,
                 const int ifindex, struct dp_xdp_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    // VLOG_INFO("---- Called: %s  with ifindex of: %d----", __func__, ifindex);
    struct dp_xdp_port *port; // IMPORTANT: port type not common

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_get_ifindex(port->netdev) == ifindex) {
            *portp = port;
            return 0;
        }
    }

    *portp = NULL;
    /* Callers of dpif_netdev_port_query_by_name() expect ENODEV for a non
     * existing port. */
    return ENODEV;
}

// IMPORTANT: port type not common (dp_xdp_port vs dp_netdev_port)
static void
answer_port_query(const struct dp_xdp_port *port,
                  struct dpif_port *dpif_port)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    dpif_port->name = xstrdup(netdev_get_name(port->netdev));
    dpif_port->type = xstrdup(port->type);
    dpif_port->port_no = port->port_no;
}

static uint32_t
hash_port_no(odp_port_t port_no)
{
    return hash_int(odp_to_u32(port_no), 0);
}

static struct dp_xdp_port *
dp_xdp_lookup_port(const struct dp_xdp *dp, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp_port *port;

    HMAP_FOR_EACH_WITH_HASH (port, node, hash_port_no(port_no), &dp->ports) {
        if (port->port_no == port_no) {
            return port;
        }
    }
    return NULL;
}

static bool
is_valid_port_number(odp_port_t port_no)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    return port_no != ODPP_NONE;
}

// IMPORTANT: port type not common (dp_xdp_port vs dp_netdev_port)
static int
get_port_by_number(struct dp_xdp *dp,
                   odp_port_t port_no, struct dp_xdp_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    if (!is_valid_port_number(port_no)) {
        *portp = NULL;
        return EINVAL;
    } else {
        *portp = dp_xdp_lookup_port(dp, port_no);
        return *portp ? 0 : ENODEV;
    }
}

bool
dpif_is_xdp(const struct dpif *dpif)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    return dpif->dpif_class->open == dpif_xdp_open;
}

static struct dpif_xdp *
dpif_xdp_cast(const struct dpif *dpif)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    
    ovs_assert(dpif_is_xdp(dpif));
    return CONTAINER_OF(dpif, struct dpif_xdp, dpif);
}

static struct dp_xdp *
get_dp_xdp(const struct dpif *dpif)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    return dpif_xdp_cast(dpif)->dp;
}

static void
port_destroy(struct dp_xdp_port *port)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    /* TODO: Might remove some of the port attributes
        so will need to remove some of the code here */
    if (!port) {
        return;
    }

    netdev_close(port->netdev);
    netdev_restore_flags(port->sf);

    // for (unsigned i = 0; i < port->n_rxq; i++) {
    //     netdev_rxq_close(port->rxqs[i].rx);
    // }
    ovs_mutex_destroy(&port->txq_used_mutex);
    free(port->rxq_affinity_list);
    free(port->txq_used);
    free(port->type);
    free(port);
}

static void
do_del_port(struct dp_xdp *dp, struct dp_xdp_port *port)
    OVS_REQUIRES(dp->port_mutex)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp_entry_point *ep;

    /* Remove ep */
    ep = dp_xdp_get_ep(dp, port->ep_id);
    
    hmap_remove(&ep->ports, &port->epnode);

    hmap_remove(&dp->ports,&port->node);
    seq_change(dp->port_seq);

    /* TODO: Remove channel if nolonger needed */
    port_destroy(port);
}

static odp_port_t
choose_port(struct dp_xdp *dp, const char *name)
    OVS_REQUIRES(dp->port_mutex)
{
    uint32_t port_no;

    if (!is_dp_xdp(dp)) {
        const char *p;
        int start_no = 0;

        /* If the port name begins with "br", start the number search at
         * 100 to make writing tests easier. */
        if (!strncmp(name, "br", 2)) {
            start_no = 100;
        }

        /* If the port name contains a number, try to assign that port number.
         * This can make writing unit tests easier because port numbers are
         * predictable. */
        for (p = name; *p != '\0'; p++) {
            if (isdigit((unsigned char) *p)) {
                port_no = start_no + strtol(p, NULL, 10);
                if (port_no > 0 && port_no != odp_to_u32(ODPP_NONE)
                    && !dp_xdp_lookup_port(dp, u32_to_odp(port_no))) {
                    return u32_to_odp(port_no);
                }
                break;
            }
        }
    }

    for (port_no = 1; port_no <= UINT16_MAX; port_no++) {
        if (!dp_xdp_lookup_port(dp, u32_to_odp(port_no))) {
            return u32_to_odp(port_no);
        }
    }

    return ODPP_NONE;
}

static int
port_create(const char *devname, const char *type,
            odp_port_t port_no, struct dp_xdp_port **portp)
{
    int error = 0;
    struct dp_xdp_port *port;
    enum netdev_flags flags;
    struct netdev *netdev;
    int ifindex = -1;

    *portp = NULL;

    /* Open and validate network device. */
    error = netdev_open(devname, type, &netdev);
    if (error) {
        return error;
    }

    ifindex = if_nametoindex(devname);
    if (ifindex == -1 || ifindex == 0) {
        goto out;
    }

    /* XXX reject non-Ethernet devices */
    netdev_get_flags(netdev, &flags);
    if (flags & NETDEV_LOOPBACK) {
        VLOG_ERR("%s: cannot add a loopback device", devname);
        error = EINVAL;
        goto out;
    }

    port = xzalloc(sizeof *port);
    port->port_no = port_no;
    port->ifindex = ifindex;
    port->name = devname;
    port->netdev = netdev;
    port->type = xstrdup(type);
    port->sf = NULL;
    port->emc_enabled = true;
    port->need_reconfigure = true;
    port->n_upcall_pids = 1;
    port->upcall_pids = xzalloc(sizeof *port->upcall_pids);
    ovs_mutex_init(&port->txq_used_mutex);

    *portp = port;
    return 0;

out:
    netdev_close(netdev);
    return error;
}

static int
do_add_port(struct dp_xdp *dp, const char *devname, const char *type,
            odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_xdp_port *port;
    struct dp_xdp_entry_point *ep;
    struct xsk_socket_info *sock = NULL;
    
    int error = 0;
    
    if (!get_port_by_name(dp, devname, &port)) {
        return EEXIST;
    }

    error = port_create(devname, type, port_no, &port);
    if (error) {
        return error;
    }

    hmap_insert(&dp->ports, &port->node, hash_port_no(port_no));
    seq_change(dp->port_seq);

    char *path = xasprintf("%s/xswitch", ovs_pkgdatadir());
    struct xs_cfg cfg = {
        .path = path,
        // .ifname = devname,
        // .brname = dp->name,
        .filenames = NULL,
        .mode = XDP_MODE_UNSPEC,
        .xsk_if_queue = 0
    };
    cfg.ifname = (char *)&cfg.ifname_buf;
    strncpy(cfg.ifname, devname, IF_NAMESIZE);
    cfg.brname = (char *)&cfg.brname_buf;
    strncpy(cfg.brname, dp->name, IF_NAMESIZE);
    // configure ep
    /* NOTE: Seems like if we try to attached the xdp program to ovs-xdp the code will break.
     * Didn't investgate the cause just put an if statement that will stop the creation of an
     * entry point for ovs-xdp */
    if (strcmp(devname, "ovs-xdp") != 0) {
        error = dp_xdp_configure_ep(&ep, dp, port, &cfg);
    } else {
        goto out;
    }
    if (error) {
        goto out;
    }

    // add socket for upcall
    fat_rwlock_wrlock(&dp->upcall_lock);
    error = xdp_xsk_create__v2(&sock, &cfg, ep->umem);
    fat_rwlock_unlock(&dp->upcall_lock);
    if (error) {
        goto out;
    }

    int fd = xsk_socket__fd(sock->xsk);
    port->upcall_pids[0] = fd;

    error = port_add_channel(dp, port_no, sock);
out:
    if (error) {
        do_del_port(dp, port);
    }
    return error;
}

static void
destroy_all_channels(struct dp_xdp *dp)
    OVS_REQ_WRLOCK(dp->upcall_lock)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    // unsigned int i;
    /* TODO: implement methods */

    /* TODO: need to turn off upcalls on ep since they may
       not necessarily be destroyed as well. We can assign
       up_callid of 0 */

    /* TODO: close channels */
    // for (i = 0; i < dp->n_channels; i++) {
    //     struct afxdp_channel *channel = &dp->channels[i];
        
    //     afxdp_channel_close(channel);
    // }

    /* TODO: uninitialise handlers */

    /* TODO: free channels and handlers arrays */
    // free(dp->channels);
    // free(dp->handlers);
    // dp->handlers = NULL;
    // dp->channels = NULL;
    // dp->n_channels = 0;
    // dp->n_handlers = 0;

}

/* Given the port number 'port_idx', extracts the pids of netlink sockets
 * associated to the port and assigns it to 'upcall_pids'. */
static bool
port_get_pid(struct dp_xdp *dp, uint32_t port_idx,
               uint32_t *upcall_pid)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    /* Since the nl_sock can only be assigned in either all
     * or none "dpif" channels, the following check
     * would suffice. */
    if (!dp->channels[port_idx].sock) {
        return false;
    }

    *upcall_pid = xsk_socket__fd(dp->channels[port_idx].sock->xsk);

    return true;
}


static int
port_add_channel(struct dp_xdp *dp, odp_port_t port_no,
                  struct xsk_socket_info *sock)
{
    uint32_t port_idx = odp_to_u32(port_no);
    size_t i;

    if (dp->handlers == NULL) {
        xsk_sock_close(sock);
        return 0;
    }

    /* We assume that the datapath densely chooses port numbers, which can
     * therefore be used as an index into 'channels' and 'pollfds' of
     * 'dpif'. */
    if (port_idx >= dp->n_channels) {
        uint32_t new_size = port_idx + 1;

        if (new_size > MAX_SOCKS) {
            VLOG_WARN("%s: datapath port %d too big",
                         dpif_name(dp->dpif), port_no);
            return EFBIG;
        }

        dp->channels = xrealloc(dp->channels,
                                  new_size * sizeof *dp->channels);

        for (i = dp->n_channels; i < new_size; i++) {
            dp->channels[i].sock = NULL;
        }

        for (i = 0; i < dp->n_handlers; i++) {
            struct dp_handler *handler = &dp->handlers[i];

            handler->fds = xrealloc(handler->fds,
                new_size * sizeof *handler->fds);

        }

        // for (i = 0; i < dp->n_handlers; i++) {
        //     struct dp_handler *handler = &dp->handlers[i];

        //     handler->epoll_events = xrealloc(handler->epoll_events,
        //         new_size * sizeof *handler->epoll_events);

        // }

        dp->n_channels = new_size;
    }

    // If port_no wasn't densely populated or port doesn't have valid fd assign it to -1
    // to be skipped during upcall
    int j = 0;
    for (j = 0; j < dp->n_channels; j++) {
        if (!dp->channels[j].sock) {
            for (i = 0; i < dp->n_handlers; i++) {
                struct dp_handler *handler = &dp->handlers[i];
                handler->fds[j].fd = -1; 
                handler->fds[j].events = POLLIN; // TODO: handle events for when sock is undefined
            }
        }
    }

    int fd = -1;
    for (i = 0; i < dp->n_handlers; i++) {
        struct dp_handler *handler = &dp->handlers[i];
        fd = xsk_socket__fd(sock->xsk); // can be sock[i]->xsk
        VLOG_INFO("---- Called: %s xsk_socket__fd: %d port_idx: %d ----", __func__, fd, port_idx);
        handler->fds[port_idx].fd =  fd >= 0 ? fd : -1; // fd = 0 is valid
        handler->fds[port_idx].events = POLLIN;
    }

    dp->channels[port_idx].sock = sock;
    dp->channels[port_idx].last_poll = LLONG_MIN;
    return 0;
}

static void
port_del_channels(struct dp_xdp *dp, odp_port_t port_no)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    uint32_t port_idx = odp_to_u32(port_no);
    size_t i;

    if (!dp->handlers || port_idx >= dp->n_channels
        || !dp->channels[port_idx].sock) {
        return;
    }

    for (i = 0; i < dp->n_handlers; i++) {
        struct dp_handler *handler = &dp->handlers[i];
        handler->fds[port_idx].fd = -1;
    }

    // for (i = 0; i < dp->n_handlers; i++) {
    //     struct dp_handler *handler = &dp->handlers[i];
    //     epoll_ctl(handler->epoll_fd, EPOLL_CTL_DEL,
    //               xsk_socket__fd(dp->channels[port_idx].sock->xsk), NULL);
    //     handler->event_offset = handler->n_events = 0;
    // }

    xsk_sock_destroy(dp->channels[port_idx].sock);

    dp->channels[port_idx].sock = NULL;
}

static int
dp_xdp_refresh_channels(struct dp_xdp *dp, uint32_t n_handlers)
    OVS_REQ_WRLOCK(dp->upcall_lock)
{
    VLOG_INFO("---- Called: %s, dp->n_handlers: %d, n_handlers: %d ----", __func__, dp->n_handlers, n_handlers);

    struct dp_xdp_port port;
    struct dpif_xdp_port_state state;
    int retval = 0;
    size_t i;

    if (dp->n_handlers != n_handlers) {
        destroy_all_channels(dp);
        dp->handlers = xzalloc(n_handlers * sizeof *dp->handlers);
        for (i = 0; i < n_handlers; i++) {
            int error;
            struct dp_handler *handler = &dp->handlers[i];

            error = dp_xdp_handler_init(handler);
            if (error) {
                size_t j;

                for (j = 0; j < i; j++) {
                    struct dp_handler *tmp = &dp->handlers[j];
                    dp_xdp_handler_uninit(tmp);
                }
                free(dp->handlers);
                dp->handlers = NULL;

                return error;
            }
        }
        dp->n_handlers = n_handlers;
    }

    for (i = 0; i < n_handlers; i++) {
        struct dp_handler *handler = &dp->handlers[i];

        handler->n_events = 0;
    }
    // for (i = 0; i < n_handlers; i++) {
    //     struct dp_handler *handler = &dp->handlers[i];

    //     handler->event_offset = handler->n_events = 0;
    // }

    dpif_xdp_port_dump_start__(dp, &state);
    while (!dpif_xdp_port_dump_next__(dp, &state, &port)) {
        uint32_t port_no = odp_to_u32(port.port_no);
        uint32_t upcall_pid;
        int error;

        if (port_no >= dp->n_channels
            || !port_get_pid(dp, port_no, &upcall_pid)) {
            struct xsk_socket_info *sock = NULL;
            error = xsk_sock_create(&sock, port.name);

            if (error) {
                goto error;
            }

            error = port_add_channel(dp, port.port_no, sock);
            if (error) {
                VLOG_INFO("%s: could not add channels for port %s",
                          dpif_name(dp->dpif), port.name);
                xsk_sock_destroy(sock);
                retval = error;
                goto error;
            }
            upcall_pid = xsk_socket__fd(sock->xsk);
            VLOG_INFO("---- Called: %s xsk_socket__fd :%d port.port_no: %d ----", __func__, upcall_pid, port.port_no);
        }

        /* Configure the vport to deliver misses to 'sock'. */
        if (port.upcall_pids[0] == 0
            || port.n_upcall_pids != 1
            || upcall_pid != port.upcall_pids[0]) {
            
            // TODO: update the port status

            if (error) {
                VLOG_WARN("%s: failed to set upcall pid on port: %s",
                             dpif_name(dp->dpif), ovs_strerror(error));

                if (error != ENODEV && error != ENOENT) {
                    retval = error;
                } else {
                    /* The vport isn't really there, even though the dump says
                     * it is.  Probably we just hit a race after a port
                     * disappeared. */
                }
                goto error;
            }
        }

        continue;

    error:
        port_del_channels(dp, port.port_no);
    }

    return retval;
}

/* Requires dp_xdp_mutex so that we can't get a new reference to 'dp'
 * through the 'dp_xdps' shash while freeing 'dp'. */
static void
dp_xdp_free(struct dp_xdp *dp)
    OVS_REQUIRES(dp_xdp_mutex)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp_port *port, *next;

    shash_find_and_delete(&dp_xdps, dp->name);

    ovs_mutex_lock(&dp->port_mutex);
    HMAP_FOR_EACH_SAFE (port, next, node, &dp->ports) {
        do_del_port(dp, port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    /* TODO: Destroy all entry_points detaching the XDP programs etc
       Something like the draft below. The programs might have been 
       removed by the do_del_port() above so factor that in. */
    
    // dp_xdp_destroy_all_entry_points(dp, true);
    // cmap_destroy(&dp->entry_points);

    seq_destroy(dp->port_seq);
    hmap_destroy(&dp->ports);
    ovs_mutex_destroy(&dp->port_mutex);

    /* Destroy upcall channels */
    fat_rwlock_wrlock(&dp->upcall_lock);
    destroy_all_channels(dp);               /* It also uninitialises handlers */
    fat_rwlock_unlock(&dp->upcall_lock);

    fat_rwlock_destroy(&dp->upcall_lock);

    /* TODO: Destroy the upcall queues if necessary or any */
    
    free(CONST_CAST(char *, dp->name));
    free(dp);
}

static void
dp_xdp_unref(struct dp_xdp *dp)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    if (dp) {
        /* Take dp_xdp_mutex so that, if dp->ref_cnt falls to zero, we can't
         * get a new reference to 'dp' through the 'dp_xdps' shash. */
        ovs_mutex_lock(&dp_xdp_mutex);
        if (ovs_refcount_unref_relaxed(&dp->ref_cnt) == 1) {
            dp_xdp_free(dp);
        }
        ovs_mutex_unlock(&dp_xdp_mutex);
    }
}

static struct dpif *
create_dpif_xdp(struct dp_xdp *dp)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    uint16_t netflow_id = hash_string(dp->name, 0);
    struct dpif_xdp *dpif;

    ovs_refcount_ref(&dp->ref_cnt);

    dpif = xmalloc(sizeof *dpif);
    dpif_init(&dpif->dpif, dp->class, dp->name, netflow_id >> 8, netflow_id);
    dpif->dp = dp;
    fat_rwlock_init(&dp->upcall_lock);
    dpif->last_port_seq = seq_read(dp->port_seq);
    return &dpif->dpif;
}

static int
dp_xdp_handler_init(struct dp_handler *handler)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    handler->epoll_fd = epoll_create(10);
    return handler->epoll_fd < 0 ? errno : 0;
}

static void
dp_xdp_handler_uninit(struct dp_handler *handler)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    close(handler->epoll_fd);
}

static int
create_dp_xdp(const char *name, const struct dpif_class *class,
                 struct dp_xdp **dpp)
    OVS_REQUIRES(dp_xdp_mutex)
{
    VLOG_INFO("---- Called: %s name %s ----", __func__, name);
    struct dp_xdp *dp;
    int error;

    dp = xzalloc(sizeof *dp);
    shash_add(&dp_xdps, name, dp);

    *CONST_CAST(const struct dpif_class **, &dp->class) = class;
    *CONST_CAST(const char **, &dp->name) = xstrdup(name);
    ovs_refcount_init(&dp->ref_cnt);
    atomic_flag_clear(&dp->destroyed);

    ovs_mutex_init_recursive(&dp->port_mutex);
    hmap_init(&dp->ports);
    dp->port_seq = seq_create();

    fat_rwlock_init(&dp->upcall_lock);

    ovs_mutex_lock(&dp->port_mutex);

    error = do_add_port(dp, name, dpif_xdp_port_open_type(dp->class,
                                                             "internal"),
                        ODPP_LOCAL);

    ovs_mutex_unlock(&dp->port_mutex);

    /* Initialise UMEM */
    // error = xswitch_xsk__create_umem__v2(&dp->umem);
    // if (error) {
    //     VLOG_INFO("---- Called: %s xswitch_xsk__create_umem__v2 failed");
    // }
    
    /* Initialse channels */
    /* TODO: initialise n_channels */

    cmap_init(&dp->entry_points);

    /* TODO: Need to add a port (entry_point) to attach XDP prog on  
       or preferably use the default host to bridge port (not sure if
       it's attached by default) */

    /* TODO: Assign the upcall_id to the entry point(s) should derive 
       these from the channels */

    if (error) {
        dp_xdp_free(dp);
        return error;
    }

    *dpp = dp;
    return 0;
}

static int
xf_actions_to_odp_actions(const struct dp_xdp *dp, const struct xfa_buf *xdp_acts, struct ofpbuf *out)
{
    __u32 len = 0;
    __u32 acts_len = xdp_acts->hdr.len;
    __u32 hdr_len = XF_HDR_LEN; // length of headers for a xdp action
    __u8 *act_ptr = (__u8 *) xdp_acts->data;
   
    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_hex(&ds, xdp_acts, sizeof(struct xfa_buf));
    /* TODO: verify that the actions lengths defined in the xdp/flow.h is 
       the same as the odp length. Where there are not by design factor the
       difference else it's an error */
    while (len < acts_len) {
        act_ptr += len;
        struct xf_act *act = (struct xf_act *)act_ptr;
        // VLOG_INFO("--- Called: %s, action is: %u len: %u, act->hdr.len: %u, acts_len: %u", __func__, act->hdr.type, len, act->hdr.len, acts_len);
        switch (act->hdr.type) {
        case XDP_ACTION_ATTR_UNSPEC:
            /* End of actions list. */
            return 0;

        case XDP_ACTION_ATTR_OUTPUT: {
            if (act->hdr.len - hdr_len != sizeof(__u32)) {
                return -EINVAL;
            }
            __u32 *ifindex = (__u32 *)act->data;
            struct dp_xdp_port *port = NULL;
            int err = get_port_by_ifindex(dp, *ifindex, &port);
            if (err)
                goto error;

            nl_msg_put_odp_port(out, OVS_ACTION_ATTR_OUTPUT, port->port_no);
            break;
        }
        case XDP_ACTION_ATTR_PUSH_VLAN: {
            nl_msg_put_unspec(out, OVS_ACTION_ATTR_PUSH_VLAN, act->data,
                              act->hdr.len);
            break;
        }
        case XDP_ACTION_ATTR_RECIRC:
            if (act->hdr.len - hdr_len != sizeof(__u32)) {
                return -EINVAL;
            }
            nl_msg_put_u32(out, OVS_ACTION_ATTR_RECIRC, (uint32_t) *act->data);
            break;
        case XDP_ACTION_ATTR_TRUNC:
            nl_msg_put_unspec(out, OVS_ACTION_ATTR_TRUNC, act->data, act->hdr.len);
            break;
        case XDP_ACTION_ATTR_HASH:
            nl_msg_put_unspec(out, OVS_ACTION_ATTR_HASH, act->data, act->hdr.len);
            break;
        case XDP_ACTION_ATTR_PUSH_MPLS:
            nl_msg_put_unspec(out, OVS_ACTION_ATTR_PUSH_MPLS, act->data, act->hdr.len);
            break;
        case XDP_ACTION_ATTR_POP_MPLS:
            if (act->hdr.len - hdr_len != sizeof(__be16)) {
                return -EINVAL;
            }
            nl_msg_put_be16(out, OVS_ACTION_ATTR_POP_MPLS, (__be16) *act->data);
            break;
        case XDP_ACTION_ATTR_SET: {
            /* TODO: implement */
            return EOPNOTSUPP;
        }
        case XDP_ACTION_ATTR_SET_MASKED: {
            /* TODO: implement */
            return EOPNOTSUPP;
        }

        case XDP_ACTION_ATTR_USERSPACE: {
            /* TODO: implement */
            return EOPNOTSUPP;
        }
        case XDP_ACTION_ATTR_PUSH_ETH: {
            __u8 *eth_ptr = (__u8 *) act->data;
            struct ovs_action_push_eth eth;

            memset(&eth, 0, sizeof eth);
            memcpy(&eth.addresses.eth_src, eth_ptr, 6);
            eth_ptr += 6;
            memcpy(&eth.addresses.eth_dst, eth_ptr, 6);

            nl_msg_put_unspec(out, OVS_ACTION_ATTR_PUSH_ETH,
                            &eth, sizeof eth);
            break;
        }
        case XDP_ACTION_ATTR_POP_ETH: {
            nl_msg_put_flag(out, OVS_ACTION_ATTR_POP_ETH);
            break;
        }
        case XDP_ACTION_ATTR_PUSH_NSH: {
            /* TODO: implement */
            return EOPNOTSUPP;
        }
        case XDP_ACTION_ATTR_POP_NSH: {
            /* TODO: implement */
            return EOPNOTSUPP;
        }
        case XDP_ACTION_ATTR_CT:
        case XDP_ACTION_ATTR_POP_VLAN:
        case XDP_ACTION_ATTR_CLONE:
        case XDP_ACTION_ATTR_METER:
        case XDP_ACTION_ATTR_CT_CLEAR:
            return EOPNOTSUPP;
        case __XDP_ACTION_ATTR_MAX:
        default:
            OVS_NOT_REACHED();
            break;
        }
        len += act->hdr.len;
    }
    return 0;

error:
    return -1;
}

enum odp_key_fitness
xf_key_to_flow(const struct xf_key *key, struct flow *flow)
{
    memset(flow, 0, sizeof *flow);

    /* TODO: handle conversion of flow metadata */

    /* L2 */
    if (key->valid & ETH_VALID) {
        memcpy(&flow->dl_dst, &key->eth.eth_dst, sizeof flow->dl_dst);
        memcpy(&flow->dl_src, &key->eth.eth_src, sizeof flow->dl_src);
        flow->dl_type = key->eth.h_proto;
    }
    if (key->valid & VLAN_VALID) {
        /* TODO: implement */
    }

    /* L3 */
    if (key->valid & IPV4_VALID) {
        flow->nw_src = key->iph.ipv4_src;
        flow->nw_dst = key->iph.ipv4_dst;
        flow->nw_ttl = key->iph.ipv4_ttl;
        flow->nw_proto = key->iph.ipv4_proto;
    } else if (key->valid & IPV6_VALID) {
        memcpy(&flow->ipv6_src, &key->ipv6h.ipv6_src, sizeof flow->ipv6_src);
        memcpy(&flow->ipv6_dst, &key->ipv6h.ipv6_dst, sizeof flow->ipv6_dst);
        // flow->ipv6_label = htonl(key->ipv6h.flowLabel); /* TODO: enable label */
        /* XXX: flow->nw_frag */
        flow->nw_tos = key->ipv6h.ipv6_tclass;
        flow->nw_ttl = key->ipv6h.ipv6_hlimit;
        flow->nw_proto = key->ipv6h.ipv6_proto;
    } else if (key->valid & ARP_VALID) {
        memcpy(&flow->arp_sha, &key->arph.arp_sha, 6);
        memcpy(&flow->arp_tha, &key->arph.arp_tha, 6);
        memcpy(&flow->nw_src, &key->arph.arp_sip, 4); /* be32 */
        memcpy(&flow->nw_dst, &key->arph.arp_tip, 4);

        if (ntohs(key->arph.ar_op) < 0xff) {
            flow->nw_proto = ntohs(key->arph.ar_op);
        } else {
            flow->nw_proto = 0;
        }
    }

    /* L4 */
    if (key->valid & TCP_VALID) {
        // flow->tcp_flags = key->tcph.flags; /* TODO: enable flags */
        flow->tp_src = key->tcph.tcp_src;
        flow->tp_dst = key->tcph.tcp_dst;
    } else if (key->valid & UDP_VALID) {
        flow->tp_src = htons(key->udph.udp_src);
        flow->tp_dst = htons(key->udph.udp_dst);
    } else if (key->valid & ICMP_VALID) {
        flow->tp_src = htons(key->icmph.icmp_type); // u8 to be16
        flow->tp_dst = htons(key->icmph.icmp_code);
    } else if (key->valid & ICMPV6_VALID) {
        flow->tp_src = htons(key->icmp6h.icmpv6_type); // u8 to be16
        flow->tp_dst = htons(key->icmp6h.icmpv6_code);
    } 

    return ODP_FIT_PERFECT;
}

static int
dpif_xf_actions_from_nlattrs(const struct dp_xdp *dp, const struct nlattr *acts, uint32_t actions_len,
                              struct xfa_buf *xdp_acts, bool probe)
{
    /* TODO: indicate the key actions that can't be handled by xdp datapath  */
    const struct nlattr *a;
    size_t left;
    int len = 0;
    memset(xdp_acts, 0, sizeof *xdp_acts);
    struct xfa_cur cursor;
    memset(&cursor, 0, sizeof(struct xfa_cur));

    NL_ATTR_FOR_EACH(a, left, acts, actions_len) {
        enum ovs_action_attr type = nl_attr_type(a);
        __u32 hdr_type = 0;

        switch (type) {
        case OVS_ACTION_ATTR_UNSPEC: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_UNSPEC;
            break;
        }
        case OVS_ACTION_ATTR_OUTPUT: {
            hdr_type = XDP_ACTION_ATTR_OUTPUT;
            odp_port_t port_no = nl_attr_get_odp_port(a);
            struct dp_xdp_port *port = NULL;
            int err = get_port_by_number(dp, port_no, &port);
            if (err)
                goto out;

            int ifindex = port->ifindex;
            len = sizeof(int);
            int ret = xfa_put(xdp_acts, hdr_type, &cursor, &ifindex, len);
            if (ret < 0)
                return ODP_FIT_ERROR;

            break;
        }
        case OVS_ACTION_ATTR_TRUNC: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_TRUNC;
            break;
        }
        case OVS_ACTION_ATTR_METER: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_METER;
            break;
        }
        case OVS_ACTION_ATTR_USERSPACE: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_USERSPACE;
            // TODO: add the action data
            break;
        }
        case OVS_ACTION_ATTR_PUSH_VLAN: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_PUSH_VLAN;
            // TODO: add action data
            break;
        }
        case OVS_ACTION_ATTR_POP_VLAN: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_POP_VLAN;
            /* TODO: implement key parse */
            break;
        }
        case OVS_ACTION_ATTR_PUSH_MPLS: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_PUSH_MPLS;
            /* TODO: implement key parse */
            break;
        }
        case OVS_ACTION_ATTR_POP_MPLS: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_POP_MPLS;
            break;
        }
        case OVS_ACTION_ATTR_RECIRC: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_RECIRC;
            break;
        }
        case OVS_ACTION_ATTR_HASH: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_HASH;
            break;
        }
        case OVS_ACTION_ATTR_SET: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_SET;
            break;
        }
        case OVS_ACTION_ATTR_SET_MASKED: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_SET_MASKED;
            break;
        }
        case OVS_ACTION_ATTR_SAMPLE: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_SAMPLE;
            break;
        }
        case OVS_ACTION_ATTR_CT: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_CT;
            break;
        }
        case OVS_ACTION_ATTR_CT_CLEAR: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_CT_CLEAR;
            break;
        }
        case OVS_ACTION_ATTR_PUSH_ETH: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_PUSH_ETH;
            break;
        }
        case OVS_ACTION_ATTR_POP_ETH: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_POP_ETH;
            break;
        }
        case OVS_ACTION_ATTR_CLONE: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_CLONE;
            break;
        }
        case OVS_ACTION_ATTR_PUSH_NSH: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_PUSH_NSH;
            break;
        }
        case OVS_ACTION_ATTR_POP_NSH: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_POP_NSH;
            break;
        }
        case OVS_ACTION_ATTR_CHECK_PKT_LEN: {
            
            break;
        }
        case OVS_ACTION_ATTR_DROP: {
            len = nl_attr_get_size(a);
            hdr_type = XDP_ACTION_ATTR_DROP;
            break;
        }
        case OVS_ACTION_ATTR_TUNNEL_PUSH:
        case OVS_ACTION_ATTR_TUNNEL_POP:
        case OVS_ACTION_ATTR_XDPNSH:
        case __OVS_ACTION_ATTR_MAX:
        default:
            VLOG_WARN("---- Called: %s dpif_xf_actions_from_nlattrs type %d----", __func__, type);
            return ODP_FIT_ERROR;
        }
    }

out:
    return ODP_FIT_PERFECT;
}


static int
dpif_xf_key_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              struct xf_key *xdp_key, bool probe)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    /* TODO: indicate the key actions that can't be handled by xdp datapath  */
    const struct nlattr *a;
    size_t left;
    memset(xdp_key, 0, sizeof *xdp_key);
    NL_ATTR_FOR_EACH(a, left, key, key_len) {
        enum ovs_key_attr type = nl_attr_type(a);
        switch (type) {
        case OVS_KEY_ATTR_UNSPEC: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_ENCAP: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_PRIORITY: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_IN_PORT: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_ETHERNET: {
            const struct ovs_key_ethernet *eth = nl_attr_get(a);
            memcpy(xdp_key->eth.eth_src, &eth->eth_src, ETH_ALEN);
            memcpy(xdp_key->eth.eth_dst, &eth->eth_dst, ETH_ALEN);
            xdp_key->valid |= ETH_VALID;
            break;
        }
        case OVS_KEY_ATTR_VLAN: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_ETHERTYPE: {
            ovs_be16 dl_type = nl_attr_get_be16(a);

            xdp_key->eth.h_proto = dl_type;

            /* TODO: implement the logic to check if valid */
            break;
        }
        case OVS_KEY_ATTR_IPV4: {
            const struct ovs_key_ipv4 *ipv4 = nl_attr_get(a);
            xdp_key->iph.ipv4_src = ipv4->ipv4_src;
            xdp_key->iph.ipv4_dst = ipv4->ipv4_dst;
            xdp_key->iph.ipv4_proto = ipv4->ipv4_proto;
            xdp_key->iph.ipv4_tos = ipv4->ipv4_tos;
            xdp_key->iph.ipv4_ttl = ipv4->ipv4_ttl;
            // xdp_key->iph.ipv4_frag = ipv4->ipv4_frag; /* TODO: support flag */

            xdp_key->valid |= IPV4_VALID;
            break;
        }
        case OVS_KEY_ATTR_IPV6: {
            const struct ovs_key_ipv6 *ipv6 = nl_attr_get(a);

            xdp_key->ipv6h.ipv6_proto = ipv6->ipv6_proto;
            xdp_key->ipv6h.ipv6_tclass = ipv6->ipv6_tclass;
            xdp_key->ipv6h.ipv6_hlimit = ipv6->ipv6_hlimit;
            xdp_key->ipv6h.ipv6_frag = 0;

            memcpy(xdp_key->ipv6h.ipv6_dst.addr_b32, &ipv6->ipv6_src, 4);
            memcpy(xdp_key->ipv6h.ipv6_src.addr_b32, &ipv6->ipv6_dst, 4);

            xdp_key->valid |= IPV6_VALID;
            break;
        }
        case OVS_KEY_ATTR_TCP: {
            const struct ovs_key_tcp *tcp = nl_attr_get(a);
            xdp_key->tcph.tcp_src = tcp->tcp_src;
            xdp_key->tcph.tcp_dst = tcp->tcp_dst;

            xdp_key->valid |= TCP_VALID;
            break;
        }
        case OVS_KEY_ATTR_UDP: {
            const struct ovs_key_udp *udp = nl_attr_get(a);
            xdp_key->udph.udp_src = udp->udp_src;
            xdp_key->udph.udp_dst = udp->udp_dst;

            xdp_key->valid |= UDP_VALID;
            break;
        }
        case OVS_KEY_ATTR_ICMP: {
            const struct ovs_key_icmp *icmp = nl_attr_get(a);
            xdp_key->icmph.icmp_type = icmp->icmp_type;
            xdp_key->icmph.icmp_code = icmp->icmp_code;

            xdp_key->valid |= ICMP_VALID;
            break;
        }
        case OVS_KEY_ATTR_ICMPV6: {
            const struct ovs_key_icmpv6 *icmpv6 = nl_attr_get(a);

            xdp_key->icmp6h.icmpv6_type = icmpv6->icmpv6_type;
            xdp_key->icmp6h.icmpv6_type = icmpv6->icmpv6_type;

            xdp_key->valid |= ICMPV6_VALID;
            break;
        }
        case OVS_KEY_ATTR_ARP: {
            const struct ovs_key_arp *arp = nl_attr_get(a);
            #pragma push_macro("arp_op")
            #define	arp_op	arp_op
            xdp_key->arph.ar_op = arp->arp_op; /* TODO: fix me*/
            #pragma pop_macro("arp_op")
            xdp_key->arph.arp_sip = arp->arp_sip;
            xdp_key->arph.arp_tip = arp->arp_tip;
            
            memcpy(xdp_key->arph.arp_sha, &arp->arp_sha, sizeof(arp->arp_sha));
            memcpy(xdp_key->arph.arp_tha, &arp->arp_tha, sizeof(arp->arp_tha));

            xdp_key->valid |= ARP_VALID;
            break;
        }
        case OVS_KEY_ATTR_ND: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_SKB_MARK: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_TUNNEL: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_SCTP: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_TCP_FLAGS: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_DP_HASH: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_RECIRC_ID: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_MPLS: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_CT_STATE: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_CT_ZONE: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_CT_MARK: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_CT_LABELS: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_NSH: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_PACKET_TYPE: {
            /* TODO: implement key parse */
            break;
        }
        case OVS_KEY_ATTR_ND_EXTENSIONS: {
            /* TODO: implement key parse */
            break;
        }
        case __OVS_KEY_ATTR_MAX:
        default:
            return ODP_FIT_ERROR;
        }
    }
    return ODP_FIT_PERFECT;
}

// static int
// dpif_xdp_mask_from_nlattrs(const struct nlattr *key, uint32_t key_len,
//                               const struct nlattr *mask_key,
//                               uint32_t mask_key_len, const struct flow *flow,
//                               struct flow_wildcards *wc, bool probe)
// {
//     // VLOG_INFO("---- Called: %s ----", __func__);

//     /* TODO: implement method */
    
//     return 0;
// }

static void
dp_xdp_ep_remove_flow(struct dp_xdp_entry_point *ep,
                      struct xf *flow)
    // OVS_REQUIRES(ep->flow_mutex) /* TODO: check if needed. Comment in dp_xdp_entry_point too */
{
    /* TODO: remove flow from the ep->flow_table_cache bpf_map */
}

static void
dp_xdp_ep_flow_flush(struct dp_xdp_entry_point *ep)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    // struct xf *xf;

    // ovs_mutex_lock(&ep->flow_mutex); /* TODO: uncomment if needed */
    
    /* TODO: loop through the ep->flow_table_cache bpf_map passing each flow and ep to
       dp_xdp_ep_remove_flow(ep, xf) */

    // ovs_mutex_unlock(&ep->flow_mutex); /* TODO: uncomment if needed */
}

static struct xf *
dp_xdp_ep_lookup_flow(struct dp_xdp_entry_point *ep,
                          struct xf_key *key,
                          int *lookup_num_p)
{
    // VLOG_INFO("---- Called: %s ep->flow_map_fd: %d ----", __func__, ep->flow_map_fd);
    struct xf *xf = NULL;

    /* TODO: implement method */
    struct dp_xdp *dp = ep->dp;
    // xswitch_ep_flow_lookup(ep->flow_map_fd, key, &xf);
    xswitch_br__flow_lookup(dp->name, key, &xf);
    return xf;
}

static struct xf *
dp_xdp_ep_find_flow(const struct dp_xdp_entry_point *ep,
                        const ovs_u128 *ufidp, const struct nlattr *key,
                        size_t key_len)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    // struct xf *xf;
    // struct flow flow;
    // ovs_u128 ufid;

    /* TODO: verify that we are using the same type of key, else we
       have to change the hash function odp_flow_key_hash */
    
    /* TODO: check if ufid is set, if not set generate one using the
       a hash function on the flows and set the result to ufid */

    /* TODO: search for the flow in the ep's bpf_map and return xf
       if found. ELSE return NULL */

    return NULL;
}

// static struct xf * dp_xdp_ep_next_flow(const struct dp_xdp_entry_point *ep,
//                         struct xf_key *key)
// {
//     VLOG_INFO("---- Called: %s flow_map_fd %d ----", __func__, ep->flow_map_fd);
//     struct xf *xf = NULL;
    
//     /* returns xf = NULL when end of map */
//     if (xswitch_ep_flow_next(ep->flow_map_fd, key, &xf)) {
//         xf = NULL;
//     }

//     return xf;
// }

static int dp_xdp_ep_update_flow(const struct dp_xdp_entry_point *ep,
                        struct xf *flow)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp *dp = ep->dp;

    return xswitch_br__flow_insert(dp->name, flow);
}

static struct dpif_xf_dump *
dpif_xf_dump_cast(struct dpif_flow_dump *dump)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    return CONTAINER_OF(dump, struct dpif_xf_dump, up);
}

static struct dpif_xf_dump_thread *
dpif_xf_dump_thread_cast(struct dpif_flow_dump_thread *thread)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    return CONTAINER_OF(thread, struct dpif_xf_dump_thread, up);
}

/* Given cmap position 'pos', tries to ref the next node.  If try_ref()
 * fails, keeps checking for next node until reaching the end of cmap.
 *
 * Caller must unrefs the returned reference. */
static struct dp_xdp_entry_point *
dp_xdp_ep_get_next(struct dp_xdp *dp, struct cmap_position *pos)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp_entry_point *next;

    do {
        struct cmap_node *node;

        node = cmap_next_position(&dp->entry_points, pos);
        next = node ? CONTAINER_OF(node, struct dp_xdp_entry_point, node)
            : NULL;
    } while (next && !dp_xdp_ep_try_ref(next));
    return next;
}

/* Configures the 'ep' based on the input argument. */
static int
dp_xdp_configure_ep(struct dp_xdp_entry_point **epp, struct dp_xdp *dp,
                        struct dp_xdp_port *port, struct xs_cfg *cfg)
{
    VLOG_INFO("---- Called: %s, devname %s ----", __func__, cfg->ifname);
    struct xdp_ep *xdp_ep;
    int error = 0;
    struct dp_xdp_entry_point *ep = NULL;
    *epp = NULL;
    
    // check if program already loaded
    if (dp_xdp_get_ep(dp, port->ep_id))
        goto out;

    /* load the xdp program */
    xdp_ep = xzalloc(sizeof *xdp_ep);
    // error = xdp_load(xdp_ep, path, devname);
    error = xdp_prog_default_load(xdp_ep, cfg);

    /* If program exist probably want to unload and load again */
    if (!(error == EEXIST || error == -EEXIST || error == 0)) {
        goto out;
    }
    VLOG_INFO("--- Successfully loaded xdp program ep_id: %d ---", xdp_ep->ep_id);
    /* check if port has been configure on an already existing ep */
    ep = dp_xdp_get_ep(dp, xdp_ep->ep_id);
    if (!ep) {
        ep = xzalloc(sizeof *ep);
        ep->dp = dp;
        ep->ep_id = xdp_ep->ep_id;
        ep->flow_map_fd = xdp_ep->flow_map_fd;
        ep->stats_map_fd = xdp_ep->stats_map_fd;
        ovs_refcount_init(&ep->ref_cnt);
        hmap_init(&ep->ports);
        cmap_insert(&dp->entry_points, CONST_CAST(struct cmap_node *, &ep->node),
                    hash_int(xdp_ep->ep_id, 0));
         /* Initialise UMEM */
        error = xswitch_xsk__create_umem__v2(&ep->umem);
        if (error) {
            VLOG_INFO("---- Called: %s xswitch_xsk__create_umem__v2 failed");
            goto out;
        }
    }

    hmap_insert(&ep->ports, &port->epnode, hash_port_no(port->port_no));
    port->ep_id = xdp_ep->ep_id;
    *epp = ep;
    
    if (dp_xdp_get_ep(dp, xdp_ep->ep_id))
        error = 0;

out:
    if (error) {
        dp_xdp_destroy_ep(ep);
    }
    return error;
}

/* don't need to delete point since it the 
 * ep point might just being changed to an ordinary port.
 * If caller intends to delete the port as well then must
 * explictly call method to delete port. 
 * */
static void
dp_xdp_destroy_ep(struct dp_xdp_entry_point *ep)
{
    VLOG_INFO("---- Called: %s ----", __func__);

    dp_xdp_ep_flow_flush(ep);

    /* TODO: delete devmap bpf_map */
    
    /* TODO: delete prog bpf_prog */

    /* TODO: delete flow_table_cache bpf_map */

    /* TODO: delete stats bpf_map */
              
    free(ep);
}

/* Caller must have valid pointer to 'ep'. */
static bool
dp_xdp_ep_try_ref(struct dp_xdp_entry_point *ep)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    return ovs_refcount_try_ref_rcu(&ep->ref_cnt);
}

static void
dp_xdp_ep_unref(struct dp_xdp_entry_point *ep)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    if (ep && ovs_refcount_unref(&ep->ref_cnt) == 1) {
        ovsrcu_postpone(dp_xdp_destroy_ep, ep);
    }
}

static void
dp_xdp_actions_free(struct dp_xdp_actions *actions)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    free(actions);
}

/* Creates and returns a new 'struct dp_xdp_actions', whose actions are
 * a copy of the 'size' bytes of 'actions' input parameters. */
struct dp_xdp_actions *
dp_xdp_actions_create(const struct nlattr *actions, size_t size)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp_actions *xdp_actions;

    // TODO: implement method relavant to our dp_xdp_actions

    xdp_actions = xmalloc(sizeof *xdp_actions + size);
    memcpy(xdp_actions->actions, actions, size);
    xdp_actions->size = size;

    return xdp_actions;
}

struct dp_xdp_actions *
dp_xf_get_actions(const struct xf *flow)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    // return ovsrcu_get(struct dp_xdp_actions *, &flow->actions);
    return NULL;
}

/* Finds and refs the dp_netdev_pmd_thread on core 'core_id'.  Returns
 * the pointer if succeeds, otherwise, NULL (it can return NULL even if
 * 'core_id' is NON_PMD_CORE_ID).
 *
 * Caller must unrefs the returned reference.  */
static struct dp_xdp_entry_point *
dp_xdp_get_ep(struct dp_xdp *dp, int ep_id)
{
    // VLOG_INFO("---- Called: %s, ep_id %d ----", __func__, ep_id);
    struct dp_xdp_entry_point *ep;
    const struct cmap_node *pnode;

    pnode = cmap_find(&dp->entry_points, hash_int(ep_id, 0));
    if (!pnode) {
        return NULL;
    }
    ep = CONTAINER_OF(pnode, struct dp_xdp_entry_point, node);

    return dp_xdp_ep_try_ref(ep) ? ep : NULL;
}

static void
dp_xf_to_dpif_flow(const struct dp_xdp *dp, int ep_id,
                            const struct xf *xf,
                            struct ofpbuf *key_buf, struct ofpbuf *mask_buf,
                            struct dpif_flow *flow, bool terse)
{
    VLOG_INFO("---- Called: %s ----", __func__);

    /* TODO: implement this method */

    /* TODO: make sure that the method checks if the flow is available
       already before adding it since our method may result in the same
       flow on different entry points. */

    struct ofpbuf act_buf;
    dp_xf_to_dpif_flow__(dp, ep_id, xf, key_buf, mask_buf, &act_buf, flow, terse);
}

/* NOTE: when a single flow is being requested by flow_get the buffer provided maybe small for key, mask
 * and actions to fit in. Therefore we will pass the actions to the point thats not in the buffer as other
 * dpif hence this overloaded function */
static void
dp_xf_to_dpif_flow__(const struct dp_xdp *dp, int ep_id,
                            const struct xf *xf,
                            struct ofpbuf *key_buf, struct ofpbuf *mask_buf, struct ofpbuf *act_buf,
                            struct dpif_flow *dpif_flow, bool terse)
{
    // VLOG_INFO("---- Called: %s ----", __func__);

    /* TODO: implement this method */

    /* TODO: make sure that the method checks if the flow is available
       already before adding it since our method may result in the same
       flow on different entry points. */
    struct flow flow;
    

    xf_key_to_flow(&xf->key, &flow);

    if (terse) {
        memset(dpif_flow, 0, sizeof *dpif_flow);
    } else {
        size_t offset;
        struct odp_flow_key_parms odp_parms = {
            .flow = &flow,
            .support = dp_xdp_support,
        };

        /* Key */
        offset = key_buf->size;
        dpif_flow->key = ofpbuf_tail(key_buf);
        odp_flow_key_from_flow(&odp_parms, key_buf);
        dpif_flow->key_len = key_buf->size - offset;

        /* Mask */
        /* TODO: implement */

        /* Actions */
        offset = act_buf->size;
        dpif_flow->actions = ofpbuf_tail(act_buf);
        int error = xf_actions_to_odp_actions(dp, &xf->actions, act_buf);
        if (error) {
            VLOG_WARN("---- Called: %s, one of the xfa_buf to odp_actions failed ----", __func__);
        }
        dpif_flow->actions_len = key_buf->size - offset;
    }

    dp_xf_hash(dpif_flow->key, dpif_flow->key_len, &dpif_flow->ufid);
    dpif_flow->ufid_present = true;
    // dpif_flow->pmd_id = netdev_flow->pmd_id; /* TODO: assign ep_id */

    /* TODO: fetch stats*/
}

static void
dpif_xf_get_stats(const struct xf *flow,
                            struct dpif_flow_stats *stats)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    /* TODO: implement method */
}

static int
flow_put_on_ep(struct dp_xdp_entry_point *ep,
                struct xf_key *key,
                ovs_u128 *ufid,
                const struct dpif_flow_put *put,
                struct dpif_flow_stats *stats)
{
    struct xf *xf = NULL;
    struct xfa_buf acts;
    int error = 0;

    error = dpif_xf_actions_from_nlattrs(ep->dp, put->actions, put->actions_len, &acts,
                                        true);
    if (error) {
        VLOG_INFO("---- Called: %s, error from dpif_xf_actions_from_nlattrs ----", __func__);
        goto out;
    }

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }

    // ovs_mutex_lock(&ep->flow_mutex); // TODO: check if needed
    xf = dp_xdp_ep_lookup_flow(ep, key, 0);
    if (!xf) {
        if (put->flags & DPIF_FP_CREATE) {
            struct xf flow;
            memset(&flow, 0, sizeof(struct xf));
            memcpy(&flow.key, key, sizeof(struct xf_key));
            memcpy(&flow.actions, &acts, sizeof(struct xfa_buf));
            error = dp_xdp_ep_update_flow(ep, &flow);
            if (error) {
                goto out;
            }
        } else {
            VLOG_INFO("---- Called: %s, DPIF_FP_CREATE failed ----", __func__);
            error = ENOENT;
            goto out;
        }
    } else {
        if (put->flags & DPIF_FP_MODIFY) {
            VLOG_INFO("---- Called: %s DPIF_FP_MODIFY  not supported yet----", __func__);
            struct dp_xdp_actions *new_actions;
            struct dp_xdp_actions *old_actions;

            new_actions = dp_xdp_actions_create(put->actions,
                                                   put->actions_len);

            old_actions = dp_xf_get_actions(xf);
            // ovsrcu_set(&xf->actions, new_actions);

            /* TODO: update the bpf_map flow action */

            if (stats) {
                dpif_xf_get_stats(xf, stats);
            }

            /* TODO: verify if this is the case as well for our implementation 
               or we can support write to stats */
            if (put->flags & DPIF_FP_ZERO_STATS) {
                VLOG_INFO("---- Called: %s DPIF_FP_ZERO_STATS ----", __func__);
                /* XXX: The userspace datapath uses thread local statistics
                 * (for flows), which should be updated only by the owning
                 * thread.  Since we cannot write on stats memory here,
                 * we choose not to support this flag.  Please note:
                 * - This feature is currently used only by dpctl commands with
                 *   option --clear.
                 * - Should the need arise, this operation can be implemented
                 *   by keeping a base value (to be update here) for each
                 *   counter, and subtracting it before outputting the stats */
                error = EOPNOTSUPP;
            }

            ovsrcu_postpone(dp_xdp_actions_free, old_actions);
        } else if (put->flags & DPIF_FP_CREATE) {
            error = EEXIST;
            goto out;
        } else {
            /* Overlapping flow. */
            error = EINVAL;
            goto out;
        }
    }
    // ovs_mutex_unlock(&ep->flow_mutex); // TODO: check if needed
out:
    return error;
}

static int
dpif_xf_put(struct dpif *dpif, const struct dpif_flow_put *put)
{
    // VLOG_INFO("---- Called: %s pmd_id %d ----", __func__, put->pmd_id);
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct dp_xdp_entry_point *ep;
    ovs_u128 ufid;
    int error = 0;
    bool probe = put->flags & DPIF_FP_PROBE;
   
    if (put->stats) {
        memset(put->stats, 0, sizeof *put->stats);
    }

    struct xf_key key;
    memset(&key, 0, sizeof(struct xf_key));
    /* TODO: implement method */
    error = dpif_xf_key_from_nlattrs(put->key, put->key_len, &key,
                                        probe);

    if (error) {
        return error;
    }

    if (put->ufid) {
        ufid = *put->ufid;
    } else {
        // odp_flow_key_hash(&match.flow, sizeof match.flow, &ufid);
    }

    // we will treat the pmd id as the etry point id (port_no)
    if (put->pmd_id == PMD_ID_NULL) {
        /* TODO: need to revise this in case we change our logic. If we are 
           going to have a macro cache then for flows with ep specified we 
           should add then to that macro cache instead of putting it on every
           micro cache (ep) */
        
        if (cmap_count(&dp->entry_points) == 0) {
            VLOG_INFO("---- Called: %s, no entry point defined yet ----", __func__);
            return EINVAL;
        }
        CMAP_FOR_EACH (ep, node, &dp->entry_points) {
            struct dpif_flow_stats ep_stats;
            int ep_error;

            ep_error = flow_put_on_ep(ep, &key, &ufid, put,
                                        &ep_stats);
            if (ep_error) {
                error = ep_error;
            } else if (put->stats) {
                put->stats->n_packets += ep_stats.n_packets;
                put->stats->n_bytes += ep_stats.n_bytes;
                put->stats->used = MAX(put->stats->used, ep_stats.used);
                put->stats->tcp_flags |= ep_stats.tcp_flags;
            }
        }
    } else { // add to the specified entry point
        ep = dp_xdp_get_ep(dp, put->pmd_id);
        if (!ep) {
            return EINVAL;
        }
        error = flow_put_on_ep(ep, &key, &ufid, put, put->stats);
        dp_xdp_ep_unref(ep);
    }
    return error;
}

static int
flow_del_on_ep(struct dp_xdp_entry_point *ep,
                struct dpif_flow_stats *stats,
                const struct dpif_flow_del *del)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    struct xf *xf;
    int error = 0;

    // ovs_mutex_lock(&ep->flow_mutex); // TODO: check if needed
    xf = dp_xdp_ep_find_flow(ep, del->ufid, del->key,
                                          del->key_len);
    if (xf) {
        // VLOG_INFO("== Called: %s, xf not null ==", __func__);
        if (stats) {
            dpif_xf_get_stats(xf, stats);
        }
        dp_xdp_ep_remove_flow(ep, xf);
    } else {
        error = ENOENT;
    }
    // ovs_mutex_unlock(&pmd->flow_mutex); // TODO: check if needed

    return error;
}

static int
dpif_xf_del(struct dpif *dpif, const struct dpif_flow_del *del)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    int error = 0;
    /* TODO: implement method */
    // struct dp_xdp *dp = get_dp_xdp(dpif);
    // struct dp_xdp_entry_point *ep;

    // if (del->stats) {
    //     memset(del->stats, 0, sizeof *del->stats);
    // }

    // if (del->pmd_id == PMD_ID_NULL) {
    //     if (cmap_count(&dp->entry_points) == 0) {
    //         return EINVAL;
    //     }
    //     CMAP_FOR_EACH (ep, node, &dp->entry_points) {
    //         struct dpif_flow_stats ep_stats;
    //         int ep_error;

    //         ep_error = flow_del_on_ep(ep, &ep_stats, del);
    //         if (ep_error) {
    //             error = ep_error;
    //         } else if (del->stats) {
    //             del->stats->n_packets += ep_stats.n_packets;
    //             del->stats->n_bytes += ep_stats.n_bytes;
    //             del->stats->used = MAX(del->stats->used, ep_stats.used);
    //             del->stats->tcp_flags |= ep_stats.tcp_flags;
    //         }
    //     }
    // } else {
    //     ep = dp_xdp_get_ep(dp, del->pmd_id);
    //     if (!ep) {
    //         return EINVAL;
    //     }
    //     error = flow_del_on_ep(ep, del->stats, del);
    //     dp_xdp_ep_unref(ep);
    // }

    return error;
}

static void complete_tx(struct xsk_socket_info *xsk)
{
    unsigned int completed;
    uint32_t idx_cq;

    if (!xsk->outstanding_tx)
        return;

    VLOG_INFO("--- Called: %s xsk_socket__fd(xsk->xsk): %d ----", __func__, xsk_socket__fd(xsk->xsk));
    int ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    VLOG_INFO("--- Called: %s sendto return: %d ---", __func__, ret);

    /* Collect/free completed TX buffers */
    completed = xsk_ring_cons__peek(&xsk->umem->cq,
                    XSK_RING_CONS__DEFAULT_NUM_DESCS,
                    &idx_cq);

    VLOG_INFO("--- Called: %s completed: %d ---", __func__, completed);
    if (completed > 0) {
        for (int i = 0; i < completed; i++)
            xsk_free_umem_frame(xsk,
                        *xsk_ring_cons__comp_addr(&xsk->umem->cq,
                                      idx_cq++));

        xsk_ring_cons__release(&xsk->umem->cq, completed);
    }
}

static void tx_only(struct xsk_socket_info *xsk, struct dp_packet *packet)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    __u32 idx = 0;
    

    if (xsk_ring_prod__reserve(&xsk->tx, 1, &idx) == 1) {
        VLOG_INFO("---- Called: %s xsk_ring_prod__reserve ---", __func__); 
        // get address of free mem
        uint64_t addr = xsk_alloc_umem_frame(xsk);
        void *ptr = xsk_umem__get_data(xsk->umem->buffer, addr);
        uint32_t len = dp_packet_size(packet);
        // fill that address with packets (memcpy)
        memcpy(ptr, dp_packet_data(packet), len);
        
        // assign that addr to ring
        xsk_ring_prod__tx_desc(&xsk->tx, idx)->addr    = addr;
        xsk_ring_prod__tx_desc(&xsk->tx, idx)->len = len;

        xsk_ring_prod__submit(&xsk->tx, 1);
        xsk->outstanding_tx++;
        xsk->stats.tx_bytes += len;
        xsk->stats.tx_packets++;
    }

    // send it out.
    complete_tx(xsk);
}

static int
dpif_xdp_execute(struct dpif *dpif, struct dpif_execute *execute)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct dp_xdp_port *port;
    int queue = 0;
    // struct dp_xdp_entry_point *ep;
    int error = 0;

    if (dp_packet_size(execute->packet) < ETH_HEADER_LEN ||
        dp_packet_size(execute->packet) > UINT16_MAX) {
        return EINVAL;
    }

    /* TODO: implement logic to execute actions on the packet. Might need
       a mechanism to inject traffic on the interface specified by in_port
       but first we will need to put in the action and the flow key on the
       ep's flow_table_cache. Not sure if we can inject a packet on an 
       interface but if we can then we can use this approach to handle the
       DPIF_OP_EXECUTE operate type. The steps needed will be similar to the
       ones below. */

    // parse the actions to know which actions to apply

    // get the flow key from flow

    // get the port_no for the ep from flow->in_port

    // insert the deatils in flow_table_cache

    const struct nlattr *a;
    unsigned int left;
    
    NL_ATTR_FOR_EACH_UNSAFE (a, left, execute->actions, execute->actions_len) {
        enum ovs_action_attr type = nl_attr_type(a);

        if (type == OVS_ACTION_ATTR_OUTPUT) {
            struct ds dsf = DS_EMPTY_INITIALIZER;
            odp_port_t port_no = { 0 };
            if (bpf_ntohs(execute->flow->dl_type) == ETH_P_ARP
                || bpf_ntohs(execute->flow->dl_type) == ETH_P_RARP) {
                port_no = nl_attr_get_odp_port(a);
                VLOG_INFO("--- Called: %s arp port_no %d ----", __func__, odp_to_u32(port_no));
                struct dp_xdp_port *port_in;
                odp_port_t in_port = execute->flow->in_port.odp_port;
                ovs_mutex_lock(&dp->port_mutex);
                error = get_port_by_number(dp, in_port, &port_in);
                ovs_mutex_unlock(&dp->port_mutex);
                if (error) {
                    goto out;
                }

                // skip bridge interface, assuming that all bridge interfaces are
                // of type tap and the ports are of type system
                if (strcmp(port_in->type, "tap") == 0)
                    continue;

                // add to arp table
                error = xswitch_arp__add_entry(port_in->name, execute->flow->nw_src, execute->flow->arp_sha.ea);
                if (error) {
                    VLOG_WARN("--- Called: %s error xswitch_arp__add_entry ---", __func__);
                    continue;
                }
            } else {
                port_no = execute->flow->in_port.odp_port;
            }
            
            ovs_mutex_lock(&dp->port_mutex);
            error = get_port_by_number(dp, port_no, &port);
            ovs_mutex_unlock(&dp->port_mutex);
            if (error) {
                goto out;
            }

            struct dp_packet_batch batch;
            struct dp_packet *clone_pkt = dp_packet_clone(execute->packet);
            dp_packet_batch_init_packet(&batch, clone_pkt);

            struct flow flow;
            flow_extract(clone_pkt, &flow);

            struct ds ds = DS_EMPTY_INITIALIZER;
            flow_format(&ds, &flow, NULL);
            VLOG_INFO("--- Called: %s out_port %d, flow %s ---", __func__, odp_to_u32(port->port_no), ds_cstr(&ds));
            ds_destroy(&ds);

            // tx_only(dp->channels[odp_to_u32(port_no)].sock, clone_pkt);
            error = netdev_send(port->netdev, queue, &batch, false);
            if (error) {
                VLOG_INFO("--- Called: %s error sending out ---", __func__);
                continue;
            }
        }
    }
    
out:
    return error;
}

static int
dpif_xf_get(const struct dpif *dpif, const struct dpif_flow_get *get)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct xf *xf;
    struct dp_xdp_entry_point *ep;
    struct hmapx to_find = HMAPX_INITIALIZER(&to_find);
    struct hmapx_node *node;
    int error = EINVAL;

    if (get->pmd_id == PMD_ID_NULL) {
        CMAP_FOR_EACH (ep, node, &dp->entry_points) {
            if (dp_xdp_ep_try_ref(ep) && !hmapx_add(&to_find, ep)) {
                dp_xdp_ep_unref(ep);
            }
        }
    } else {
        ep = dp_xdp_get_ep(dp, get->pmd_id);
        if (!ep) {
            goto out;
        }
        hmapx_add(&to_find, ep);
    }

    if (!hmapx_count(&to_find)) {
        goto out;
    }

    HMAPX_FOR_EACH (node, &to_find) {
        struct ds dsf = DS_EMPTY_INITIALIZER;
        odp_format_ufid(get->ufid, &dsf);
        ep = (struct dp_xdp_entry_point *) node->data;
        xf = dp_xdp_ep_find_flow(ep, get->ufid, get->key,
                                              get->key_len);
        if (xf) {
            dp_xf_to_dpif_flow(dp, ep->ep_id, xf, get->buffer,
                                        get->buffer, get->flow, false);
            error = 0;
            break;
        } else {
            error = ENOENT;
        }
    }

    HMAPX_FOR_EACH (node, &to_find) {
        ep = (struct dp_xdp_entry_point *) node->data;
        dp_xdp_ep_unref(ep);
    }
out:
    hmapx_destroy(&to_find);
    return error;
}

/* Provider functions */
static int
dpif_xdp_init()
{
    VLOG_INFO("---- Called: %s ----", __func__);
    static int error = 0; // retains it's previous value in future calls

    /*  TODO: not sure if (1) should be done now or on create 
        (2) doesn't need to be unique (per dp) so can be set up 
        at this point */

    /* TODO: 
       1) set up for downcall from OVS 
       2) create and set up map to receive from nftables */    

    return error;
}

static int
dpif_xdp_enumerate(struct sset *all_dps, const struct dpif_class *dpif_class)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    struct shash_node *node;

    ovs_mutex_lock(&dp_xdp_mutex);
    SHASH_FOR_EACH(node, &dp_xdps) {
        struct dp_xdp *dp = node->data;
        if (dpif_class != dp->class) {
            /* 'dp_netdevs' contains both "netdev" and "dummy" dpifs.
             * If the class doesn't match, skip this dpif. */
             continue;
        }
        sset_add(all_dps, node->name);
    }
    ovs_mutex_unlock(&dp_xdp_mutex);

    return 0;
}

static const char *
dpif_xdp_port_open_type(const struct dpif_class *dpif_class,
                                  const char *type)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    return strcmp(type, "internal") ? type : "tap";
}

static int
dpif_xdp_open(const struct dpif_class *dpif_class,
                const char *name, bool create, struct dpif **dpifp)
{
    VLOG_INFO("---- Called: %s name %s----", __func__, name);
    struct dp_xdp *dp;
    int error;

    error = dpif_xdp_init();
    if (error) {
        VLOG_ERR("error from dpif_xdp_open calling dpif_xdp_init");
        return error;
    }

    ovs_mutex_lock(&dp_xdp_mutex);
    dp = shash_find_data(&dp_xdps, name);
    if (!dp) {
        error = create ? create_dp_xdp(name, dpif_class, &dp) : ENODEV;
    } else {
        VLOG_INFO("--- dp %s already exists ---", name);
        error = (dp->class != dpif_class ? EINVAL
                 : create ? EEXIST
                 : 0);
    }
    if (!error) {
        *dpifp = create_dpif_xdp(dp);
        if (create) {
            dp->dpif = *dpifp;
        }
    }
    ovs_mutex_unlock(&dp_xdp_mutex);

    return error;

}

static void
dpif_xdp_close(struct dpif *dpif)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp *dp = get_dp_xdp(dpif);

    dp_xdp_unref(dp);
    free(dpif);
}

static int
dpif_xdp_destroy(struct dpif *dpif)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp *dp = get_dp_xdp(dpif);

    if (!atomic_flag_test_and_set(&dp->destroyed)) {
        if (ovs_refcount_unref_relaxed(&dp->ref_cnt) == 1) {
            /* Can't happen: 'dpif' still owns a reference to 'dp'. */
            OVS_NOT_REACHED();
        }
    }

    return 0;
}

static bool
dpif_xdp_run(struct dpif *dpif)
{
    /* TODO: check if this is needed for now returning
       false indicating that there is no periodic work 
       needed to be done. */
    
    return false;
}

static int
dpif_xdp_get_stats(const struct dpif *dpif, struct dpif_dp_stats *stats)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct dp_xdp_entry_point *ep;

    stats->n_flows = stats->n_hit = stats->n_missed = stats->n_lost = 0;
    CMAP_FOR_EACH (ep, node, &dp->entry_points) {
        // TODO: put code to get the stats from each map and add them to each stats->
    }

    return 0;
}

static int
dpif_xdp_port_add(struct dpif *dpif, struct netdev *netdev,
                    odp_port_t *port_nop)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp *dp = get_dp_xdp(dpif);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dpif_port;
    odp_port_t port_no;
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    dpif_port = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);
    if (*port_nop != ODPP_NONE) {
        port_no = *port_nop;
        error = dp_xdp_lookup_port(dp, *port_nop) ? EBUSY : 0;
    } else {
        port_no = choose_port(dp, dpif_port);
        error = port_no == ODPP_NONE ? EFBIG : 0;
    }
    if (error) {
        goto unlock;
    }

    *port_nop = port_no;
    error = do_add_port(dp, dpif_port, netdev_get_type(netdev), port_no);
    if (error) {
        goto unlock;
    }

unlock:
    ovs_mutex_unlock(&dp->port_mutex);
    VLOG_INFO("---- Edded: %s, error %d ----", __func__, error);
    return error;
}

static int
dpif_xdp_port_del(struct dpif *dpif, odp_port_t port_no)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct dp_xdp_port *port;
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    error = get_port_by_number(dp, port_no, &port);
    if (!error) {
        do_del_port(dp, port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

static int
dpif_xdp_port_query_by_number(const struct dpif *dpif, odp_port_t port_no,
                                struct dpif_port *dpif_port)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct dp_xdp_port *port;
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    error = get_port_by_number(dp, port_no, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_mutex_unlock(&dp->port_mutex);
    // VLOG_INFO("---- Ended: %s ----", __func__);
    return error;
}

static int
dpif_xdp_port_query_by_name(const struct dpif *dpif, const char *devname,
                              struct dpif_port *dpif_port)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct dp_xdp_port *port;
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    error = get_port_by_name(dp, devname, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

/** ===============================================================================
 * The minimal behavior of dpif_port_get_pid() and the treatment of the Netlink
 * PID in "action" upcalls is that dpif_port_get_pid() returns a constant value
 * and all upcalls are appended to a single queue. (from dpif.h)
 * For simplicity we will go with this approach first. As mentioned in dpif.h
 * docs under Ports, each port has a Netlink PID and under Upcall Queuing and
 * Ordering it mentions that Netlink PID is a termilogy from the netlink 
 * implentation from the kernel module. In our implementation we will use this
 * to identify the queue that we are going to put our upcalls. We are going to
 * experiment with AF_XDP for upcalls. There is also an implementation with perf
 * that we can adapt in case AF_XDP etheir doesn't work or perform well. It should
 * tho :).
 * 
 * Therefore this function returns the same PID from AF_XDP i.e, all entry_points
 * have the same upcall_pid
 * ================================================================================
*/
static uint32_t 
dpif_xdp_port_get_pid(const struct dpif *dpif, odp_port_t port_no)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    uint32_t ret = 0;

    /* TODO: check if lock is needed for afxdp upcalls (also see dpif_xdp) */
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct dp_xdp_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if(port->port_no == port_no) {
            ret = *port->upcall_pids;
            break;
        }
    }

    return ret;
}

/* Seperating because we need an internal function that iterates 
 * through the ports */
static int
dpif_xdp_port_dump_start__(struct dp_xdp *dp, struct dpif_xdp_port_state *state)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    state = xzalloc(sizeof(struct dpif_xdp_port_state));
    return 0;
}

static int
dpif_xdp_port_dump_start(const struct dpif *dpif, void **statep)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    // struct dp_xdp *dp = get_dp_xdp(dpif);
    // struct dpif_xdp_port_state state;

    // if (!dpif_xdp_port_dump_start__(dp, &state)){
    //     *statep = &state;
    // } else {
    //     return EOF;
    // }
    *statep = xzalloc(sizeof(struct dpif_xdp_port_state));
    return 0;
}

/* Seperating because we need an internal function that iterates
 * through and returns dp_xdp_port instead of dpif_port */
static int
dpif_xdp_port_dump_next__(const struct dp_xdp *dp, struct dpif_xdp_port_state *state,
                          struct dp_xdp_port *port)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct hmap_node *node;
    int retval = 0;

    ovs_mutex_lock(&dp->port_mutex);
    node = hmap_at_position(&dp->ports, &state->position);
    if (node) {
        port = CONTAINER_OF(node, struct dp_xdp_port, node);
        // free(state->name);
        state->name = xstrdup(netdev_get_name(port->netdev));
        retval = 0;
    } else {
        retval = EOF;
    }
    ovs_mutex_unlock(&dp->port_mutex);
    return retval;
}
static int
dpif_xdp_port_dump_next(const struct dpif *dpif, void *state_,
                          struct dpif_port *dpif_port)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dpif_xdp_port_state *state = state_;
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct hmap_node *node;
    int retval = 0;
    
    ovs_mutex_lock(&dp->port_mutex);
    struct dp_xdp_port port;
    node = hmap_at_position(&dp->ports, &state->position);
    if (!dpif_xdp_port_dump_next__(dp, state, &port)) {
        dpif_port->name = state->name;
        dpif_port->type = port.type;
        dpif_port->port_no = port.port_no;
    } else {
        retval = EOF;
    }
    ovs_mutex_unlock(&dp->port_mutex);
    return retval;
}

static int
dpif_xdp_port_dump_done(const struct dpif *dpif, void *state_)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dpif_xdp_port_state *state = state_;
    free(state->name);
    free(state);
    return 0;
}

static int
dpif_xdp_port_poll(const struct dpif *dpif_, char **devnamep)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dpif_xdp *dpif = dpif_xdp_cast(dpif_);
    uint64_t new_port_seq;
    int error;

    new_port_seq = seq_read(dpif->dp->port_seq);
    if (dpif->last_port_seq != new_port_seq) {
        dpif->last_port_seq = new_port_seq;
        error = ENOBUFS;
    } else {
        error = EAGAIN;
    }
    // VLOG_INFO("---- Ended: %s error %d ----", __func__, error);
    return error;
}

static void
dpif_xdp_port_poll_wait(const struct dpif *dpif_)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dpif_xdp *dpif = dpif_xdp_cast(dpif_);

    seq_wait(dpif->dp->port_seq, dpif->last_port_seq);
}

static int
dpif_xf_flush(struct dpif *dpif)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct dp_xdp_entry_point *ep;

    CMAP_FOR_EACH (ep, node, &dp->entry_points) {
        dp_xdp_ep_flow_flush(ep);
    }

    return 0;

}

static struct dpif_flow_dump *
dpif_xf_dump_create(
        const struct dpif *dpif_,
        bool terse,
        struct dpif_flow_dump_types *types)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dpif_xf_dump *dump;

    dump = xzalloc(sizeof *dump);
    dpif_flow_dump_init(&dump->up, dpif_);
    dump->up.terse = terse;
    
    /* TODO: check if we need to initialise the bpf_map_pos in dump */
    
    /* TODO: if we need the dpif_flow_dump_types commented out in the
       dp_xf_dump then we will need to populate it or initialise it */
    
    ovs_mutex_init(&dump->mutex);

    return &dump->up;
}

static int
dpif_xf_dump_destroy(struct dpif_flow_dump *dump_)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dpif_xf_dump *dump = dpif_xf_dump_cast(dump_);

    ovs_mutex_destroy(&dump->mutex);
    free(dump);
    return 0;
}

static struct dpif_flow_dump_thread *
dpif_xf_dump_thread_create(
        struct dpif_flow_dump *dump_)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dpif_xf_dump *dump = dpif_xf_dump_cast(dump_);
    struct dpif_xf_dump_thread *thread;

    thread = xmalloc(sizeof *thread);
    dpif_flow_dump_thread_init(&thread->up, &dump->up);
    thread->dump = dump;

    return &thread->up;
}

static void
dpif_xf_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dpif_xf_dump_thread *thread
        = dpif_xf_dump_thread_cast(thread_);

    free(thread);
}

static int
dpif_xf_dump_next(struct dpif_flow_dump_thread *thread_,
                          struct dpif_flow *flows, int max_flows)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct dpif_xf_dump_thread *thread
        = dpif_xf_dump_thread_cast(thread_);
    struct dpif_xf_dump *dump = thread->dump;
    struct xf xfs[FLOW_DUMP_MAX_BATCH];
    struct dpif_xdp *dpif = dpif_xdp_cast(thread->up.dpif);
    struct dp_xdp *dp = get_dp_xdp(&dpif->dpif);
    int n_flows = 0;
    int flow_limit = MIN(max_flows, FLOW_DUMP_MAX_BATCH);
    int ep_ids[flow_limit];

    ovs_mutex_lock(&dump->mutex);
    if(!dump->status) {
        struct dp_xdp_entry_point *ep = dump->cur_ep;
        /* First call to dump_next(), extracts the first entry point.dp_xdp_get_ep
         * If there is no entry point, returns immediately. */
        if (!ep) {
            ep = dp_xdp_ep_get_next(dp, &dump->entry_point_pos);
            if (!ep) {
                ovs_mutex_unlock(&dump->mutex);
                return n_flows;

            }
        }
        /* TODO: recheck logic for the flow_table_cache if the flows 
           on these tables are different the will need to search through
           every endpoint hence our do while will need to change
           
           Secondly xfs[] will need to be a hash table storing or
           dumping the flows based on the hash key of the flow such that
           we won't have duplicates. */
        do {
            for (n_flows = 0; n_flows < flow_limit; n_flows++) {
                /* TODO: fetch flows from flow_table something like below */
                /* TODO: if duplicate keys are not resolved e.g concatenate the stats
                 * need to refactor the design. Where either a flow can only appear in
                 * one ep or when dumping we check the other ep for the same flow. E.g,
                 * ep(1) has key x check if x is in ep(2) ep(3) etc. And when on ep(3) 
                 * check if x in in ep(1) or an earlier ep(n). If already there means
                 * it has been dumped already go to the next */
                
                
                struct xf *xf = NULL;
                // int error = xswitch_ep_flow_next(ep->flow_map_fd, &dump->flow_pos, &xf);
                int error = xswitch_br__flow_next(dp->name, &dump->flow_pos, &xf);
                // If no flow found break
                if (error) {
                    break;
                }
                
                memcpy(&dump->flow_pos, &xf->key, sizeof(struct xf_key)); // update to next key
                memcpy(&xfs[n_flows], xf, sizeof(struct xf));
                ep_ids[n_flows] = ep->ep_id;
            }
            if (n_flows < flow_limit) {
                memset(&dump->flow_pos, 0, sizeof(struct xf_key));
                dp_xdp_ep_unref(ep);
                ep = dp_xdp_ep_get_next(dp, &dump->entry_point_pos);
                if (!ep) {
                    dump->status = EOF;
                    break;
                }
            }

            /* Keeps the reference to next caller. */
            dump->cur_ep = ep;
            /* If the current dump is empty, do not exit the loop, since the
             * remaining eps could have flows to be dumped.  Just dumps again
             * on the new 'ep'. */
        } while (!n_flows); 
    }
    ovs_mutex_unlock(&dump->mutex);

    for (size_t i = 0; i < n_flows; i++) {
        struct odputil_keybuf *maskbuf = &thread->maskbuf[i];
        struct odputil_keybuf *keybuf = &thread->keybuf[i];
        struct odputil_keybuf *actbuf = &thread->actbuf[i];
        struct xf *xf = &xfs[i];
        struct dpif_flow *f = &flows[i];
        struct ofpbuf key, mask, act;

        ofpbuf_use_stack(&key, keybuf, sizeof *keybuf);
        ofpbuf_use_stack(&mask, maskbuf, sizeof *maskbuf);
        ofpbuf_use_stack(&act, actbuf, sizeof *actbuf);
        dp_xf_to_dpif_flow__(dp, ep_ids[i], xf, &key, &mask, &act, f,
                                    dump->up.terse);
    }

    return n_flows;
}

static void
dpif_xdp_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops,
                    enum dpif_offload_type offload_type)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    size_t i;

    for (i = 0; i < n_ops; i++) {
        struct dpif_op *op = ops[i];

        switch (op->type) {
        case DPIF_OP_FLOW_PUT:
            op->error = dpif_xf_put(dpif, &op->flow_put);
            // VLOG_INFO("---- Ended: %s dpif_xf_put, error: %d  ----", __func__, op->error);
            break;

        case DPIF_OP_FLOW_DEL:
            op->error = dpif_xf_del(dpif, &op->flow_del);
            // VLOG_INFO("---- Ended: %s dpif_xf_del, error: %d  ----", __func__, op->error);
            break;

        case DPIF_OP_EXECUTE:
            op->error = dpif_xdp_execute(dpif, &op->execute);
            // VLOG_INFO("---- Ended: %s dpif_xdp_execute, error: %d  ----", __func__, op->error);
            break;

        case DPIF_OP_FLOW_GET:
            op->error = dpif_xf_get(dpif, &op->flow_get);
            // VLOG_INFO("---- Ended: %s dpif_xf_get, error: %d  ----", __func__, op->error);
            break;
        }
    }
}

static int
dpif_xdp_recv_set(struct dpif *dpif, bool enable)
{
    VLOG_INFO("---- Called: %s -- enable: %d ----", __func__, enable);
    struct dp_xdp *dp = get_dp_xdp(dpif);
    int error;

    fat_rwlock_wrlock(&dp->upcall_lock);
    if ((dp->handlers != NULL) == enable) {
        error = 0;
    } else if (!enable) {
        destroy_all_channels(dp);
        error = 0;
    } else {
        error = dp_xdp_refresh_channels(dp, 1);
    }
    fat_rwlock_unlock(&dp->upcall_lock);
    VLOG_INFO("---- Edded: %s, error %d ----", __func__, error);
    return error;    

}

static int
dpif_xdp_handlers_set(struct dpif *dpif, uint32_t n_handlers)
{
    VLOG_INFO("---- Called: %s n_handlers %d ----", __func__, n_handlers);
    struct dp_xdp *dp = get_dp_xdp(dpif);
    int error = 0;

    fat_rwlock_wrlock(&dp->upcall_lock);
    if (dp->handlers) {
        error = dp_xdp_refresh_channels(dp, n_handlers);
    }
    fat_rwlock_unlock(&dp->upcall_lock);
    return error;
}

static int
extract_key(struct dp_xdp *dp, const struct xf_key *key,
            struct dp_packet *packet, struct ofpbuf *buf)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    struct flow flow;
    struct odp_flow_key_parms parms = {
        .flow = &flow,
        .mask = NULL,
        .support = dp_xdp_support, /* used at odp_flow_key_from_flow */
    };


    /* This function goes first because it zeros out flow. */
    flow_extract(packet, &flow);

    // extract_metadata(key, &flow); // probably don't need this

    if (flow.in_port.odp_port == 0) {
        flow.in_port.odp_port = packet->md.in_port.odp_port;
    }

    odp_flow_key_from_flow(&parms, buf);

    return 0;
}

static void
dp_xf_hash(const void *key, size_t key_len, ovs_u128 *hash)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static uint32_t secret;

    if (ovsthread_once_start(&once)) {
        secret = random_uint32();
        ovsthread_once_done(&once);
    }
    hash_bytes128(key, key_len, secret, hash);
    uuid_set_bits_v4((struct uuid *)hash);
}

static int
xsk_socket_data_to_upcall__(struct dp_xdp *dp, struct ovs_xsk_event *e,
                        struct dpif_upcall *upcall, struct ofpbuf *buffer)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    size_t pkt_len = e->header.pkt_len;
    size_t pre_key_len;
    struct dp_xdp_port *port;
    int err = 0;

    // check if the packet is valid (by size)

    // get port_no from index
    /* TODO: have the db for the ports and datapath stored in a bpf map so that there
     * won't be a need for the conversion. The upcall will come with port_no, also any
     * search can be done by querying the map */
    ovs_mutex_lock(&dp->port_mutex);
    err = get_port_by_ifindex(dp, e->header.ifindex, &port);
    ovs_mutex_unlock(&dp->port_mutex);
    
    if (err) {
        goto out;
    }

    if (port->port_no == ODPP_NONE) {
        VLOG_WARN("failed to map upcall ifindex=%d to odp",
                     e->header.ifindex);
        return EINVAL;
    }

    memset(upcall, 0, sizeof *upcall);

    /* Use buffer->header to point to the packet, and buffer->msg to point to
     * the extracted flow key. Therefore, when extract_key() reallocates
     * 'buffer', we can easily get pointers back to the packet and start of
     * extracted key. */
    buffer->header = e->data; // packet
    buffer->msg = ofpbuf_tail(buffer); // now the end, will add the key here
    pre_key_len = buffer->size;

    
    dp_packet_use_stub(&upcall->packet, e->data, pkt_len);
    dp_packet_set_size(&upcall->packet, pkt_len);
    pkt_metadata_init(&upcall->packet.md, port->port_no);

    err = extract_key(dp, &e->header.key, &upcall->packet, buffer); // key will start being append from msg
    if (err) {
        VLOG_INFO("--- Called: %s error extracting key ----");
        goto out;
    }

    upcall->key = buffer->msg;
    upcall->key_len = buffer->size - pre_key_len;
    dp_xf_hash(upcall->key, upcall->key_len, &upcall->ufid);

    struct ds dsk = DS_EMPTY_INITIALIZER;
    xdp_flow_key_format(&dsk, &e->header.key);
    // VLOG_INFO("--- Called: %s recv from index: %d, flow key %s ----", __func__, e->header.ifindex, ds_cstr(&dsk));
    ds_destroy(&dsk);
out:
    return err;
}

/* xsk_socket_read fills the first part of 'buffer' with the ovs_xsk_event
 * which contains the upcall packet from the datapath and it's metadata.
 * This method will extract the key from the packet and add it to the buffer
 * the point the upcall->packet and upcall->key to the data in the buffer.
 */
static int
xsk_socket_data_to_upcall_miss(struct dp_xdp *dp, struct ovs_xsk_event *e,
                           struct dpif_upcall *upcall, struct ofpbuf *buffer)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    int err;

    err = xsk_socket_data_to_upcall__(dp, e, upcall, buffer);
    
    if (err) {
        return err;
    }

    upcall->type = DPIF_UC_MISS;

    return 0;
}

/* Modified from perf_sample_to_upcall.
 */
static int
xsk_socket_data_to_upcall_userspace(struct dp_xdp *dp, struct ovs_xsk_event *e,
                                struct dpif_upcall *upcall,
                                struct ofpbuf *buffer)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    int err;

    err = xsk_socket_data_to_upcall__(dp, e, upcall, buffer);
    if (err) {
        return err;
    }

    /* TODO: implement method */
   

    upcall->type = DPIF_UC_ACTION;
    return 0;
}

/* TODO: factor for xsk_ring_prod__needs_wakeup */
static int 
xsk_socket_read(struct xsk_socket_info *xsk, struct ofpbuf *buf, struct pollfd *fds, int n_socks)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    unsigned int rcvd, stock_frames, i;
    uint32_t idx_rx = 0, idx_fq = 0;
    int ret;
    int read;

    rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
    if (!rcvd) {
        if (xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
            ret = poll(fds, n_socks, 0);
        }
        return -1;
    }

    read = MIN(rcvd, UPCALL_MAX_READ);
    /* Stuff the ring with as much frames as possible */
    stock_frames = xsk_prod_nb_free(&xsk->umem->fq,
                    xsk_umem_free_frames(xsk));
    if (stock_frames > 0) {

        ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
                         &idx_fq);

        /* This should not happen, but just in case */
        while (ret != stock_frames)
            ret = xsk_ring_prod__reserve(&xsk->umem->fq, read,
                             &idx_fq);

        for (i = 0; i < stock_frames; i++)
            *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
                xsk_alloc_umem_frame(xsk);

        xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
    }

    /* Process received packets */
    for (i = 0; i < read; i++) {
        uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
        struct ovs_xsk_event *e = xsk_umem__get_data(xsk->umem->buffer, addr);
        // TODO: factor for batch processing
        int event_len = e->header.pkt_len + sizeof(struct xdp_upcall);
        ofpbuf_clear(buf); 
        ofpbuf_put(buf, e, event_len);
        buf->header = buf->data;
        xsk_free_umem_frame(xsk, addr);
        xsk->stats.rx_bytes += len;
    }
    xsk_ring_cons__release(&xsk->rx, read);
    xsk->stats.rx_packets += read;

    return read;
}

static int
recv_from_socket(struct dp_xdp *dp, struct ovs_xsk_event *e, struct dpif_upcall *upcall, 
        struct ofpbuf *buffer)
{
    // VLOG_INFO("---- Called: %s ----", __func__);
    // struct ovs_xsk_event *e = buffer->header;

    switch (e->header.type) {
    case OVS_PACKET_CMD_MISS:
        return xsk_socket_data_to_upcall_miss(dp, e, upcall, buffer);
        break;
    case OVS_PACKET_CMD_ACTION:
        return xsk_socket_data_to_upcall_userspace(dp, e, upcall, buffer);
        break;
    default:
        VLOG_INFO("---- default %s ----", __func__);
        break;
    }
    return EINVAL;
}

/* TODO: this seems with high frequency as compared to the dpif_netlink. Should probably investigate the
 * reasons since this most likley will affect performace. */

/* TODO: support receiving multiple packets at a time */
static int
dpif_xdp_recv(struct dpif *dpif, uint32_t handler_id,
                struct dpif_upcall *upcall, struct ofpbuf *buf)
{
    // VLOG_INFO("---- Called: %s -- handler_id: %d ----", __func__, handler_id);
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct dp_handler *handler;
    int error = EAGAIN;

    fat_rwlock_wrlock(&dp->upcall_lock);
    if (!dp->handlers || handler_id >= dp->n_handlers || dp->n_channels == 0) {
        error = EAGAIN;
        goto out;
    }
    handler = &dp->handlers[handler_id];
    
    if (!(handler->n_events > 0)) {
        int retval = 0;
        handler->n_events = 0;

        retval = poll(handler->fds, dp->n_channels, opt_timeout);
        if (retval < 0) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "poll failed (%s)", ovs_strerror(errno));
        } else if (retval > 0) {
            handler->n_events = retval;
        }
    }
    
    int idx = 0;
    while (handler->n_events > 0 && idx <= dp->n_channels) {
        if (handler->fds[idx].revents == POLLIN) {
            struct dp_channel *ch = &dp->channels[idx];
            /* NOTE: dpif_recv seems to support one packet at a time, so we should
             * ensure that we read a packet at a time. */
            int rcvd = xsk_socket_read(ch->sock, buf, handler->fds, dp->n_handlers);
            if (rcvd <= 0) {
                idx++;
                continue;
            }
            int ixd = 0;
            handler->n_events -= rcvd;
            ch->last_poll = time_msec();
        
            /* TODO: make sure recv_from_socket returns EAGAIN when nothing found */
            error = recv_from_socket(dp, buf->header, upcall, buf);
            if (error) {
                VLOG_INFO("---- Called: %s recv_from_socket error %d ----", __func__, error);
                goto out;
            } else {
                goto out;
            }
        } else if (handler->fds[idx].revents == POLLERR || // Cater for implicitly polled events
                    handler->fds[idx].revents == POLLHUP || 
                    handler->fds[idx].revents == POLLNVAL) { 
            
            // TODO: Approriately handle the events
            // remove the event
            handler->n_events -= handler->n_events > 0 ? 1 : 0;
        }
        idx++;
    }

out:
    // poll_immediate_wake();
    poll_timer_wait(opt_timeout);
    fat_rwlock_unlock(&dp->upcall_lock);
    return error;
}

static void                     
dpif_xdp_recv_wait(struct dpif *dpif, uint32_t handler_id)
{
    // VLOG_INFO("---- Called: %s -- handler_id: %d ----", __func__, handler_id);
    struct dp_xdp *dp = get_dp_xdp(dpif);
    // struct dp_xdp_port *port;
    // HMAP_FOR_EACH (port, node, &dp->ports) {
    // }

    fat_rwlock_rdlock(&dp->upcall_lock);
    if (dp->handlers && handler_id < dp->n_handlers) {
        struct dp_handler *handler = &dp->handlers[handler_id];

        poll(handler->fds, dp->n_channels, opt_timeout);
    }
    // if (dp->handlers && handler_id < dp->n_handlers) {
    //     struct dp_handler *handler = &dp->handlers[handler_id];

    //     poll_fd_wait(handler->epoll_fd, POLLIN);
    // }
    poll_timer_wait(opt_timeout);
    fat_rwlock_unlock(&dp->upcall_lock);
    // VLOG_INFO("---- Edded: %s handler_id: %d ----", __func__, handler_id);
}

static void
dpif_xdp_recv_purge(struct dpif *dpif)
{
    VLOG_INFO("---- Called: %s ----", __func__);
    struct dp_xdp *dp = get_dp_xdp(dpif);
    int i;

    fat_rwlock_rdlock(&dp->upcall_lock);
    for (i = 0; i < dp->n_channels; i++) {
        // struct afxdp_channel *channel = &dp->channels[i];

        /* TODO: flush channel */
    }
    fat_rwlock_unlock(&dp->upcall_lock);
}

static char *
dpif_xdp_get_datapath_version()
{
    VLOG_INFO("---- Called: %s ----", __func__);
    return xstrdup("<built-in>");
}
#pragma GCC diagnostic pop

const struct dpif_class dpif_xdp_class = {
    .type = "xdp",
    .cleanup_required = true,
    .init = dpif_xdp_init,
    .enumerate = dpif_xdp_enumerate,
    .port_open_type = dpif_xdp_port_open_type,
    .open = dpif_xdp_open,
    .close = dpif_xdp_close,
    .destroy = dpif_xdp_destroy,
    .run = dpif_xdp_run,
    .wait = NULL,
    .get_stats = dpif_xdp_get_stats,
    .set_features = NULL, // don't think we need this
    .port_add = dpif_xdp_port_add,
    .port_del = dpif_xdp_port_del,
    .port_set_config = NULL,
    .port_query_by_number = dpif_xdp_port_query_by_number,
    .port_query_by_name = dpif_xdp_port_query_by_name,
    .port_get_pid = dpif_xdp_port_get_pid,
    .port_dump_start = dpif_xdp_port_dump_start,
    .port_dump_next = dpif_xdp_port_dump_next,
    .port_dump_done = dpif_xdp_port_dump_done,
    .port_poll = dpif_xdp_port_poll,
    .port_poll_wait = dpif_xdp_port_poll_wait,
    .flow_flush = dpif_xf_flush,
    .flow_dump_create = dpif_xf_dump_create,
    .flow_dump_destroy = dpif_xf_dump_destroy,
    .flow_dump_thread_create = dpif_xf_dump_thread_create,
    .flow_dump_thread_destroy = dpif_xf_dump_thread_destroy,
    .flow_dump_next = dpif_xf_dump_next,
    .operate = dpif_xdp_operate,
    .recv_set = dpif_xdp_recv_set,
    .handlers_set = dpif_xdp_handlers_set,
    .set_config = NULL,
    .queue_to_priority = NULL,
    .recv = dpif_xdp_recv,
    .recv_wait = dpif_xdp_recv_wait,
    .recv_purge = dpif_xdp_recv_purge,
    .register_dp_purge_cb = NULL,
    .register_upcall_cb = NULL,
    .enable_upcall = NULL,
    .disable_upcall = NULL,
    .get_datapath_version = dpif_xdp_get_datapath_version,
    .ct_dump_start = NULL,
    .ct_dump_next = NULL,
    .ct_dump_done = NULL,
    .ct_flush = NULL,
    .ct_set_maxconns = NULL,
    .ct_get_maxconns = NULL,
    .ct_get_nconns = NULL,
    .ct_set_tcp_seq_chk = NULL,
    .ct_get_tcp_seq_chk = NULL,
    .ct_set_limits = NULL,
    .ct_get_limits = NULL,
    .ct_del_limits = NULL,
    .ct_set_timeout_policy = NULL,
    .ct_get_timeout_policy = NULL,
    .ct_del_timeout_policy = NULL,
    .ct_timeout_policy_dump_start = NULL,
    .ct_timeout_policy_dump_next = NULL,
    .ct_timeout_policy_dump_done = NULL,
    .ct_get_timeout_policy_name = NULL,
    .ipf_set_enabled = NULL,
    .ipf_set_min_frag = NULL,
    .ipf_set_max_nfrags = NULL,
    .ipf_get_status = NULL,
    .ipf_dump_start = NULL,
    .ipf_dump_next = NULL,
    .ipf_dump_done = NULL,
    .meter_get_features = NULL, // TODO: dpif_xdp_meter_get_features,
    .meter_set = NULL, // TODO: dpif_xdp_meter_set,
    .meter_get = NULL, // TODO: dpif_xdp_meter_get,
    .meter_del = NULL, // TODO: dpif_xdp_meter_del,
};

static bool
is_dp_xdp(struct dp_xdp *dp) {
    return dp->class == &dpif_xdp_class;
}