#include "dpif-xdp.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

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

/* ================================================================
    The xdp uses more or less the same datapath as netdev, only
    that it attaches a program on it. Hence the datapath shash  and
    other datapath attributes might be similar or the same and/or
    are handled in a similar way. Therefore this file 'might' 
    contain the same dp(s), this might need to be factored in and 
    will contribute to some code reuse or similar code.
   ================================================================ */

/* Protects against changes to 'dp_netdevs'. */
static struct ovs_mutex dp_xdp_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dp_netdev's. */
static struct shash dp_xdps OVS_GUARDED_BY(dp_netdev_mutex)
    = SHASH_INITIALIZER(&dp_xdps);

struct dp_xdp {
    const struct dpif_class *const class;
    const char *const name;
    struct ovs_refcount ref_cnt;
    atomic_flag destroyed;

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

}

/* TODO: check if there will be any difference in the dp_xdp_port
 * and the dp_netdev_port which is a port in a netdev-based datapath. 
 * if there is no difference should probably use the same. */
struct dp_xdp_port {
    odp_port_t port_no;
    bool dynamic_txqs;          /* If true XPS will be used. */
    bool need_reconfigure;      /* True if we should reconfigure netdev. */
    struct netdev *netdev;
    struct hmap_node node;      /* Node in dp_netdev's 'ports'. */
    struct netdev_saved_flags *sf;
    struct dp_netdev_rxq *rxqs;
    unsigned n_rxq;             /* Number of elements in 'rxqs' */
    unsigned *txq_used;         /* Number of threads that use each tx queue. */
    struct ovs_mutex txq_used_mutex;
    bool emc_enabled;           /* If true EMC will be used. */
    char *type;                 /* Port type as requested by user. */
    char *rxq_affinity_list;    /* Requested affinity of rx queues. */
    
    /* TODO: check if we need a lock for upcalls */
    /* The upcall id, using the id of the afxdp 
       this corresponds to one of the entry points.
       Possibly where each port is an entry point, this
       will have a 1-to-1 match with the dp_xdp_entry_point*/
    const uint32_t *upcall_pid;

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
    odp_port_t port_no; // to identify the network device
    struct ovs_refcount ref_cnt;    /* Every reference must be refcount'ed. */

    struct cmap_node node; // reference to the node in dp->entry_points

    // TODO: check the tyoe of mode, likely not char
    char *mode; /* Native, Generic, Offloaded */

    struct bpf_prog prog; /* The loaded xdp program */

    struct bpf_map devmap; /* map with destination interfaces for batch flushing */

    // struct ovs_mutex flow_mutex; /* TODO: check if mutex for flow_table_cache is needed and init it in relevant methods. */
    struct bpf_map flow_table; /* Flow table, shared map. TODO: if possible make it readonly reference */
    struct bpf_map flow_table_cache; /* Cache of flow table, for individual interface */
    struct bpf_map stats; /* Keeps track of the entry point's performance */

    const uint32_t *upcall_pid; /* The upcall id, using the id of the afxdp */
};

struct dp_xdp_port_state {
    struct hmap_position position;
    char *name;
};

struct dp_xdp_flow {
    /* TODO: define the flow attributes */
}

struct dpif_xdp_flow_dump {
    struct dpif_flow_dump up;
    struct cmap_position entry_point_pos;
    struct bpf_map_pos flow_pos; /* TODO: define the type for a bpf_map position when looping */
    struct dp_xdp_entry_point *cur_ep;
    int status;
    struct ovs_mutex mutex; /* TODO: *verify if needed */
    // struct dpif_flow_dump_types types; /* TODO: check if we need it */
}

/* TODO: need to define the relavant struct */
/* Must be public as it is instantiated in subtable struct below. */
struct xdp_flow_key {
    uint32_t hash;       /* Hash function differs for different users. */
    uint32_t len;        /* Length of the following miniflow (incl. map). */
    struct miniflow mf;
    uint64_t buf[FLOW_MAX_PACKET_U64S];
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
/** ====================== COMMON ========================================== 
 * The section contains the 'util' function that are common for dpif-netdev
 * and this file. Might/should consider reusing them from dpif-netdev in 
 * future
*/

// IMPORTANT: port type not common (dp_xdp_port vs dp_netdev_port)
static int
get_port_by_name(struct dp_xdp *dp,
                 const char *devname, struct dp_xdp_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_xdp_port *port; // IMPORTANT: port type not common

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!strcmp(netdev_get_name(port->netdev), devname)) {
            *portp = port;
            return 0;
        }
    }

    /* Callers of dpif_netdev_port_query_by_name() expect ENODEV for a non
     * existing port. */
    return ENODEV;
}

// IMPORTANT: port type not common (dp_xdp_port vs dp_netdev_port)
static void
answer_port_query(const struct dp_xdp_port *port,
                  struct dpif_port *dpif_port)
{
    dpif_port->name = xstrdup(netdev_get_name(port->netdev));
    dpif_port->type = xstrdup(port->type);
    dpif_port->port_no = port->port_no;
}

static struct dp_xdp_port *
dp_xdp_lookup_port(const struct dp_xdp *dp, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_xdp_port *port;

    HMAP_FOR_EACH_WITH_HASH (port, node, hash_port_no(port_no), &dp->ports) {
        if (port->port_no == port_no) {
            return port;
        }
    }
    return NULL;
}

// IMPORTANT: port type not common (dp_xdp_port vs dp_netdev_port)
static int
get_port_by_number(struct dp_xdp *dp,
                   odp_port_t port_no, struct dp_xdp_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    if (!is_valid_port_number(port_no)) {
        *portp = NULL;
        return EINVAL;
    } else {
        *portp = dp_xdp_lookup_port(dp, port_no);
        return *portp ? 0 : ENODEV;
    }
}

/** ====================== COMMON ========================================== */

/* Returns true if 'dpif' is a netdev or dummy dpif, false otherwise. */
static struct dpif_xdp *
dpif_xdp_cast(const struct dpif *dpif)
{
    dpif_assert_class(dpif, &dpif_xdp_class);
    return CONTAINER_OF(dpif, struct dpif_xdp, dpif);
}

static struct dp_xdp *
get_dp_xdp(const struct dpif *dpif)
{
    return dpif_xdp_cast(dpif)->dp;
}

static void
port_destroy(struct dp_xdp_port *port)
{
    /* TODO: Might remove some of the port attributes
        so will need to remove some of the code here */
    if (!port) {
        return;
    }

    netdev_close(port->netdev);
    netdev_restore_flags(port->sf);

    for (unsigned i = 0; i < port->n_rxq; i++) {
        netdev_rxq_close(port->rxqs[i].rx);
    }
    ovs_mutex_destroy(&port->txq_used_mutex);
    free(port->rxq_affinity_list);
    free(port->txq_used);
    free(port->rxqs);
    free(port->type);
    free(port);
}

static void
do_del_port(struct dp_xdp *dp, struct dp_xdp_port *port)
    OVS_REQUIRES(dp->port_mutex)
{
    hmap_remove(&dp->ports, &port->node);
    seq_change(dp->port_seq);

    // TODO: Remove the XDP program loaded on port

    port_destroy(port);
}

/* Requires dp_xdp_mutex so that we can't get a new reference to 'dp'
 * through the 'dp_xdps' shash while freeing 'dp'. */
static void
dp_xdp_free(struct dp_xdp *dp)
    OVS_REQUIRES(dp_xdp_mutex)
{
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

    /* TODO: Destroy the upcall queues if necessary or any */
    
    free(CONST_CAST(char *, dp->name));
    free(dp);
}

static void
dp_xdp_unref(struct dp_netdev *dp)
{
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
    uint16_t netflow_id = hash_string(dp->name, 0);
    struct dpif_xdp *dpif;

    ovs_refcount_ref(&dp->ref_cnt);

    dpif = xmalloc(sizeof *dpif);
    dpif_init(&dpif->dpif, dp->class, dp->name, netflow_id >> 8, netflow_id);
    dpif->dp = dp;
    dpif->last_port_seq = seq_read(dp->port_seq);

    return &dpif->dpif;
}

static int
create_dp_xdp(const char *name, const struct dpif_class *class,
                 struct dp_xdp **dpp)
    OVS_REQUIRES(dp_xdp_mutex)
{
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


    cmap_init(&dp->entry_points);

    /* TODO: Need to add a port (entry_point) to attach XDP prog on  
       or preferably use the default host to bridge port (not sure if
       it's attached by default) */

    /* TODO: Assign the on the entry point upcall_id, will need to 
       create the respective queue(s) */

    if (error) {
        dp_netdev_free(dp);
        return error;
    }

    *dpp = dp;
    return 0;
}

static int
dpif_xdp_flow_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              struct flow *flow, bool probe)
{
    /* TODO: implement method */

    return 0;
}

static int
dpif_xdp_mask_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              const struct nlattr *mask_key,
                              uint32_t mask_key_len, const struct flow *flow,
                              struct flow_wildcards *wc, bool probe)
{

    /* TODO: implement method */

    return 0;
}

static void
dp_xdp_ep_remove_flow(struct dp_xdp_entry_point *ep,
                      struct dp_xdp_flow *flow)
    // OVS_REQUIRES(ep->flow_mutex) /* TODO: check if needed. Comment in dp_xdp_entry_point too */
{
    /* TODO: remove flow from the ep->flow_table_cache bpf_map */
}

static void
dp_xdp_ep_flow_flush(struct dp_xdp_entry_point *ep)
{
    struct dp_xdp_flow *xdp_flow;

    // ovs_mutex_lock(&ep->flow_mutex); /* TODO: uncomment if needed */
    
    /* TODO: loop through the ep->flow_table_cache bpf_map passing each flow and ep to
       dp_xdp_ep_remove_flow(ep, xdp_flow) */

    // ovs_mutex_unlock(&ep->flow_mutex); /* TODO: uncomment if needed */
}

static struct dp_xdp_flow *
dp_xdp_ep_lookup_flow(struct dp_xdp_entry_point *ep,
                          const struct xdp_flow_key *key,
                          int *lookup_num_p)
{
    struct dp_xdp_flow *xdp_flow = NULL;

    /* TODO: implement method */
    return xdp_flow;
}

static struct dp_xdp_flow *
dp_xdp_ep_find_flow(const struct dp_xdp_entry_point *ep,
                        const ovs_u128 *ufidp, const struct nlattr *key,
                        size_t key_len)
{
    struct dp_xdp_flow *xdp_flow;
    struct flow flow;
    ovs_u128 ufid;

    /* TODO: verify that we are using the same type of key, else we
       have to change the hash function odp_flow_key_hash */
    
    /* TODO: check if ufid is set, if not set generate one using the
       a hash function on the flows and set the result to ufid */

    /* TODO: search for the flow in the ep's bpf_map and return xdp_flow
       if found. ELSE return NULL */

    return NULL;
}

static struct dpif_xdp_flow_dump *
dpif_xdp_flow_dump_cast(struct dpif_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpif_xdp_flow_dump, up);
}

static struct dpif_xdp_flow_dump_thread *
dpif_xdp_flow_dump_thread_cast(struct dpif_flow_dump_thread *thread)
{
    return CONTAINER_OF(thread, struct dpif_xdp_flow_dump_thread, up);
}

/* Configures the 'pmd' based on the input argument. */
static void
dp_xdp_configure_ep(struct dp_xdp_entry_point *ep, struct dp_xdp *dp,
                        odp_port_t port_no)
{
    /* TODO: implement method */

    // cmap_insert(&dp->entry_points, CONST_CAST(struct cmap_node *, &ep->node),
    //             hash_int(port_no, 0));

}

/* don't need to delete point since it the 
 * ep point might just being changed to an ordinary port.
 * If caller intends to delete the port as well then must
 * explictly call method to delete port. 
 * */
static void
dp_xdp_destroy_ep(struct dp_xdp_entry_point *ep)
{

    dp_xdp_ep_flow_flush(ep);

    /* TODO: delete devmap bpf_map */
    
    /* TODO: delete prog bpf_prog */

    /* TODO: delete flow_table_cache bpf_map */

    /* TODO: delete stats bpf_map */
          
    ovs_mutex_destroy(&ep->flow_mutex);
    
    free(ep);
}

/* Caller must have valid pointer to 'pmd'. */
static bool
dp_xdp_ep_try_ref(struct dp_xdp_entry_point *ep)
{
    return ovs_refcount_try_ref_rcu(&ep->ref_cnt);
}

static void
dp_xdp_ep_unref(struct dp_xdp_entry_point *ep)
{
    if (ep && ovs_refcount_unref(&ep->ref_cnt) == 1) {
        ovsrcu_postpone(dp_xdp_destroy_ep, ep);
    }
}

static void
dp_xdp_actions_free(struct dp_xdp_actions *actions)
{
    free(actions);
}

/* Creates and returns a new 'struct dp_xdp_actions', whose actions are
 * a copy of the 'size' bytes of 'actions' input parameters. */
struct dp_xdp_actions *
dp_xdp_actions_create(const struct nlattr *actions, size_t size)
{
    struct dp_xdp_actions *xdp_actions;

    // TODO: implement method relavant to our dp_xdp_actions

    xdp_actions = xmalloc(sizeof *xdp_actions + size);
    memcpy(xdp_actions->actions, actions, size);
    xdp_actions->size = size;

    return xdp_actions;
}

struct dp_xdp_actions *
dp_xdp_flow_get_actions(const struct dp_xdp_flow *flow)
{
    return ovsrcu_get(struct dp_xdp_actions *, &flow->actions);
}

/* Finds and refs the dp_netdev_pmd_thread on core 'core_id'.  Returns
 * the pointer if succeeds, otherwise, NULL (it can return NULL even if
 * 'core_id' is NON_PMD_CORE_ID).
 *
 * Caller must unrefs the returned reference.  */
static struct dp_xdp_entry_point *
dp_xdp_get_ep(struct dp_xdp *dp, odp_port_t port_no)
{
    struct dp_xdp_entry_point *ep;
    const struct cmap_node *pnode;

    pnode = cmap_find(&dp->entry_points, hash_int(port_no, 0));
    if (!pnode) {
        return NULL;
    }
    ep = CONTAINER_OF(pnode, struct dp_xdp_entry_point, node);

    return dp_xdp_ep_try_ref(ep) ? ep : NULL;
}

/* Given cmap position 'pos', tries to ref the next node.  If try_ref()
 * fails, keeps checking for next node until reaching the end of cmap.
 *
 * Caller must unrefs the returned reference. */
static struct dp_netdev_pmd_thread *
dp_xdp_ep_get_next(struct dp_netdev *dp, struct cmap_position *pos)
{
    struct dp_xdp_entry_point *next;

    do {
        struct cmap_node *node;

        node = cmap_next_position(&dp->entry_points, pos);
        next = node ? CONTAINER_OF(node, struct dp_xdp_entry_point, node)
            : NULL;
    } while (next && !dp_xdp_ep_try_ref(next));

    return next;
}

static void
dp_xdp_flow_to_dpif_flow(const struct dp_netdev *dp,
                            const struct dp_xdp_flow *xdp_flow,
                            struct ofpbuf *key_buf, struct ofpbuf *mask_buf,
                            struct dpif_flow *flow, bool terse)
{

    /* TODO: implement this method */

    /* TODO: make sure that the method checks if the flow is available
       already before adding it since our method may result in the same
       flow on different entry points. */
}

static void
dpif_xdp_flow_get_stats(const struct dp_xdp_flow *flow,
                            struct dpif_flow_stats *stats)
{
    /* TODO: implement method */
}

static int
flow_put_on_ep(struct dp_xdp_entry_point *ep,
                struct xdp_flow_key *key,
                struct match *match,
                ovs_u128 *ufid,
                const struct dpif_flow_put *put,
                struct dpif_flow_stats *stats)
{
    struct dp_xdp_flow *xdp_flow;
    int error = 0;

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }

    // ovs_mutex_lock(&ep->flow_mutex); // TODO: check if needed
    xdp_flow = dp_xdp_ep_lookup_flow(ep, key, NULL);
    if (!xdp_flow) {
        if (put->flags & DPIF_FP_CREATE) {
            /* TODO: count the flows in the bpf_map flow_table_cache
               then if less that MAX_FLOWS proceed to call method 
               dp_xdp_flow_add and set error to 0. ELSE set error to 
               EFBIG */
            // if (cmap_count(&ep->flow_table) < MAX_FLOWS) {
            //     dp_xdp_flow_add(pmd, match, ufid, put->actions,
            //                        put->actions_len);
            //     error = 0;
            // } else {
            //     error = EFBIG;
            // }
        } else {
            error = ENOENT;
        }
    } else {
        if (put->flags & DPIF_FP_MODIFY) {
            struct dp_xdp_actions *new_actions;
            struct dp_xdp_actions *old_actions;

            new_actions = dp_xdp_actions_create(put->actions,
                                                   put->actions_len);

            old_actions = dp_xdp_flow_get_actions(xdp_flow);
            ovsrcu_set(&xdp_flow->actions, new_actions);

            /* TODO: update the bpf_map flow action */

            if (stats) {
                dpif_xdp_flow_get_stats(xdp_flow, stats);
            }

            /* TODO: verify if this is the case as well for our implementation 
               or we can support write to stats */
            if (put->flags & DPIF_FP_ZERO_STATS) {
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
        } else {
            /* Overlapping flow. */
            error = EINVAL;
        }
    }
    // ovs_mutex_unlock(&pmd->flow_mutex); // TODO: check if needed
    return error;
}

static int
dpif_xdp_flow_put(struct dpif *dpif, const struct dpif_flow_put *put)
{
    struct dp_netdev *dp = get_dp_xdp(dpif);
    struct xdp_flow_key key, mask;
    struct dp_xdp_entry_point *ep;
    struct match match;
    ovs_u128 ufid;
    int error = 0;
    bool probe = put->flags & DPIF_FP_PROBE;

    if (put->stats) {
        memset(put->stats, 0, sizeof *put->stats);
    }
    /* TODO: implement method */
    error = dpif_xdp_flow_from_nlattrs(put->key, put->key_len, &match.flow,
                                        probe);

    if (error) {
        return error;
    }

    error = dpif_xdp_mask_from_nlattrs(put->key, put->key_len,
                                          put->mask, put->mask_len,
                                          &match.flow, &match.wc, probe);

    if (error) {
        return error;
    }

    if (put->ufid) {
        ufid = *put->ufid;
    } else {
        odp_flow_key_hash(&match.flow, sizeof match.flow, &ufid);
    }

    /* TODO: verify if this is needed too */
    /* The Netlink encoding of datapath flow keys cannot express
     * wildcarding the presence of a VLAN tag. Instead, a missing VLAN
     * tag is interpreted as exact match on the fact that there is no
     * VLAN.  Unless we refactor a lot of code that translates between
     * Netlink and struct flow representations, we have to do the same
     * here.  This must be in sync with 'match' in handle_packet_upcall(). */
    if (!match.wc.masks.vlans[0].tci) {
        match.wc.masks.vlans[0].tci = htons(0xffff);
    }

    /* TODO: Implement the logic below, it might be very similar to the netdev one
       probably depending on how different our flow key will be. */
    /* Must produce a netdev_flow_key for lookup.
     * Use the same method as employed to create the key when adding
     * the flow to the dplcs to make sure they match. */

    // we will treat the pmd id as the etry point id (port_no)
    if (put->pmd_id == PMD_ID_NULL) {
        /* TODO: need to revise this in case we change our logic. If we are 
           going to have a macro cache then for flows with ep specified we 
           should add then to that macro cache instead of putting it on every
           micro cache (ep) */
        
        if (cmap_count(&dp->entry_points) == 0) {
            return EINVAL;
        }
        CMAP_FOR_EACH (ep, node, &dp->entry_points) {
            struct dpif_flow_stats ep_stats;
            int ep_error;

            ep_error = flow_put_on_ep(ep, &key, &match, &ufid, put,
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
        error = flow_put_on_ep(ep, &key, &match, &ufid, put, put->stats);
        dp_xdp_ep_unref(ep);
    }
    return error;
}

static int
flow_del_on_ep(struct dp_xdp_entry_point *ep,
                struct dpif_flow_stats *stats,
                const struct dpif_flow_del *del)
{
    struct dp_xdp_flow *xdp_flow;
    int error = 0;

    // ovs_mutex_lock(&ep->flow_mutex); // TODO: check if needed
    xdp_flow = dp_xdp_ep_find_flow(ep, del->ufid, del->key,
                                          del->key_len);
    if (xdp_flow) {
        if (stats) {
            dpif_xdp_flow_get_stats(xdp_flow, stats);
        }
        dp_xdp_ep_remove_flow(ep, xdp_flow);
    } else {
        error = ENOENT;
    }
    // ovs_mutex_unlock(&pmd->flow_mutex); // TODO: check if needed

    return error;
}

static int
dpif_xdp_flow_del(struct dpif *dpif, const struct dpif_flow_put *del)
{
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct dp_xdp_entry_point *ep;
    int error = 0;

    if (del->stats) {
        memset(del->stats, 0, sizeof *del->stats);
    }

    if (del->pmd_id == PMD_ID_NULL) {
        if (cmap_count(&dp->entry_points) == 0) {
            return EINVAL;
        }
        CMAP_FOR_EACH (ep, node, &dp->entry_points) {
            struct dpif_flow_stats ep_stats;
            int ep_error;

            ep_error = flow_del_on_ep(ep, &ep_stats, del);
            if (ep_error) {
                error = ep_error;
            } else if (del->stats) {
                del->stats->n_packets += ep_stats.n_packets;
                del->stats->n_bytes += ep_stats.n_bytes;
                del->stats->used = MAX(del->stats->used, ep_stats.used);
                del->stats->tcp_flags |= ep_stats.tcp_flags;
            }
        }
    } else {
        ep = dp_xdp_get_ep(dp, del->pmd_id);
        if (!ep) {
            return EINVAL;
        }
        error = flow_del_on_ep(ep, del->stats, del);
        dp_xdp_ep_unref(ep);
    }
    /* TODO: implement method */

    return error;
}

static int
dpif_xdp_execute(struct dpif *dpif, struct dpif_execute *execute)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev *dp = get_dp_xdp(dpif);
    struct dp_xdp_entry_point *ep;
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


    /* TODO: implement method */

    return error;
}

static int
dpif_xdp_flow_get(const struct dpif *dpif, const struct dpif_flow_get *get)
{
    struct dp_netdev *dp = get_dp_xdp(dpif);
    struct dp_xdp_flow *xdp_flow;
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
        ep = dp_xdp_ep_pmd(dp, get->pmd_id);
        if (!ep) {
            goto out;
        }
        hmapx_add(&to_find, ep);
    }

    if (!hmapx_count(&to_find)) {
        goto out;
    }

    HMAPX_FOR_EACH (node, &to_find) {
        ep = (struct dp_xdp_entry_point *) node->data;
        xdp_flow = dp_xdp_ep_find_flow(ep, get->ufid, get->key,
                                              get->key_len);
        if (xdp_flow) {
            dp_xdp_flow_to_dpif_flow(dp, xdp_flow, get->buffer,
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
    return strcmp(type, "internal") ? type : "tap";
}

static int
dpif_xdp_open(const struct dpif_class *dpif_class,
                const char *name, bool create, struct dpif **dpifp)
{
    struct dp_xdp *dp;
    int error;

    error = dpif_xdp_init();
    if (error) {
        return error;
    }

    ovs_mutex_lock(&dp_xdp_mutex);
    dp = shash_find_data(&dp_netdevs, name);
    if (!dp) {
        error = create ? create_dp_xdp(name, dpif_class, &dp) : ENODEV;
    } else {
        error = (dp->class != dpif_class ? EINVAL
                 : create ? EEXIST
                 : 0);
    }
    if (!error) {
        *dpifp = create_dpif_xdp(dp);
    }
    ovs_mutex_unlock(&dp_xdp_mutex);

    return error;

}

static void
dpif_xdp_close(struct dpif *dpif)
{
    struct dp_xdp *dp = get_dp_xdp(dpif);

    dp_xdp_unref(dp);
    free(dpif);
}

static int
dpif_xdp_destroy(struct dpif *dpif)
{
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
                    odp_port_t *port_no)
{
    struct dp_xdp *dp = get_dp_xdp(dpif);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dpif_port;
    odp_port_t port_no;
    int error;

    // TODO: Check where to assign the Netlink PID

    ovs_mutex_lock(&dp->port_mutex);
    dpif_port = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);
    if (*port_nop != ODPP_NONE) {
        port_no = *port_nop;
        error = dp_xdp_lookup_port(dp, *port_nop) ? EBUSY : 0;
    } else {
        port_no = choose_port(dp);
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
    return error;
}

int (*dpif_xdp_port_del)(struct dpif *dpif, odp_port_t port_no)
{

}

static int
dpif_xdp_port_query_by_number(const struct dpif *dpif, odp_port_t port_no,
                                struct dpif_port *port)
{
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct dp_xdp_port *port;
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    error = get_port_by_number(dp, port_no, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

static int
dpif_xdp_port_query_by_name(const struct dpif *dpif, const char *devname,
                              struct dpif_port *port)
{
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
    uint32_t ret;

    /* TODO: check if lock is needed for afxdp upcalls (also see dpif_xdp) */
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct dp_xdp_port *port;

    CMAP_FOR_EACH (port, node, &dp->ports) {
        if(port->port_no == port_no) {
            ret = port->upcall_pid;
            break;
        }
    }

    return ret;
}

static int
dpif_xdp_port_dump_start(const struct dpif *dpif, void **statep)
{
    *statep = xzalloc(sizeof(struct dpif_xdp_port_state));
    return 0;
}

static int
dpif_xdp_port_dump_next(const struct dpif *dpif, void *state_,
                          struct dpif_port *port)
{
    struct dpif_xdp_port_state *state = state_;
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct hmap_node *node;
    int retval;

    ovs_mutex_lock(&dp->port_mutex);
    node = hmap_at_position(&dp->ports, &state->position);
    if (node) {
        struct dp_xdp_port *port;

        port = CONTAINER_OF(node, struct dp_xdp_port, node);

        free(state->name);
        state->name = xstrdup(netdev_get_name(port->netdev));
        dpif_port->name = state->name;
        dpif_port->type = port->type;
        dpif_port->port_no = port->port_no;

        retval = 0;
    } else {
        retval = EOF;
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return retval;
}

static int
dpif_xdp_port_dump_done(const struct dpif *dpif, void *state_)
{
    struct dp_xdp_port_state *state = state_;
    free(state->name);
    free(state);
    return 0;
}

static int
dpif_xdp_port_poll(const struct dpif *dpif_, char **devnamep)
{
    struct dpif_xdp *dpif = dpif_netdev_cast(dpif_);
    uint64_t new_port_seq;
    int error;

    new_port_seq = seq_read(dpif->dp->port_seq);
    if (dpif->last_port_seq != new_port_seq) {
        dpif->last_port_seq = new_port_seq;
        error = ENOBUFS;
    } else {
        error = EAGAIN;
    }

    return error;
}

static void
dpif_xdp_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_xdp *dpif = dpif_xdp_cast(dpif_);

    seq_wait(dpif->dp->port_seq, dpif->last_port_seq);
}

static int
dpif_xdp_flow_flush(struct dpif *dpif)
{
    struct dp_xdp *dp = get_dp_xdp(dpif);
    struct dp_xdp_entry_point *ep;

    CMAP_FOR_EACH (ep, node, &dp->entry_points) {
        dp_xdp_ep_flow_flush(ep);
    }

    return 0;

}

static struct dpif_flow_dump *
dpif_xdp_flow_dump_create(
        const struct dpif *dpif_,
        bool terse,
        struct dpif_flow_dump_types *types)
{
    struct dpif_xdp_flow_dump *dump;

    dump = xzalloc(sizeof *dump);
    dpif_flow_dump_init(&dump->up, dpif_);
    dump->up.terse = terse;
    
    /* TODO: check if we need to initialise the bpf_map_pos in dump */
    
    /* TODO: if we need the dpif_flow_dump_types commented out in the
       dp_xdp_flow_dump then we will need to populate it or initialise it */
    
    ovs_mutex_init(&dump->mutex);

    return &dump->up;
}

static int
dpif_xdp_flow_dump_destroy(struct dpif_flow_dump *dump_)
{
    struct dpif_xdp_flow_dump *dump = dpif_xdp_flow_dump_cast(dump_);

    ovs_mutex_destroy(&dump->mutex);
    free(dump);
    return 0;
}

struct dpif_netdev_flow_dump_thread {
    struct dpif_flow_dump_thread up;
    struct dpif_xdp_flow_dump *dump;

    /* TODO: confirm if this is all we need */

    /* (Key/Mask/Actions) Buffers for netdev dumping */
    struct odputil_keybuf keybuf[FLOW_DUMP_MAX_BATCH];
    struct odputil_keybuf maskbuf[FLOW_DUMP_MAX_BATCH];
    struct odputil_keybuf actbuf[FLOW_DUMP_MAX_BATCH];
};

static struct dpif_flow_dump_thread *
dpif_xdp_flow_dump_thread_create(
        struct dpif_flow_dump *dump_)
{
    struct dpif_xdp_flow_dump *dump = dpif_xdp_flow_dump_cast(dump_);
    struct dpif_xdp_flow_dump_thread *thread;

    thread = xmalloc(sizeof *thread);
    dpif_flow_dump_thread_init(&thread->up, &dump->up);
    thread->dump = dump;
    return &thread->up;
}

static void
dpif_xdp_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    struct dpif_xdp_flow_dump_thread *thread
        = dpif_xdp_flow_dump_thread_cast(thread_);

    free(thread);
}

static int
dpif_xdp_flow_dump_next(struct dpif_flow_dump_thread *thread,
                          struct dpif_flow *flows, int max_flows)
{
    struct dpif_xdp_flow_dump_thread *thread
        = dpif_xdp_flow_dump_thread_cast(thread_);
    struct dpif_xdp_flow_dump *dump = thread->dump;
    struct dp_xdp_flow *xdp_flows[FLOW_DUMP_MAX_BATCH];
    struct dpif_xdp *dpif = dpif_xdp_cast(thread->up.dpif);
    struct dp_xdp *dp = get_dp_xdp(&dpif->dpif);
    int n_flows = 0;
    int i;

    ovs_mutex_lock(&dump->mutex);
    if(!dump->status) {
        struct dp_xdp_entry_point *ep = dump->cur_ep;
        int flow_limit = MIN(max_flows, FLOW_DUMP_MAX_BATCH);

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
           
           Secondly xdp_flows[] will need to be a hash table storing or
           dumping the flows based on the hash key of the flow such that
           we won't have duplicates. */
        do {
            for (n_flows = 0; n_flows < flow_limit; n_flows++) {
                /* TODO: fetch flows from flow_table_cache something like below */

                // xdp_flows[n_flows] = flow_from_map
            }

            if (n_flows < flow_limit) {
                memset(&dump->flow_pos, 0, sizeof dump->flow_pos);
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

    for (i = 0; i < n_flows; i++) {
        struct odputil_keybuf *maskbuf = &thread->maskbuf[i];
        struct odputil_keybuf *keybuf = &thread->keybuf[i];
        struct dp_xdp_flow *xdp_flow = xdp_flows[i];
        struct dpif_flow *f = &flows[i];
        struct ofpbuf key, mask;

        ofpbuf_use_stack(&key, keybuf, sizeof *keybuf);
        ofpbuf_use_stack(&mask, maskbuf, sizeof *maskbuf);
        dp_xdp_flow_to_dpif_flow(dp, xdp_flow, &key, &mask, f,
                                    dump->up.terse);
    }

    return n_flows;
}

static void
dpif_xdp_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops,
                    enum dpif_offload_type offload_type)
{
    size_t i;

    for (i = 0; i < n_ops; i++) {
        struct dpif_op *op = ops[i];

        switch (op->type) {
        case DPIF_OP_FLOW_PUT:
            op->error = dpif_xdp_flow_put(dpif, &op->flow_put);
            break;

        case DPIF_OP_FLOW_DEL:
            op->error = dpif_xdp_flow_del(dpif, &op->flow_del);
            break;

        case DPIF_OP_EXECUTE:
            op->error = dpif_xdp_execute(dpif, &op->execute);
            break;

        case DPIF_OP_FLOW_GET:
            op->error = dpif_xdp_flow_get(dpif, &op->flow_get);
            break;
        }
    }
}

int (*dpif_xdp_recv_set)(struct dpif *dpif, bool enable)
{

}

int (*dpif_xdp_handlers_set)(struct dpif *dpif, uint32_t n_handlers)
{

}

int (*dpif_xdp_set_config)(struct dpif *dpif, const struct smap *other_config)
{

}

int (*dpif_xdp_queue_to_priority)(const struct dpif *dpif, uint32_t queue_id,
                             uint32_t *priority)
{

}

int (*dpif_xdp_recv)(struct dpif *dpif, uint32_t handler_id,
                struct dpif_upcall *upcall, struct ofpbuf *buf)
{

}
                     
void (*dpif_xdp_recv_wait)(struct dpif *dpif, uint32_t handler_id)
{

}

void (*dpif_xdp_recv_purge)(struct dpif *dpif)
{

}

char *(*dpif_xdp_get_datapath_version)(void)
{

}

int (*dpif_xdp_ct_dump_start)(struct dpif *, struct ct_dpif_dump_state **state,
                         const uint16_t *zone, int *)
{

}

int (*dpif_xdp_ct_dump_next)(struct dpif *, struct ct_dpif_dump_state *state,
                        struct ct_dpif_entry *entry)
{

}

int (*dpif_xdp_ct_dump_done)(struct dpif *, struct ct_dpif_dump_state *state)
{

}

int (*dpif_xdp_ct_flush)(struct dpif *, const uint16_t *zone,
                    const struct ct_dpif_tuple *tuple)
{

}

int (*dpif_xdp_ct_set_maxconns)(struct dpif *, uint32_t maxconns)
{

}

int (*dpif_xdp_ct_get_maxconns)(struct dpif *, uint32_t *maxconns)
{

}

int (*dpif_xdp_ct_get_nconns)(struct dpif *, uint32_t *nconns)
{

}

int (*dpif_xdp_ct_set_tcp_seq_chk)(struct dpif *, bool enabled)
{

}

int (*dpif_xdp_ct_get_tcp_seq_chk)(struct dpif *, bool *enabled)
{

}

int (*dpif_xdp_ct_set_limits)(struct dpif *, const uint32_t *default_limit,
                         const struct ovs_list *zone_limits)
{

}

int (*dpif_xdp_ct_get_limits)(struct dpif *, uint32_t *default_limit,
                         const struct ovs_list *zone_limits_in,
                         struct ovs_list *zone_limits_out)
{

}

int (*dpif_xdp_ct_del_limits)(struct dpif *, const struct ovs_list *zone_limits)
{

}

int (*dpif_xdp_ct_set_timeout_policy)(struct dpif *,
                                 const struct ct_dpif_timeout_policy *tp)
{

}

int (*dpif_xdp_ct_get_timeout_policy)(struct dpif *, uint32_t tp_id,
                                struct ct_dpif_timeout_policy *tp)
{

}

int (*dpif_xdp_ct_del_timeout_policy)(struct dpif *, uint32_t tp_id)
{

}

int (*dpif_xdp_ct_timeout_policy_dump_start)(struct dpif *, void **statep)
{

}

int (*dpif_xdp_ct_timeout_policy_dump_next)(struct dpif *, void *state,
                                    struct ct_dpif_timeout_policy *tp)
{

}

int (*dpif_xdp_ct_timeout_policy_dump_done)(struct dpif *, void *state)
{

}

int (*dpif_xdp_ct_get_timeout_policy_name)(struct dpif *, uint32_t tp_id,
                                      uint16_t dl_type, uint8_t nw_proto,
                                      char **tp_name, bool *is_generic)
{

}

int (*dpif_xdp_ipf_set_enabled)(struct dpif *, bool v6, bool enabled)
{

}


int (*dpif_xdp_ipf_set_min_frag)(struct dpif *, bool v6, uint32_t min_frag)
{

}


int (*dpif_xdp_ipf_set_max_nfrags)(struct dpif *, uint32_t max_nfrags)
{

}


int (*dpif_xdp_ipf_get_status)(struct dpif *,
                        struct dpif_ipf_status *dpif_ipf_status)
{

}

int (*dpif_xdp_ipf_dump_start)(struct dpif *, struct ipf_dump_ctx **ipf_dump_ctx)
{

}

int (*dpif_xdp_ipf_dump_next)(struct dpif *, void *ipf_dump_ctx, char **dump)
{

}

int (*dpif_xdp_ipf_dump_done)(struct dpif *, void *ipf_dump_ctx)
{

}

void (*dpif_xdp_meter_get_features)(const struct dpif *,
                               struct ofputil_meter_features *)
{

}

int (*dpif_xdp_meter_set)(struct dpif *, ofproto_meter_id meter_id,
                     struct ofputil_meter_config *)
{

}

int (*dpif_xdp_meter_get)(const struct dpif *, ofproto_meter_id meter_id,
                     struct ofputil_meter_stats *, uint16_t n_bands)
{

}

int (*dpif_xdp_meter_del)(struct dpif *, ofproto_meter_id meter_id,
                     struct ofputil_meter_stats *, uint16_t n_bands)
{

}



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
    .port_set_config = dpif_xdp_port_set_config,
    .port_query_by_number = dpif_xdp_port_query_by_number,
    .port_query_by_name = dpif_xdp_port_query_by_name,
    .port_get_pid = dpif_xdp_port_get_pid,
    .port_dump_start = dpif_xdp_port_dump_start,
    .port_dump_next = dpif_xdp_port_dump_next,
    .port_dump_done = dpif_xdp_port_dump_done,
    .port_poll = dpif_xdp_port_poll,
    .port_poll_wait = dpif_xdp_port_poll_wait,
    .flow_flush = dpif_xdp_flow_flush,
    .flow_dump_create = dpif_xdp_flow_dump_create,
    .flow_dump_destroy = dpif_xdp_flow_dump_destroy,
    .flow_dump_thread_create = dpif_xdp_flow_dump_thread_create,
    .flow_dump_thread_destroy = dpif_xdp_flow_dump_thread_destroy,
    .flow_dump_next = dpif_xdp_flow_dump_next,
    .operate = dpif_xdp_operate,
    .recv_set = dpif_xdp_recv_set,
    .handlers_set = dpif_xdp_handlers_set,
    .set_config = NULL,
    .queue_to_priority = dpif_xdp_queue_to_priority,
    .recv = dpif_xdp_recv,
    .recv_wait = dpif_xdp_recv_wait,
    .recv_purge = dpif_xdp_recv_purge,
    .register_dp_purge_cb = NULL,
    .register_upcall_cb = NULL,
    .enable_upcall = NULL,
    .disable_upcall = NULL,
    .get_datapath_version = dpif_xdp_get_datapath_version,
    .ct_dump_start = dpif_xdp_ct_dump_start,
    .ct_dump_next = dpif_xdp_ct_dump_next,
    .ct_dump_done = dpif_xdp_ct_dump_done,
    .ct_flush = dpif_xdp_ct_flush,
    .ct_set_maxconns = NULL,
    .ct_get_maxconns = NULL,
    .ct_get_nconns = NULL,
    .ct_set_tcp_seq_chk = NULL,
    .ct_get_tcp_seq_chk = NULL,
    .ct_set_limits = dpif_xdp_ct_set_limits,
    .ct_get_limits = dpif_xdp_ct_get_limits,
    .ct_del_limits = dpif_xdp_ct_del_limits,
    .ct_set_timeout_policy = dpif_xdp_ct_set_timeout_policy,
    .ct_get_timeout_policy = dpif_xdp_ct_get_timeout_policy,
    .ct_del_timeout_policy = dpif_xdp_ct_del_timeout_policy,
    .ct_timeout_policy_dump_start = dpif_xdp_ct_timeout_policy_dump_start,
    .ct_timeout_policy_dump_next = dpif_xdp_ct_timeout_policy_dump_next,
    .ct_timeout_policy_dump_done = dpif_xdp_ct_timeout_policy_dump_done,
    .ct_get_timeout_policy_name = dpif_xdp_ct_get_timeout_policy_name,
    .ipf_set_enabled = dpif_xdp_ipf_set_enabled,
    .ipf_set_min_frag = dpif_xdp_ipf_set_min_frag,
    .ipf_set_max_nfrags = dpif_xdp_ipf_set_max_nfrags,
    .ipf_get_status = dpif_xdp_ipf_get_status,
    .ipf_dump_start = dpif_xdp_ipf_dump_start,
    .ipf_dump_next = dpif_xdp_ipf_dump_next,
    .ipf_dump_done = dpif_xdp_ipf_dump_done,
    .meter_get_features = NULL, // TODO: dpif_xdp_meter_get_features,
    .meter_set = NULL, // TODO: dpif_xdp_meter_set,
    .meter_get = NULL, // TODO: dpif_xdp_meter_get,
    .meter_del = NULL, // TODO: dpif_xdp_meter_del,
};