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
};

/* Interface to xdp-based datapath. */
struct dpif_xdp {
    struct dpif dpif;
    struct dp_xdp *dp;
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
    int ifindex; // to identify the network device

    // TODO: check the tyoe of mode, likely not char
    char *mode; /* Native, Generic, Offloaded */

    struct bpf_prog prog; /* The loaded xdp program */

    struct bpf_map devmap; /* map with destination interfaces for batch flushing */
    struct bpf_map flow_table; /* Flow table, shared map */
    struct bpf_map flow_table_cache; /* Cache of flow table, for individual interface */
    struct bpf_map stats; /* Keeps track of the entry point's performance */

    const uint32_t *upcall_pid; /* The upcall id, using the id of the afxdp */
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

    dp_netdev_destroy_all_pmds(dp, true);
    cmap_destroy(&dp->poll_threads);

    ovs_mutex_destroy(&dp->tx_qid_pool_mutex);
    id_pool_destroy(dp->tx_qid_pool);

    ovs_mutex_destroy(&dp->non_pmd_mutex);
    ovsthread_key_delete(dp->per_pmd_key);

    conntrack_destroy(dp->conntrack);


    seq_destroy(dp->reconfigure_seq);

    seq_destroy(dp->port_seq);
    hmap_destroy(&dp->ports);
    ovs_mutex_destroy(&dp->port_mutex);

    /* Upcalls must be disabled at this point */
    dp_netdev_destroy_upcall_lock(dp);

    int i;

    for (i = 0; i < MAX_METERS; ++i) {
        meter_lock(dp, i);
        dp_delete_meter(dp, i);
        meter_unlock(dp, i);
    }
    for (i = 0; i < N_METER_LOCKS; ++i) {
        ovs_mutex_destroy(&dp->meter_locks[i]);
    }

    free(dp->pmd_cmask);
    free(CONST_CAST(char *, dp->name));
    free(dp);
}

static void
dp_xdp_unref(struct dp_netdev *dp)
{
    if (dp) {
        /* Take dp_netdev_mutex so that, if dp->ref_cnt falls to zero, we can't
         * get a new reference to 'dp' through the 'dp_netdevs' shash. */
        ovs_mutex_lock(&dp_xdp_mutex);
        if (ovs_refcount_unref_relaxed(&dp->ref_cnt) == 1) {
            dp_xdp_free(dp);
        }
        ovs_mutex_unlock(&dp_xdp_mutex);
    }
}

/* Provider functions */
static int
dpif_xdp_init()
{
    static int error = 0; // retains it's previous value in future calls

    // We want to set up for downcall from OVS
    
    // And possibly for upcalls too
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

const char *(*dpif_xdp_port_open_type)(const struct dpif_class *dpif_class,
                                  const char *type)
{

}

int (*dpif_xdp_open)(const struct dpif_class *dpif_class,
                const char *name, bool create, struct dpif **dpifp)
{

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
    struct dp_nxdp *dp = get_dp_xdp(dpif);

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
 * Therefore this function returns the same PID from AF_XDP
 * ================================================================================
*/
uint32_t *dpif_xdp_port_get_pid(const struct dpif *dpif, odp_port_t port_no)
{

}

int (*dpif_xdp_port_dump_start)(const struct dpif *dpif, void **statep)
{

}

int (*dpif_xdp_port_dump_next)(const struct dpif *dpif, void *state,
                          struct dpif_port *port)
{

}

int (*dpif_xdp_port_dump_done)(const struct dpif *dpif, void *state)
{

}

int (*dpif_xdp_port_poll)(const struct dpif *dpif, char **devnamep)
{

}

void (*dpif_xdp_port_poll_wait)(const struct dpif *dpif)
{

}

int (*dpif_xdp_flow_flush)(struct dpif *dpif)
{

}

struct dpif_flow_dump *(*dpif_xdp_flow_dump_create)(
        const struct dpif *dpif,
        bool terse,
        struct dpif_flow_dump_types *types)
{

}

int (*dpif_xdp_flow_dump_destroy)(struct dpif_flow_dump *dump)
{

}
     
struct dpif_flow_dump_thread *(*dpif_xdp_flow_dump_thread_create)(
        struct dpif_flow_dump *dump)
{

}

void (*dpif_xdp_flow_dump_thread_destroy)(struct dpif_flow_dump_thread *thread)
{

}


int (*dpif_xdp_flow_dump_next)(struct dpif_flow_dump_thread *thread,
                          struct dpif_flow *flows, int max_flows)
{

}

void (*dpif_xdp_operate)(struct dpif *dpif, struct dpif_op **ops, size_t n_ops,
                    enum dpif_offload_type offload_type)
{

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