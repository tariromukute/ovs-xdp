
#include "netdev-xdp.h"

int netdev_xdp_rxq_construct(struct netdev_rxq *rxq_)
{
    return 0;
}

void netdev_xdp_rxq_destruct(struct netdev_rxq *rxq_)
{
}

int netdev_xdp_init(void)
{
    return 0;
}

int netdev_xdp_construct(struct netdev *netdev_)
{
    return 0;
}

void netdev_xdp_destruct(struct netdev *netdev_)
{
}

int netdev_xdp_verify_mtu_size(const struct netdev *netdev, int mtu)
{
    return 0;
}

int netdev_xdp_rxq_recv(struct netdev_rxq *rxq_,
                        struct dp_packet_batch *batch,
                        int *qfill)
{
    return 0;
}

int netdev_xdp_batch_send(struct netdev *netdev_, int qid,
                          struct dp_packet_batch *batch,
                          bool concurrent_txq)
{
    return 0;
}

int netdev_xdp_set_config(struct netdev *netdev, const struct smap *args,
                          char **errp)
{
    return 0;
}

int netdev_xdp_get_config(const struct netdev *netdev, struct smap *args)
{
    return 0;
}

int netdev_xdp_get_stats(const struct netdev *netdev_,
                         struct netdev_stats *stats)
{
    return 0;
}

int netdev_xdp_get_custom_stats(const struct netdev *netdev,
                                struct netdev_custom_stats *custom_stats)
{
    return 0;
}

// might not be needed
void free_xdp_buf(struct dp_packet *p)
{
}

int netdev_xdp_reconfigure(struct netdev *netdev)
{
    return 0;
}
// might not be needed
void signal_remove_xdp(struct netdev *netdev)
{
    return 0;
}