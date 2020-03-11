
/*
 * Copyright (c) 2018, 2019 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "netdev-linux-private.h"
#include "netdev-linux.h"
#include "netdev-xdp.h"
#include "netdev-afxdp.h"

#include <errno.h>
#include <inttypes.h>
#include <linux/rtnetlink.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <numa.h>
#include <numaif.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "coverage.h"
#include "dp-packet.h"
#include "dpif-netdev.h"
#include "fatal-signal.h"
#include "openvswitch/compiler.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/thread.h"
#include "openvswitch/vlog.h"
#include "ovs-numa.h"
#include "packets.h"
#include "socket-util.h"
#include "util.h"

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
    struct netdev_linux *dev = netdev_linux_cast(netdev_);
    int ret;

    /* Configure common netdev-linux first. */
    ret = netdev_linux_construct(netdev_);
    if (ret) {
        return ret;
    }

    return 0;
}

void netdev_xdp_destruct(struct netdev *netdev_)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev_);
    int ret;

    /* Configure common netdev-linux first. */
    ret = netdev_linux_destruct(netdev_);
    if (ret) {
        return ret;
    }

    return 0;
}

int netdev_xdp_verify_mtu_size(const struct netdev *netdev, int mtu)
{
    /*
     * If a device is used in xdpmode skb, no driver-specific MTU size is
     * checked and any value is allowed resulting in packet drops.
     * This check will verify the maximum supported value based on the
     * buffer size allocated and the additional headroom required.
     */
    if (mtu > (FRAME_SIZE - OVS_XDP_HEADROOM -
               XDP_PACKET_HEADROOM - VLAN_ETH_HEADER_LEN)) {
        return EINVAL;
    }
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