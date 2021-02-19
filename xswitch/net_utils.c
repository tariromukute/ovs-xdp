#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <errno.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>

#include "xf_netdev.h"
#include "logging.h"
#include "net_utils.h"

int net__n_rxq(const char *ifname)
{
    struct ethtool_channels channels = { .cmd = ETHTOOL_GCHANNELS };
	struct ifreq ifr = {};
	int fd, err, ret;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	ifr.ifr_data = (void *)&channels;
	memcpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err && errno != EOPNOTSUPP) {
		ret = -errno;
		goto out;
	}

	if (err) {
		/* If the device says it has no channels, then all traffic
		 * is sent to a single stream, so max queues = 1.
		 */
		ret = 1;
	} else {
		/* Take the max of rx, tx, combined. Drivers return
		 * the number of channels in different ways.
		 */
		ret = max(channels.rx_count, channels.combined_count);
	}

out:
	close(fd);
	return ret;
}

int net__max_rxq(const char *ifname)
{
    struct ethtool_channels channels = { .cmd = ETHTOOL_GCHANNELS };
	struct ifreq ifr = {};
	int fd, err, ret;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	ifr.ifr_data = (void *)&channels;
	memcpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err && errno != EOPNOTSUPP) {
		ret = -errno;
		goto out;
	}

	if (err) {
		/* If the device says it has no channels, then all traffic
		 * is sent to a single stream, so max queues = 1.
		 */
		ret = 1;
	} else {
		/* Take the max of rx, tx, combined. Drivers return
		 * the number of channels in different ways.
		 */
		ret = max(channels.max_rx, channels.max_tx);
		ret = max(ret, (int)channels.max_combined);
	}

out:
	close(fd);
	return ret;
}

int net_bridge__create(const char *brname)
{
    int error = 0;
    int sfd;

    if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        pr_warn("Failed to create socket");
        return errno;
    }
 
    int ret = ioctl(sfd, SIOCBRADDBR, brname);
 
    if (ret < 0) {
        pr_warn(stderr, "Create bridge failed");
        error = errno;
        goto out;
    }

out:  
    close(sfd);
    return error;
}

int net_bridge__delete(const char *brname)
{
    int error = 0;
    int sfd;

    if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        pr_warn("Failed to create socket");
        return errno;
    }
 
    int ret = ioctl(sfd, SIOCBRDELBR, brname);
 
    if (ret < 0) {
        pr_warn(stderr, "Delete bridge failed");
        error = errno;
        goto out;
    }

out:  
    close(sfd);
    return error;
}

int net_bridge__add_port(const char *brname, const char *ifname)
{
    int error = 0;
    int sfd, saved_errno, ret;
    struct ifreq ifr;
 
    memset(&ifr, 0, sizeof(ifr));
    
    if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        pr_warn("Failed to create socket");
        return errno;
    }

    strncpy(ifr.ifr_name, brname, IFNAMSIZ);

    ifr.ifr_ifindex = if_nametoindex(ifname);
    ret = ioctl(sfd, SIOCBRADDIF, &ifr);
    if (ret < 0)
    {
        pr_debug("SIOCBRADDIF, Attach interface failed");
        unsigned long args[4] = { BRCTL_ADD_IF, ifr.ifr_ifindex, 0, 0 };

        ifr.ifr_data = (char *) args;
        ret = ioctl(sfd, SIOCDEVPRIVATE, &ifr);
    }
    if (ret < 0) {
        pr_warn("Attach interface failed");
        close(sfd);
        return errno;
    }

    close(sfd);
    return error;
}

int net_bridge__remove_port(const char *brname, const char *ifname)
{
    int error = 0;
    int sfd, saved_errno, ret;
    struct ifreq ifr;
    
    memset (&ifr, 0, sizeof(ifr));

    if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        pr_warn("Failed to create socket");
        return errno;
    }

    strncpy(ifr.ifr_name, brname, IFNAMSIZ);

    ifr.ifr_ifindex = if_nametoindex(ifname);
    ret = ioctl(sfd, SIOCBRDELIF, &ifr);
    if (ret < 0)
    {
        pr_debug("SIOCBRDELIF, Detach interface failed");
        unsigned long args[4] = { BRCTL_DEL_IF, ifr.ifr_ifindex, 0, 0 };

        ifr.ifr_data = (char *) args;
        ret = ioctl(sfd, SIOCDEVPRIVATE, &ifr);
    }
    if (ret < 0) {
        pr_warn("Detach interface failed");
        close(sfd);
        return errno;
    }

    close(sfd);
    return error;
}

int net_arp__add_entry(char *dev, __be32 ip, __u8 mac[ETH_ALEN])
{
    int error = 0;
    int sfd, ret;
    struct arpreq arp_req;
    struct sockaddr_in *sin;
 
    if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        pr_warn("Failed to create socket");
        return errno;
    }
 
    sin = (struct sockaddr_in *)&(arp_req.arp_pa);
 
    memset(&arp_req, 0, sizeof(arp_req));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip;
    memcpy(arp_req.arp_ha.sa_data, mac, ETH_ALEN);
    strncpy(arp_req.arp_dev, dev, IFNAMSIZ-1);
    arp_req.arp_flags = ATF_PERM | ATF_COM;
 
    ret = ioctl(sfd, SIOCSARP, &arp_req);
    if (ret < 0) {
        pr_warn("Set ARP entry failed");
       return errno;
    }

    return error;
}

int net_arp__del_entry(char *dev, __be32 ip)
{
    int error = 0;
    int sfd, ret;
    struct arpreq arp_req;
    struct sockaddr_in *sin;
 
    if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        pr_warn("Failed to create socket");
        return errno;
    }
 
    sin = (struct sockaddr_in *)&(arp_req.arp_pa);
    memset(&arp_req, 0, sizeof(arp_req));
    sin->sin_family = AF_INET;
    strncpy(arp_req.arp_dev, dev, IFNAMSIZ-1);
    sin->sin_addr.s_addr = ip;
 
    ret = ioctl(sfd, SIOCDARP, &arp_req);
    if (ret < 0) {
        pr_warn("Delete ARP entry failed");
        return errno;
    }
    return error;
}

int net_arp__show_entry(const char *dev, __be32 ip)
{
    int error = ENOENT;
    int sfd, saved_errno, ret;
    unsigned char *mac;
    struct arpreq arp_req;
    struct sockaddr_in *sin;
 
    sin = (struct sockaddr_in *)&(arp_req.arp_pa);
 
    memset(&arp_req, 0, sizeof(arp_req));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip;
    strncpy(arp_req.arp_dev, dev, IFNAMSIZ-1);
 
    if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        pr_warn("Failed to create socket");
        return errno;
    }
 
    ret = ioctl(sfd, SIOCGARP, &arp_req);
    if (ret < 0) {
        pr_warn("Get ARP entry failed");
        return errno;
    }
 
    if (arp_req.arp_flags & ATF_COM) {
        mac = (unsigned char *)arp_req.arp_ha.sa_data;
        printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        printf("MAC: Not in the ARP cache.\n");
    }
    return error;
}

int net_arp__list_entries()
{
    int error = ENOENT;

    return error;
}


int net_port__add_ipv4_address()
{
    int error = ENOENT;

    return error;
}

int net_port__add_ipv6_address()
{
    int error = ENOENT;

    return error;
}

int net_port__show_ipv4_address()
{
    int error = ENOENT;

    return error;
}

int net_port__show_ipv6_address()
{
    int error = ENOENT;

    return error;
}

int net_port__show_mac()
{
    int error = ENOENT;

    return error;
}