#ifndef XF_NETDEV_H
#define XF_NETDEV_H 1

#include <stdio.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/sockios.h>
#include <linux/if_bridge.h>

int bridge__create(const char *brname);
int bridge__delete(const char *brname);
int bridge__add_port(const char *brname, const char *ifname);
int bridge__remove_port(const char *brname, const char *ifname);

int arp__add_entry(char *dev, __be32 ip, __u8 mac[ETH_ALEN]);
int arp__del_entry(char *dev, __be32 ip);
int arp__show_entry(const char *dev, __be32 ip);
int arp__list_entries();

int port__add_ipv4_address();
int port__add_ipv6_address();
int port__show_ipv4_address();
int port__show_ipv6_address();
int port__show_mac();

#endif /* XF_NETDEV_H */     