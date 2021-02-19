#ifndef NET_UTILS_H
#define NET_UTILS_H 1

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef min
# define min(x, y) ((x) < (y) ? (x) : (y))
#endif
#ifndef max
# define max(x, y) ((x) < (y) ? (y) : (x))
#endif

int net__n_rxq(const char *);

int net__max_rxq(const char *);

int net_bridge__create(const char *brname);
int net_bridge__delete(const char *brname);
int net_bridge__add_port(const char *brname, const char *ifname);
int net_bridge__remove_port(const char *brname, const char *ifname);

int net_arp__add_entry(char *dev, __be32 ip, __u8 mac[ETH_ALEN]);
int net_arp__del_entry(char *dev, __be32 ip);
int net_arp__show_entry(const char *dev, __be32 ip);
int net_arp__list_entries();

int net_port__add_ipv4_address();
int net_port__add_ipv6_address();
int net_port__show_ipv4_address();
int net_port__show_ipv6_address();
int net_port__show_mac();

#endif /* net_utils.h */