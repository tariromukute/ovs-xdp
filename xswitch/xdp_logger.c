/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include "../common/common_defines.h"
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/bpf_endian.h>

#define TRACEFS_PIPE "/sys/kernel/debug/tracing/trace_pipe"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void print_ether_addr(const char *type, char *str)
{
    __u64 addr;

    if (1 != sscanf(str, "%llu", &addr))
        return;
    printf("%s=%s ", type, ether_ntoa((struct ether_addr *)&addr));
}

static void print_ip_addr(const char *type, char *str)
{
    __be32 addr;
    void *ptr = &addr;
    char buf[INET_ADDRSTRLEN];
    if (1 != sscanf(str, "%u", &addr))
        return;
    printf("%s=%s ", type, inet_ntop(AF_INET, ptr, buf, sizeof(buf)));
}

static void print_ipv6_addr(const char *type, char *str)
{
    __be64 addr[2];
    void *ptr = &addr;
    char buf[INET6_ADDRSTRLEN];
    if (2 != sscanf(str, "%llu-%llu", &addr[0], &addr[1]))
        return;
    printf("%s=%s ", type, inet_ntop(AF_INET6, ptr, buf, sizeof(buf)));
}

static void print_nsh_md1_context(const char *type, char *str)
{
    __be64 addr[2];
    if (2 != sscanf(str, "%llu-%llu", &addr[0], &addr[1]))
        return;
    printf("%s=%llx%llx ", type, bpf_be64_to_cpu(addr[0]), bpf_be64_to_cpu(addr[1]));
}
static void print_u32(const char *type, char *str)
{
    __u32 i;
    if (1 == sscanf(str, "%u", &i))
        printf("%s=%u ", type, i);
}


// static void print_be32(const char *type, char *str)
// {
//     __be32 i;
//     if (1 == sscanf(str, "%u", &i))
//         printf("%s=%u ", type, ntohl(i));
// }

static void print_be16(const char *type, char *str)
{
    __be16 i;
    if (1 == sscanf(str, "%hu", &i))
        printf("%s=%u ", type, ntohs(i));
}

static void print_hex32(const char *type, char *str)
{
    __u32 i;
    if (1 == sscanf(str, "%u", &i))
        printf("%s=0x%08x ", type, i);
}

static void print_hex16(const char *type, char *str)
{
    __u32 i;
    if (1 == sscanf(str, "%u", &i))
        printf("%s=0x%04x ", type, i);
}

static void print_xdp_key_ethernet(char *tok, char **saveptr)
{
    printf("\n");
    while (tok)
    {
        if (!strncmp(tok, "eth_src:", 8))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_ether_addr("eth_src", tok);
        }

        if (!strncmp(tok, "eth_dst:", 8))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_ether_addr("eth_dst", tok);
        }

        if (!strncmp(tok, "h_proto:", 8))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_hex16("h_proto", tok);
        }
        if (!strncmp(tok, ":line", 5))
        {
            printf("\n");
        }
        tok = strtok_r(NULL, " ", saveptr);
    }
}

static void print_xdp_key_ipv6(char *tok, char **saveptr)
{
    // unsigned int proto;
    while (tok)
    {
        if (!strncmp(tok, "ipv6_src:", 9))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_ipv6_addr("ipv6_src", tok);
        }

        if (!strncmp(tok, "ipv6_dst:", 9))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_ipv6_addr("ipv6_dst", tok);
        }
        if (!strncmp(tok, ":line", 5))
        {
            printf("\n");
        }
        if (!strncmp(tok, "ipv6_proto:", 12))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("ipv6_proto", tok);
        }
        if (!strncmp(tok, "ipv6_tclass:", 13))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("ipv6_tclass", tok);
        }
        if (!strncmp(tok, "ipv6_hlimit:", 13))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("ipv6_hlimit", tok);
        }
        if (!strncmp(tok, "ipv6_frag:", 11))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("ipv6_frag", tok);
        }
        tok = strtok_r(NULL, " ", saveptr);
    }
}

static void print_xdp_key_ipv4(char *tok, char **saveptr)
{
    // unsigned int proto;
    while (tok)
    {
        if (!strncmp(tok, "ipv4_src:", 10))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_ip_addr("ipv4_src", tok);
        }

        if (!strncmp(tok, "ipv4_dst:", 10))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_ip_addr("ipv4_dst", tok);
        }
        if (!strncmp(tok, "ipv4_proto:", 12))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("ipv4_proto", tok);
        }
        if (!strncmp(tok, "ipv4_tos:", 10))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("ipv4_tos", tok);
        }
        if (!strncmp(tok, "ipv4_ttl:", 10))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("ipv4_ttl", tok);
        }
        if (!strncmp(tok, "ipv4_frag:", 11))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("ipv4_frag", tok);
        }
        if (!strncmp(tok, ":line", 5))
        {
            printf("\n");
        }
        tok = strtok_r(NULL, " ", saveptr);
    }
}

static void print_xdp_key_arp(char *tok, char **saveptr)
{
    while (tok)
    {
        if (!strncmp(tok, "arp_sip:", 9))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_ip_addr("arp_sip", tok);
        }
        if (!strncmp(tok, "arp_tip:", 9))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_ip_addr("arp_tip", tok);
        }
        if (!strncmp(tok, "arp_op:", 8))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("arp_op", tok);
        }
        if (!strncmp(tok, "arp_sha:", 9))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_ether_addr("arp_sha", tok);
        }
        if (!strncmp(tok, "arp_tha:", 9))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_ether_addr("arp_tha", tok);
        }
        if (!strncmp(tok, ":line", 5))
        {
            printf("\n");
        }    
        tok = strtok_r(NULL, " ", saveptr);
    }
}

static void print_xdp_key_tcp(char *tok, char **saveptr)
{
    while (tok)
    {
        if (!strncmp(tok, "tcp_src:", 9))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_be16("tcp_src", tok);
        }
        if (!strncmp(tok, "tcp_dst:", 9))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_be16("tcp_dst", tok);
        }
        if (!strncmp(tok, ":line", 5))
        {
            printf("\n");
        }    
        tok = strtok_r(NULL, " ", saveptr);
    }
}

static void print_xdp_key_udp(char *tok, char **saveptr)
{
    while (tok)
    {

        if (!strncmp(tok, "udp_src:", 9))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_be16("udp_src", tok);
        }
        if (!strncmp(tok, "udp_dst:", 9))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_be16("udp_dst", tok);
        }
        if (!strncmp(tok, ":line", 5))
        {
            printf("\n");
        }        
        tok = strtok_r(NULL, " ", saveptr);
    }
}

static void print_xdp_key_sctp(char *tok, char **saveptr)
{
    while (tok)
    {
        if (!strncmp(tok, "sctp_src:", 10))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_be16("sctp_src", tok);
        }
        if (!strncmp(tok, "sctp_dst:", 10))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_be16("sctp_dst", tok);
        }
        if (!strncmp(tok, ":line", 5))
        {
            printf("\n");
        }    
        tok = strtok_r(NULL, " ", saveptr);
    }
}

static void print_xdp_key_icmp(char *tok, char **saveptr)
{
    while (tok)
    {

        if (!strncmp(tok, "icmp_type:", 11))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("icmp_type", tok);
        }
        if (!strncmp(tok, "icmp_code:", 11))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("icmp_code", tok);
        }
        if (!strncmp(tok, ":line", 5))
        {
            printf("\n");
        }    
        tok = strtok_r(NULL, " ", saveptr);
    }
}

static void print_xdp_key_icmpv6(char *tok, char **saveptr)
{
    while (tok)
    {
        if (!strncmp(tok, "icmpv6_type:", 13))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("icmpv6_type", tok);
        }
        if (!strncmp(tok, "icmpv6_code:", 13))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("icmpv6_code", tok);
        }
        if (!strncmp(tok, ":line", 5))
        {
            printf("\n");
        }    
        tok = strtok_r(NULL, " ", saveptr);
    }
}

static void print_xdp_key_nsh_base(char *tok, char **saveptr)
{
    while (tok)
    {
        if (!strncmp(tok, "flags:", 7))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("flags", tok);
        }
        if (!strncmp(tok, "ttl:", 5))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("ttl", tok);
        }
        if (!strncmp(tok, "mdtype:", 8))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("mdtype", tok);
        }
        if (!strncmp(tok, "np:", 4))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_u32("np", tok);
        }
        if (!strncmp(tok, "path_hdr:", 10))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_hex32("path_hdr", tok);
        }
        if (!strncmp(tok, ":line", 5))
        {
            printf("\n");
        }    
        tok = strtok_r(NULL, " ", saveptr);
    }
}

static void print_xdp_key_nsh_md1(char *tok, char **saveptr)
{
    while (tok)
    {
        if (!strncmp(tok, "context:", 9))
        {
            tok = strtok_r(NULL, " ", saveptr);
            print_nsh_md1_context("context", tok);
        }
        if (!strncmp(tok, ":line", 5))
        {
            printf("\n");
        }    
        tok = strtok_r(NULL, " ", saveptr);
    }
}

int main()
{
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    stream = fopen(TRACEFS_PIPE, "r");
    if (stream == NULL)
    {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    /* NOTE: an identifier to the log type being processed e.g., INFO: ERROR: DEBUG: xdp_key_ethernet:
     * xdp_key_ipv4 etc. This basically used in cases were the log being processed is broken across 
     * multiple lines being of the limitation of the bpf_trace_printk of 3 args max, 1 %s only. It is 
     * also important to note that trace_pipe is globally shared, so concurrent programs will have 
     * clashing output therefore TODO: will need a work around for that especially logs broken across
     * multiple lines */
    // char *key;

    while ((nread = getline(&line, &len, stream)) != -1)
    {
        char *tok, *saveptr;

        tok = strtok_r(line, " ", &saveptr);
        while (tok)
        {
            // printf("tok %s", tok);
            if (!strncmp(tok, "xdp_key_ethernet:", 18)) {
                print_xdp_key_ethernet(tok, &saveptr);
            }

            if (!strncmp(tok, "xdp_key_ipv6:", 14)) {
                print_xdp_key_ipv6(tok, &saveptr);
            }

            if (!strncmp(tok, "xdp_key_ipv4:", 14)) {
                print_xdp_key_ipv4(tok, &saveptr);
            }

            if (!strncmp(tok, "xdp_key_tcp:", 13)) {
                print_xdp_key_tcp(tok, &saveptr);
            }

            if (!strncmp(tok, "xdp_key_udp:", 13)) {
                print_xdp_key_udp(tok, &saveptr);
            }

            if (!strncmp(tok, "xdp_key_sctp:", 14)) {
                print_xdp_key_sctp(tok, &saveptr);
            }

            if (!strncmp(tok, "xdp_key_icmp:", 14)) {
                print_xdp_key_icmp(tok, &saveptr);
            }

            if (!strncmp(tok, "xdp_key_icmpv6:", 16)) {
                print_xdp_key_icmpv6(tok, &saveptr);
            }

            if (!strncmp(tok, "xdp_key_arp:", 13)) {
                print_xdp_key_arp(tok, &saveptr);
            }

            if (!strncmp(tok, "xdp_key_nsh_base:", 18)) {
                print_xdp_key_nsh_base(tok, &saveptr);
            }

            if (!strncmp(tok, "xdp_key_nsh_md1:", 17)) {
                print_xdp_key_nsh_md1(tok, &saveptr);
            }
            tok = strtok_r(NULL, " ", &saveptr);
        }
    }
    

    free(line);
    fclose(stream);
    return 0;
}
