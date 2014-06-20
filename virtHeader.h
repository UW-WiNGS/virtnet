/* 
 * Copyright (C) 2014 Joshua Hare, Lance Hartung, and Suman Banerjee.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _VIRT_HEADER__
#define _VIRT_HEADER__

#include "virt.h"

/* Version of tunhdr structure in use.  Increment if a change to the tunhdr
 * structure causes incompatibility with older code. */
#define TUNHDR_VERSION  0x01

struct tunhdr {
    __u8    flags;
    __u8    version;

    __u8    xor_same_path:4;
    __u8    xor_same_prio:4;
    __u8    xor_lower_prio:4;
    __u8    xor_rate:4;

    __be32  seq;
    __be32  ack;
    __be32  path_ack;

    __be32  send_ts;
    __be32  recv_ts;
} __attribute__((__packed__));

#define TUN_FLAG_PING               0x10
#define TUN_FLAG_TIMESTAMP_VALID    0x20
#define TUN_FLAG_XOR_CODED          0x40

// Maximum amount of space we may need to contstruct the tunnel header.
// (ethernet + IP + UDP)
#define VIRT_HEADER_MAX_LEN (42 + sizeof(struct tunhdr))

struct device_node;
struct sk_buff;
struct remote_node;
struct remote_link;
struct flow_stats;
struct pathinfo;
struct flow_table_entry;

struct remote_node *select_remote_node(struct virt_priv *virt, struct packet *pkt);
int virt_header_create(struct virt_priv *virt, struct packet *pkt, 
        struct device_node* slave, struct remote_node *dest);
int create_proxy_header(struct virt_network *net, struct sk_buff *skb,  
        struct device_node *slave, struct remote_link *link, 
        struct flow_table_entry *flow);
void set_virt_proxy_addr(const struct in_addr *addr);

struct tunhdr *virt_build_tunhdr(struct sk_buff *skb, 
        const struct flow_table_entry *flow, const struct remote_node *node);
void virt_finish_tunhdr(struct tunhdr *tunhdr, struct pathinfo *path, 
        struct flow_table_entry *flow, const struct remote_node *dest);

struct udphdr *virt_build_udp_header(struct sk_buff *skb, __be16 sport, __be16 dport);
struct iphdr *virt_build_ip_header(struct sk_buff *skb, __be32 saddr, __be32 daddr);

/* Check if the XOR coding rate bits are valid.  The XOR bits were added in
 * tunhdr version 1. */
static inline int tunhdr_xor_bits_valid(const struct tunhdr *tunhdr)
{
    return (tunhdr->version >= 0x01);
}

#endif //_VIRT_HEADER__

