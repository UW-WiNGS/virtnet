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

#ifndef _VIRT_PARSE_H__
#define _VIRT_PARSE_H__

struct packet;

struct flow_tuple {
    __be16 net_proto; // IPv4 vs IPv6
    __be32 dAddr;
    __be32 sAddr;
    __be16 proto;
    __be16 dPort;
    __be16 sPort;

    unsigned char d_mac[ETH_ALEN];
    unsigned char s_mac[ETH_ALEN];
};

struct hdr_ptrs {
    struct ethhdr *eth_ptr;
    struct iphdr  *ip_ptr;
    struct tcphdr *tcp_ptr;
    struct udphdr *udp_ptr;
};


struct parse_pkt {
    struct sk_buff *skb;
    struct flow_tuple *key;
    struct hdr_ptrs *hdr_ptrs;
};


//int virt_parse_egress_pkt(struct sk_buff *skb, struct flow_tuple *key, struct hdr_ptrs *ptrs);
//int virt_parse_ingress_pkt(struct sk_buff *skb, struct flow_tuple *key, struct hdr_ptrs *ptrs);
int virt_parse_egress_pkt(struct packet *pkt);
int virt_parse_ingress_pkt(struct packet *pkt);





#endif //_VIRT_PARSE_H__
