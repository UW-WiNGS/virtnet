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

#include <linux/if_ether.h>  //for struct ethhdr
#include <linux/ip.h>        //for struct iphdr
#include <linux/udp.h>       //for struct udphdr
#include <linux/in.h>
#include <net/route.h>
#include <net/ip.h>

#include "virt.h"
#include "virtDebug.h"
#include "virtDevList.h"
#include "virtHeader.h"
#include "virtNetwork.h"
#include "virtSelectInterface.h"
#include "virtPassive.h"
#include "virtRoute.h"
#include "virtFlowTable.h"
#include "virtHeader.h"

/*
 * Route a packet to the appropriate node.
 *
 * Note that the reference count on the returned remote_node will be
 * incremented.  The caller must use remote_node_put when finished
 * with it.
 */
struct remote_node *select_remote_node(struct virt_priv *virt, struct packet *pkt)
{
    const struct iphdr *iphdr = ip_hdr(pkt->skb);
    struct remote_node *node;

    node = find_remote_node_by_ip(&virt->network, (struct in_addr *)&iphdr->daddr);

    if(!node) {
        __be32 proxy = virt_route(virt, iphdr->daddr);
        if(proxy) {
            VIRT_DBG("route 0x%x to 0x%x", ntohl(iphdr->daddr), ntohl(proxy));
            node = find_remote_node_by_ip(&virt->network, (struct in_addr *)&proxy);
        }
    }

    return node;
}

/*
 * The first step of building the tunnel header simply allocates space in the
 * sk_buff and adds the global and flow sequence numbers.  If the sk_buff is to
 * be queued, this part can be performed before queuing.
 */
struct tunhdr *virt_build_tunhdr(struct sk_buff *skb, const struct flow_table_entry *flow, 
        const struct remote_node *dest)
{
    struct tunhdr *tunhdr = (struct tunhdr *)skb_push(skb, sizeof(struct tunhdr));
    memset(tunhdr, 0, sizeof(*tunhdr));

    tunhdr->version = TUNHDR_VERSION;

    if(dest)
        tunhdr->seq = htonl(dest->next_tx_seq);

    return tunhdr;
}

/*
 * The second step of building the tunnel header fills in timestamps and
 * path-specific fields.  If the sk_buff is to be queued, this part should be
 * performed after dequeuing.
 *
 * flow can be NULL, as it is not currently used.
 */
void virt_finish_tunhdr(struct tunhdr *tunhdr, struct pathinfo *path, 
        struct flow_table_entry *flow, const struct remote_node *dest)
{
    s64 local_ts = ktime_to_us(ktime_get());
    s64 service;
    
    if(WARN_ON(!path))
        return;

    if(dest)
        tunhdr->ack = htonl(dest->next_rx_seq);

    tunhdr->path_ack = htonl(path->rcv_nxt);
    tunhdr->send_ts = htonl((int32_t)local_ts);

    service = local_ts - path->local_recv_time;
    if(service < MAX_SERVICE_TIME) {
        tunhdr->flags |= TUN_FLAG_TIMESTAMP_VALID;
        tunhdr->recv_ts  = htonl(path->recv_ts + (int32_t)service);
        path->local_meas_sent_time = local_ts;
    }

    tunhdr->xor_same_path = path->xor_same_path.rate;
    tunhdr->xor_same_prio = path->xor_same_prio.rate;
    tunhdr->xor_lower_prio = path->xor_lower_prio.rate;
}

struct udphdr *virt_build_udp_header(struct sk_buff *skb, __be16 sport, __be16 dport)
{
    struct udphdr *udphdr = (struct udphdr *)skb_push(skb, sizeof(struct udphdr));
    udphdr->source = sport;
    udphdr->dest = dport;
    udphdr->len = htons(skb->len);
    udphdr->check = 0; //TODO: checksum before sending

    skb_reset_transport_header(skb);

    return udphdr;
}

struct iphdr *virt_build_ip_header(struct sk_buff *skb, __be32 saddr, __be32 daddr)
{
    struct iphdr *iphdr = (struct iphdr *)skb_push(skb, sizeof(struct iphdr));
    iphdr->version = IPVERSION;
    iphdr->ihl = 5; //no options, just a plain IPv4 header
    iphdr->tos = 0;
    iphdr->tot_len = htons(skb->len);
    iphdr->id = 0;
    iphdr->frag_off = 0;
    iphdr->ttl = 0x40;
    iphdr->protocol = IPPROTO_UDP;
    iphdr->check = 0;
    iphdr->saddr = saddr;
    iphdr->daddr = daddr;
    
    // Fill in IP header checksum
    iphdr->check = ip_fast_csum((unsigned char *)iphdr, iphdr->ihl);

    skb_reset_network_header(skb);

    return iphdr;
}

