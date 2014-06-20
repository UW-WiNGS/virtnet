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

#include <linux/module.h>
#include <linux/version.h>

#include <linux/sched.h>
#include <linux/kernel.h> /* printk() */
#include <linux/slab.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/in.h>
#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/inetdevice.h>  /* struct in_device, __in_dev_get */
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/udp.h>         /* struct udphdr */
#include <linux/skbuff.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>

#include <linux/in6.h>
#include <asm/checksum.h>

#include <net/ip.h>

#include "virt.h"
#include "virtStats.h"
#include "virtDebug.h"
#include "virtParse.h"
#include "virtPolicy.h"
#include "virtIngress.h"
#include "virtEgress.h"
#include "virtDevList.h"
#include "virtPolicyTypes.h"
#include "virtEgressLookup.h"
#include "virtHeader.h"
#include "virtPassive.h"
#include "virtNetwork.h"
#include "virtFlowTable.h"
#include "virtNAT.h"

void virt_forward_skb(struct net_device *dev, struct sk_buff *skb) {
    const char fake_saddr[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    eth_header(skb, dev, ETH_P_IP, dev->dev_addr, fake_saddr, skb->len);
    skb_reset_mac_header(skb);
    skb_reset_mac_len(skb);
    dev_forward_skb(dev, skb);
}

static long calc_reorder_delay(struct virt_priv *virt, struct remote_node *dest)
{
    struct list_head *slave_list = get_slave_list_head();
    struct device_node *slave;

    long min_rtt = LONG_MAX;
    long max_rtt = LONG_MIN;

    long delay;

    int num_paths = 0;

    list_for_each_entry(slave, slave_list, lif.list) {
        struct remote_link *link;

        list_for_each_entry(link, &dest->links, rif.list) {
            struct pathinfo *path = path_lookup_create(&virt->network, slave, link);

            if(path) {
                long rtt = pathinfo_est_rtt(path);
                long rttvar = pathinfo_est_rttvar(path);

                long low_rtt = rtt - (2 * rttvar);
                long high_rtt = rtt + (2 * rttvar);

                if(low_rtt < min_rtt)
                    min_rtt = low_rtt;
                if(high_rtt > max_rtt)
                    max_rtt = high_rtt;

                virt_path_put(path);

                num_paths++;
            }
        }
    }

    if(num_paths > 1) {
        if(min_rtt < 0)
            min_rtt = 0;
        if(max_rtt < 0)
            max_rtt = virt_max_reorder_delay;

        delay = max_rtt - min_rtt;

        if(delay > virt_max_reorder_delay)
            delay = virt_max_reorder_delay;
    } else {
        delay = 0;
    }

    return delay;
}

/*
 * Possible return values are TUNNEL_FORWARD, TUNNEL_ACCEPT, TUNNEL_DROP, TUNNEL_STOLEN.
 */
int decap_ingress_packet(struct packet *pkt, struct device_node *slave)
{
    struct sk_buff *skb = pkt->skb;
    struct net_device *master_dev = pkt->master;
    int min_hdr_len;
    struct iphdr *iphdr;
    struct udphdr *udphdr;
    struct tunhdr *tunhdr;
    struct remote_link *from_link = NULL;
    struct virt_priv *virt = netdev_priv(master_dev);
    unsigned payload_len;
    int ret = TUNNEL_FORWARD;

    /* The reorder buffer and particularly the XOR code require that the
     * sk_buff be linear. */
    if(skb_is_nonlinear(skb) && __skb_linearize(skb)) {
        VIRT_DBG("Dropping nonlinear skb\n");
        ret = TUNNEL_DROP;
        goto out;
    }

    skb_reset_network_header(skb);
    iphdr = ip_hdr(skb);

    min_hdr_len = ip_hdrlen(skb) + sizeof(struct udphdr) + sizeof(struct tunhdr);
    if(unlikely(skb->len < min_hdr_len)) {
        ret = TUNNEL_ACCEPT;
        goto out;
    }

    udphdr = (struct udphdr *)skb_pull(skb, ip_hdrlen(skb));
    skb_reset_transport_header(skb);

    from_link = find_remote_link_by_addr(&virt->network, 
            (struct in_addr *)&iphdr->saddr, udphdr->source);

    /* If we do not recognize the origin of the packet, do not decapsulate and
     * forward it.  Need to accept it in case it is a ping from a new node. */
    if(!from_link) {
        skb_push(skb, ip_hdrlen(skb));
        ret = TUNNEL_ACCEPT;
        goto out;
    }

    tunhdr = (struct tunhdr *)skb_pull(skb, sizeof(struct udphdr));

    if(unlikely(tunhdr->flags & TUN_FLAG_PING)) {
        skb_push(skb, ip_hdrlen(skb) + sizeof(struct udphdr));
        ret = TUNNEL_ACCEPT;
        goto out;
    }

    if(unlikely(tunhdr->flags & TUN_FLAG_XOR_CODED)) {
        struct reorder_head *head = &from_link->node->reorder_head;
        switch(reorder_try_recover(head, skb)) {
            case REORDER_ACCEPT:
                insert_xor_packet(head, skb);
                ret = TUNNEL_STOLEN;
                break;
            case REORDER_STOLEN:
                ret = TUNNEL_STOLEN;
                break;
            case REORDER_DROP:
            default:
                ret = TUNNEL_DROP;
                break;
        }
        goto out;
    }

    pkt->tunnel_seq = ntohl(tunhdr->seq);
    pkt->reorder_delay = calc_reorder_delay(virt, from_link->node);
    memcpy(&pkt->src_node, &from_link->node->priv_ip, sizeof(pkt->src_node));

    payload_len = skb->len - sizeof(struct tunhdr);
    update_pathinfo(&virt->network, slave, from_link, tunhdr, payload_len);

    if(payload_len == 0) {
        /* This appears to be a pure ACK packet.  Try releasing queued packets
         * then discard it. */
        virt_try_send_queued(virt, slave, from_link);
        ret = TUNNEL_DROP;
        goto out;
    }

    /* update_pathinfo may have released some capacity for new packets.
     * Check if there are any queued packets to send. */
    if(virt_try_send_queued(virt, slave, from_link) <= 0)
        virt_send_ack(virt, slave, from_link);

    skb_pull(skb, sizeof(struct tunhdr));
    skb_reset_network_header(skb);
    skb_reset_transport_header(skb);

out:
    if(from_link)
        remote_link_put(from_link);

    return ret;
}

/* netfilter code example from: http://en.wikipedia.org/wiki/Hooking#Netfilter_hook */
unsigned int recv_ip(unsigned int hooknum, struct sk_buff *skb,
                             const struct net_device *in, const struct net_device *out,
                             int (*okfn)(struct sk_buff *))
{
    int rtn = 0;

    struct device_node *slave = NULL;
    struct net_device *master = NULL;
    struct virt_priv *virt = NULL;
    struct packet *pkt = NULL;
    int payload_len;
    
    if(!skb || !in || !in->name) {
        VIRT_DBG("skb, in, or in->name is null\n");
        goto drop;
    }

    /* For flow byte counts, we are interested in network layer and above. */
    payload_len = skb->len - skb->mac_len;

    if( use_timing() )
        log_timing(TIMING_RX_START);

    /* Do not touch packets on interfaces that are not enslaved. */
    slave = slave_get_by_name((char *)in->name);
    if(!slave)
        goto accept;

    master = slave->master;
    if(WARN_ON(!master))
        goto accept;

    /* Prevent loops. */
    if(strncmp(in->name, master->name, IFNAMSIZ) == 0) {
        VIRT_DBG("Packet is from master device\n");
        goto accept;
    }
    
    /* Update master device stats. */
    virt = netdev_priv(master);
    virt->stats.rx_packets++;
    virt->stats.rx_bytes += skb->len;
    
    /* Update slave device stats. */
    slave->stats.rx_packets++;
    slave->stats.rx_bytes += skb->len;

    if( use_timing() )
        log_timing(TIMING_RX_SETUP);

    pkt = kmalloc(sizeof(struct packet), GFP_ATOMIC);
    if(!pkt)
        goto drop;
    memset(pkt, 0, sizeof(struct packet));

    pkt->key = kmalloc(sizeof(struct flow_tuple), GFP_ATOMIC);
    if(!pkt->key)
        goto drop_and_free;
    memset(pkt->key, 0, sizeof(struct flow_tuple));

    pkt->hdr_ptrs = kmalloc(sizeof(struct hdr_ptrs), GFP_ATOMIC);
    if(!pkt->hdr_ptrs)
        goto drop_and_free;
    memset(pkt->hdr_ptrs, 0, sizeof(struct hdr_ptrs));

    pkt->skb = skb;
    pkt->master = master;

    // parse packet to fill in tuple/key structure
    if( use_timing() )
        log_timing(TIMING_RX_PARSE);

    if( (rtn = virt_parse_ingress_pkt(pkt)) < 0 )
        goto drop_and_free;

    // perform lookup to get the flow's actions
    if( use_timing() )
        log_timing(TIMING_RX_LOOKUP);

    // TODO: might be better to check port number first and figure out correct ip source first
    if( virt_ingress_lookup_flow(virt, pkt) < 0 ) {
        // this packet should be handled by the kernel not us
        VIRT_DBG("lookup failed...forward to kernel\n");
        goto accept_and_free;
    }
    
    /* Update policy hit statistics. */
    if(pkt->policy) {
        struct policy_stats *stats = &pkt->policy->stats;
        stats->rx_packets++;
        stats->rx_bytes += skb->len;
    }
    
    /* Update flow stats. */
    pkt->flow_stats->rx_bytes += payload_len;
    pkt->flow_stats->rx_packets++;
    pkt->flow_stats->last_rx_dev = in->ifindex;

    if( use_timing() )
        log_timing(TIMING_RX_MANGLE);

    switch(POLICY_ACTION(pkt->policy->action)) {
        case POLICY_ACT_PASS:
        case POLICY_ACT_LISP:
            goto accept_and_free;
        case POLICY_ACT_NAT:
            virt_denat_ingress_packet(pkt);
            virt_forward_skb(master, skb);
            goto stolen;
        case POLICY_ACT_ENCAP:
        case POLICY_ACT_DECAP:
            switch(decap_ingress_packet(pkt, slave)) {
                case TUNNEL_FORWARD:
                    break;
                case TUNNEL_ACCEPT:
                    goto accept_and_free;
                case TUNNEL_STOLEN:
                    goto stolen;
                case TUNNEL_DROP:
                default:
                    goto drop_and_free;
            }

            /* Release the flow_table_entry reference because it will be
             * overwritten by virt_egress_lookup_flow. */
            flow_table_entry_put(pkt->ftable_entry);
            pkt->ftable_entry = NULL;

            /* Handle the inner packet. */
            virt_parse_ingress_pkt(pkt);

            /* TODO: Using virt_egress_lookup_flow makes controller->gateway
             * policy work, but it may be confusing the semantics of the EGRESS
             * table. */
            virt_egress_lookup_flow(virt, pkt);
            
            /* Update policy hit statistics. */
            if(pkt->policy) {
                struct policy_stats *stats = &pkt->policy->stats;
                stats->rx_packets++;
                stats->rx_bytes += skb->len;
            }
            
            pkt->flow_stats->rx_bytes += skb->len - skb->mac_len;
            pkt->flow_stats->rx_packets++;
            pkt->flow_stats->last_rx_dev = in->ifindex;
            
            switch(reorder_rx_packet(&virt->network, pkt)) {
                case REORDER_ACCEPT:
                    virt_forward_skb(master, skb);
                    break;
                case REORDER_STOLEN:
                    break;
                case REORDER_DROP:
                    goto drop_and_free;
            }

            goto stolen;
        case POLICY_ACT_DROP:
            goto drop_and_free;
        default:
            // unknown route policy
            VIRT_DBG("ingress ERROR: unknown policy action (%x)\n", pkt->policy->action);
    }

    skb->dev = master;

    if( use_timing() )
        log_timing(TIMING_RX_END);

    VIRT_DBG("sending ingress packet to kernel\n\n");
    virt_free_packet(pkt);
    device_node_put(slave);
    return NF_ACCEPT;

stolen:
    virt_free_packet(pkt);

    if(slave)
        device_node_put(slave);

    return NF_STOLEN;

accept_and_free:
    virt_free_packet(pkt);

accept:
    if(slave)
        device_node_put(slave);

    return NF_ACCEPT;

drop_and_free:
    virt_free_packet(pkt);

drop:
    if(slave)
        device_node_put(slave);
    return NF_DROP;
}


unsigned int recv_arp(unsigned int hooknum, struct sk_buff *skb,
                              const struct net_device *in, const struct net_device *out,
                              int (*okfn)(struct sk_buff *))
{
    struct arphdr *arp;
    void          *arp_data;
    __be32        *arp_ip;

    struct device_node *slave;

    if( !skb )
        return NF_ACCEPT;

    // make sure packet isn't from ourselves to prevent loops
    if(is_virt_interface(in->name))
        return NF_ACCEPT;

    arp = arp_hdr(skb);
    arp_data = ((char *)arp + arp_hdr_len((struct net_device *)in));

    if(ntohs(arp->ar_op) != ARPOP_REPLY)
        return NF_ACCEPT;

    arp_ip = arp_data + arp->ar_hln;

    list_for_each_entry(slave, get_slave_list_head(), lif.list) {
        if(slave->gw_ip4 == *arp_ip) {
            memcpy(slave->next_hop_addr, arp_data, arp->ar_hln);
            break;
        }
    }

    return NF_ACCEPT;
}



