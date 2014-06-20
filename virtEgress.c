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
#include <net/arp.h>
#include <net/ip.h>
#include <net/route.h>

#include <linux/in6.h>
#include <asm/checksum.h>

#include "virt.h"
#include "virtStats.h"
#include "virtParse.h"
#include "virtDebug.h"
#include "virtPolicy.h"
#include "virtHeader.h"
#include "virtEgress.h"
#include "virtDevList.h"
#include "virtPolicyTypes.h"
#include "virtEgressLookup.h"
#include "virtSelectInterface.h"
#include "virtFlowTable.h"
#include "virtNetwork.h"
#include "virtNAT.h"
#include "virtCoding.h"
#include "virtRetransmission.h"

// TODO: move all handle_xxxproto to virtEgressParse.c/.h also move flow_info struct there

unsigned int send_arp(unsigned int hooknum, struct sk_buff *skb,
                              const struct net_device *in, const struct net_device *out,
                              int (*okfn)(struct sk_buff *))
{
    struct arphdr *arp      = NULL;
    char          *arp_data = NULL;

    char sender_hw[ETH_ALEN];
    __be32 sender_ip, target_ip;

    if( !skb )
        return NF_ACCEPT;

    if(!is_virt_interface(out->name))
        return NF_ACCEPT;
    
    arp = arp_hdr(skb);

    switch( ntohs(arp->ar_op) )
    {
        case ARPOP_REPLY:
            return NF_DROP;
        case ARPOP_REQUEST: //TODO: we need to reply to these
            VIRT_DBG(" got an ARP_REQUEST\n");
            arp_data = ((char *)arp + sizeof(struct arphdr));

            memcpy(&sender_hw, arp_data, arp->ar_hln);
            arp_data += arp->ar_hln;
            memcpy(&sender_ip, arp_data, arp->ar_pln);
            arp_data += arp->ar_pln;
            arp_data += arp->ar_hln; //skip target mac cause it is blank
            memcpy(&target_ip, arp_data, arp->ar_pln);
            VIRT_DBG("sending a arp reply to: 0x%x sender: 0x%x sender_hw: 0x%02x:%02x:%02x:%02x:%02x:%02x\n", target_ip, sender_ip,
                            sender_hw[0], sender_hw[1], sender_hw[2], sender_hw[3], sender_hw[4], sender_hw[5]);
            sender_hw[5] = 0x88;

        default:
            return NF_DROP;
    }

    return NF_DROP;
}

/*
 * Try to send as many packets as possible in response to newly available
 * capacity on the path.
 *
 * Returns number of queued packets sent.
 */
int virt_try_send_queued(struct virt_priv *virt, struct device_node *slave, 
        struct remote_link *link)
{
    struct sk_buff_head *tx_queue = &link->node->tx_queue;
    struct pathinfo *path = path_lookup_create(&virt->network, slave, link);
    int free_packets = 0;
    int sent = 0;
    unsigned long now = jiffies;

    if(!path)
        return 0;

    /* If path has been quiet (no ACKs for a multiple of its RTT), then
     * send one packet for free to help prevent stalling. */
    if(afterl(now, path->stall_time)) {
        unsigned long rtt = pathinfo_est_rtt(path);

        path->stall_time = now + usecs_to_jiffies(rtt << PATH_STALL_RTT_MULT);
        free_packets = 1;
    }

    while(!skb_queue_empty(tx_queue)) {
        struct sk_buff *skb;
        unsigned payload_len;
        
        spin_lock_bh(&tx_queue->lock);
        skb = skb_peek(tx_queue);

        /* Need to check result of skb_peek due to race condition between
         * checking skb_queue_empty and taking the lock. */
        if(!skb) {
            spin_unlock_bh(&tx_queue->lock);
            break;
        }

        /* Tunnel header was added before queuing the sk_buff. */
        payload_len = skb->len - sizeof(struct tunhdr);

        if(free_packets > 0) {
            path->avail += payload_len;
            free_packets--;
        }

        if(payload_len <= path->avail) {
            struct net_device *slave_dev = slave->dev;
            struct tunhdr *tunhdr = (struct tunhdr *)skb->data;
            struct virt_skb_cb *skb_cb = (struct virt_skb_cb *)skb->cb;
            struct flow_table_entry *flow = skb_cb->flow;

            __skb_unlink(skb, tx_queue);
            spin_unlock_bh(&tx_queue->lock);

            virt_finish_tunhdr(tunhdr, path, skb_cb->flow, link->node);
            virt_build_udp_header(skb, flow->rx_port, link->rif.data_port);
            virt_build_ip_header(skb, slave->lif.ip4, link->rif.ip4);

            flow_table_entry_put(skb_cb->flow);

            path->avail -= payload_len;
            path->snd_nxt += payload_len;

            skb->dev = slave_dev;
            skb->protocol = htons(ETH_P_IP);

            dev_hard_header(skb, slave_dev, ETH_P_IP, slave->next_hop_addr,
                    slave_dev->dev_addr, skb->len);
            skb_reset_mac_header(skb);

            /* Update link statistics -- these may not be accurate if the packet
             * gets dropped after dev_queue_xmit. */
            slave->stats.tx_packets++;
            slave->stats.tx_bytes += skb->len;

            /* Update device statistics. */
            virt->stats.tx_packets++;
            virt->stats.tx_bytes += skb->len;
            
            path_update_tx_bytes(path, skb->len);

            dev_queue_xmit(skb);

            sent++;
        } else {
            spin_unlock_bh(&tx_queue->lock);
            break;
        }
    }

    virt_path_put(path);

    return sent;
}

int virt_send_ack(struct virt_priv *virt, struct device_node *slave, 
        struct remote_link *link)
{
    struct sk_buff *skb;
    struct net_device *dev = slave->dev;
    struct tunhdr *tunhdr;
    struct pathinfo *path;
    __be16 sport;

    unsigned alloc_size = sizeof(struct tunhdr) + sizeof(struct udphdr) +
        sizeof(struct iphdr) + LL_RESERVED_SPACE(dev);

    path = lookup_pathinfo(&virt->network, slave, link);
    if(!path)
        return -EINVAL;

    skb = alloc_skb(alloc_size, GFP_ATOMIC);
    if(!skb) {
        virt_path_put(path);
        return -ENOMEM;
    }

    skb_reserve(skb, alloc_size);

    tunhdr = virt_build_tunhdr(skb, NULL, NULL);
    virt_finish_tunhdr(tunhdr, path, NULL, link->node);

    /* TODO: We may want to split traffic among different ports, which
     * may change how we send ACKs.  For now, everything uses the same
     * source port. */
    sport = htons(virt_tunnel_source_port());
    virt_build_udp_header(skb, sport, link->rif.data_port);
    virt_build_ip_header(skb, slave->lif.ip4, link->rif.ip4);

    skb->dev = dev;
    skb->protocol = htons(ETH_P_IP);

    dev_hard_header(skb, dev, ETH_P_IP, slave->next_hop_addr, dev->dev_addr, skb->len);
    skb_reset_mac_header(skb);

    /* Update link statistics -- these may not be accurate if the packet gets
     * dropped after dev_queue_xmit. */
    slave->stats.tx_packets++;
    slave->stats.tx_bytes += skb->len;

    /* Update device statistics. */
    virt->stats.tx_packets++;
    virt->stats.tx_bytes += skb->len;

    /* Decrement refcnt. */
    virt_path_put(path);

    dev_queue_xmit(skb);

    return 0;
}

/*
 * Transmit a packet (called by the kernel)
 */
int virt_tx(struct sk_buff *skb, struct net_device *dev)
{
    int rtn = 0;
    struct virt_priv *priv = netdev_priv(dev);
    struct device_node *slave = NULL;
    int payload_len;

    struct packet *pkt = NULL;

#ifndef VIRT_USE_RTABLE
    struct net_device *out_dev = NULL;
#endif

    //VIRT_DBG("in virt_tx...\n");
    if( use_timing() )
        log_timing(TIMING_TX_START);

    // if no slaves default off => drop packet
    if(get_slave_list_head() == NULL)
        goto drop;

    /* For flow byte counts, we are interested in network layer and above. */
    payload_len = skb->len;

    dev->trans_start = jiffies; /* save the timestamp */

    if( use_timing() )
        log_timing(TIMING_TX_SETUP);

    //malloc packet struct and flow struct
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

    pkt->master = dev;
    pkt->skb = skb;

    if( use_timing() )
        log_timing(TIMING_TX_PARSE);

    rtn = virt_parse_egress_pkt(pkt);

    if( ntohs(pkt->key->net_proto) == ETH_P_ARP )
        goto drop_and_free;

    if( use_timing() )
        log_timing(TIMING_TX_LOOKUP);

    // lookup flow route info
    if(virt_egress_lookup_flow(priv, pkt) < 0)
        goto drop_and_free;

    /* Update policy hit statistics. */
    if(pkt->policy) {
        struct policy_stats *stats = &pkt->policy->stats;
        stats->tx_packets++;
        stats->tx_bytes += skb->len;
    }

    // route the packet
    if( use_timing() )
        log_timing(TIMING_TX_MANGLE);

    switch(POLICY_ACTION(pkt->policy->action)) {
        case POLICY_ACT_PASS:
            slave = select_local_interface(priv, pkt->ftable_entry, NULL, get_slave_list_head());
            if(!slave)
                goto drop_and_free;

            VIRT_DBG("egress PASS this packet\n");

            /* TODO: It would be nice if PASSed packets would still go through
             * netfilter, especially the post-routing hook, so that we could
             * make use of netfilter's NAT function.  However, the netfilter
             * hooks rely on routing information being filled in, so we would
             * have to play along with the routing code.
             *
             * if(nf_hook(NFPROTO_IPV4, NF_INET_POST_ROUTING, skb, NULL, 
             *      slave->dev, dev_queue_xmit) == NF_ACCEPT)
             *      dev_queue_xmit(skb);
             */
            break;
        case POLICY_ACT_LISP:
        case POLICY_ACT_NAT:
            slave = select_local_interface(priv, pkt->ftable_entry, NULL, get_slave_list_head());
            if(!slave)
                goto drop_and_free;

            VIRT_DBG("egress NAT this packet\n");
            virt_nat_egress_pkt(pkt, slave);
            break;
        case POLICY_ACT_ENCAP:
            {
                struct remote_node *rnode = pkt->ftable_entry->rnode;
                
                if(!rnode) {
                    rnode = select_remote_node(priv, pkt);
                    if(!rnode) {
                        VIRT_DBG("routing packet failed\n");
                        goto drop_and_free;
                    }

                    pkt->ftable_entry->rnode = rnode;
                }

                virt_queue_tx(priv, pkt, rnode);
                return NETDEV_TX_OK;
            }
        case POLICY_ACT_DROP:
            VIRT_DBG("egress DROP this packet\n");
            goto drop_and_free;
        default:
            // unknown route policy
            VIRT_DBG("egress ERROR: unknown policy action (%x)\n", pkt->policy->action);
    }

    // update flow statistics
    pkt->flow_stats->tx_packets++;
    pkt->flow_stats->tx_bytes += payload_len;
    pkt->flow_stats->last_tx_dev = slave->dev->ifindex;
    // update device statistics
    priv->stats.tx_packets++;
    priv->stats.tx_bytes += skb->len;
    // update link statistics
    slave->stats.tx_packets++;
    slave->stats.tx_bytes += skb->len;

    VIRT_DBG("transmitting the packet...\n\n");
    if( use_timing() )
        log_timing(TIMING_TX_END);

#ifdef VIRT_USE_RTABLE
    uint32_t gw_ip = 0x020FA8C0;
    struct rtable *rt = skb_rtable(skb);
    struct iphdr *ip = ip_hdr(skb);

    VIRT_DBG("routing %x->%x (%s)\n", ntohl(ip->saddr), ntohl(ip->daddr),
            slave->dev->name);
    struct flowi fl = {
//        .oif = pkt->slave->dev->iflink,
        .oif = slave->dev->ifindex,
        .nl_u = {
            .ip4_u = {
                .daddr = ip->daddr,
                .saddr = ip->saddr,
                .tos = 0,
            },
        },
        .proto = IPPROTO_IP,
    };

    skb_dst_drop(skb);
    if(ip_route_output_key(dev_net(slave->dev), &rt, &fl)) {
        VIRT_DBG("ip_route_output_key failed\n");
    } else {
        VIRT_DBG("route: %s, neigh: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx, state: %s\n", 
                rt->dst.dev->name,
                rt->dst.neighbour->ha[0], rt->dst.neighbour->ha[1], rt->dst.neighbour->ha[2],
                rt->dst.neighbour->ha[3], rt->dst.neighbour->ha[4], rt->dst.neighbour->ha[5],
                rt->dst.neighbour->nud_state & NUD_VALID ? "valid" : "invalid");

        if(!(rt->dst.neighbour->nud_state & NUD_VALID)) {
            neigh_release(rt->dst.neighbour);
            rt->dst.neighbour = neigh_create(&arp_tbl, &gw_ip, slave->dev);
            rt->rt_gateway = gw_ip;
        }
    }

    skb_dst_set(skb, &rt->dst);
    
    VIRT_DBG("routing done %x->%x (%s)\n", ntohl(ip->saddr), ntohl(ip->daddr),
            slave->dev->name);
#else //!VIRT_USE_RTABLE
    out_dev = slave->dev;
    dev_hard_header(skb, out_dev, ETH_P_IP, 
            slave->next_hop_addr, 
            out_dev->dev_addr, skb->len);
    skb_reset_mac_header(skb);
#endif

    pkt->flow_stats->last_send_jiffies = jiffies;

#ifdef VIRT_USE_RTABLE
    ip_local_out(skb);
#else
    skb->dev = slave->dev;
    rtn = dev_queue_xmit(skb);
#endif

    virt_free_packet(pkt);

    if(slave)
        device_node_put(slave);

    return NETDEV_TX_OK;

drop_and_free:
    virt_free_packet(pkt);

drop:
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}



/*
 * Deal with a transmit timeout.
 */
void virt_tx_timeout (struct net_device *dev)
{
    struct virt_priv *priv = netdev_priv(dev);

    VIRT_DBG("Transmit timeout at %ld, latency %ld\n", jiffies,
            jiffies - dev->trans_start);
        /* Simulate a transmission interrupt to get things moving */
    //priv->status = VIRT_TX_INTR;
    //virt_interrupt(0, dev, NULL);
    priv->stats.tx_errors++;
    netif_wake_queue(dev);
    return;
}

/*
 * Finish sending the packet on the given path.  The skb is consumed whether
 * the transmission succeeds or not.
 */
static int virt_finish_tx(struct virt_priv *virt, struct sk_buff *skb, 
        struct pathinfo *path)
{
    struct tunhdr *tunhdr = (struct tunhdr *)skb->data;
    struct virt_skb_cb *skb_cb = (struct virt_skb_cb *)skb->cb;
    long payload_len = skb->len - sizeof(struct tunhdr);
    struct flow_table_entry *flow = skb_cb->flow; /* NULL for XOR packets. */
    __be16 rx_port;

    struct device_node *slave = NULL;
    struct remote_link *link = NULL;

    if(flow)
        rx_port = flow->rx_port;
    else
        rx_port = htons(virt_tunnel_source_port());

    slave = slave_get_by_ifindex(path->local_index);
    if(unlikely(!slave))
        goto drop;

    link = find_remote_link_by_addr(&virt->network,
            &path->remote_addr.ip4, path->remote_port);
    if(unlikely(!link))
        goto drop;

    virt_finish_tunhdr(tunhdr, path, flow, link->node);
    virt_build_udp_header(skb, rx_port, link->rif.data_port);
    virt_build_ip_header(skb, slave->lif.ip4, link->rif.ip4);

    path->avail -= payload_len;
    path->snd_nxt += payload_len;

    skb->dev = slave->dev;
    skb->protocol = htons(ETH_P_IP);

    dev_hard_header(skb, slave->dev, ETH_P_IP, slave->next_hop_addr,
            slave->dev->dev_addr, skb->len);
    skb_reset_mac_header(skb);

    /* Update link statistics -- these may not be accurate if the packet
     * gets dropped after dev_queue_xmit. */
    slave->stats.tx_packets++;
    slave->stats.tx_bytes += skb->len;

    if(flow)
        flow->flow_stats->last_tx_dev = slave->dev->ifindex;

    path_update_tx_bytes(path, skb->len);

    /* Clean up before dev_queue_xmit consumes the skb. */
    remote_link_put(link);
    device_node_put(slave);

    dev_queue_xmit(skb);

    return 0;

drop:
    virt->stats.tx_dropped++;

    if(link)
        remote_link_put(link);
    if(slave)
        device_node_put(slave);

    dev_kfree_skb(skb);

    return -1;
}

/*
 * Send a copy of the packet on one of the stalled paths to the destination if
 * there are any.  This serves as a probe to test whether the path is working
 * again.
 */
static int send_probe_packet(struct virt_priv *virt, struct sk_buff *skb,
        struct remote_node *dest)
{
    struct sk_buff *copy;
    struct pathinfo *path;
    unsigned long now = jiffies;

    if(dest->stalled_paths_len <= 0)
        return 0;

    rcu_read_lock();
    list_for_each_entry_rcu(path, &dest->stalled_paths, stall_list) {
        unsigned long probe_interval = virt_probe_interval_jiffies();
        
        if(afterl(now, path->last_packet + probe_interval)) {
            copy = skb_copy(skb, GFP_ATOMIC);
            if(!copy)
                break;

            virt_finish_tx(virt, copy, path);

            /* Move this path to the end of the stall list to prevent
             * starvation of paths. */
            spin_lock_bh(&dest->stalled_paths_lock);
            list_del_rcu(&path->stall_list);
            list_add_tail_rcu(&path->stall_list, &dest->stalled_paths);
            spin_unlock_bh(&dest->stalled_paths_lock);
        }
    }
    rcu_read_unlock();

    return 0;
}

/*
 * Test if a slave device can be used to transmit.
 *
 * Checks the slave device's priority >= min_prio and whether the DEVICE_NO_TX
 * flag is set.
 */
static int can_use_device(const struct device_node *slave, int min_prio)
{
    if(slave->lif.prio < min_prio)
        return 0;

    if(slave->flags & DEVICE_NO_TX)
        return 0;

    return 1;
}

/*
 * Send copies of the packet on multiple paths.  If at least one copy is sent,
 * then the skb will be consumed.
 *
 * The return value indicates the number of copies sent.
 */
static int virt_send_duplicate(struct virt_priv *virt,
        struct sk_buff *skb, struct remote_node *dest)
{
    struct list_head *slave_list = get_slave_list_head();
    struct device_node *slave = NULL;
    int sent = 0;

    rcu_read_lock();
    list_for_each_entry(slave, slave_list, lif.list) {
        if(can_use_device(slave, virt->max_dev_prio)) {
            struct remote_link *link;

            list_for_each_entry_rcu(link, &dest->links, rif.list) {
                if(link->rif.prio >= dest->max_link_prio) {
                    struct pathinfo *path;
                    struct sk_buff *copy = skb_copy(skb, GFP_ATOMIC);

                    if(unlikely(!copy))
                        goto out;

                    path = path_lookup_create(&virt->network, slave, link);
                    if(likely(path)) {
                        virt_finish_tx(virt, copy, path);
                        virt_path_put(path);
                        sent++;
                    } else {
                        dev_kfree_skb(copy);
                    }
                }
            }
        }
    }

out:
    rcu_read_unlock();

    if(sent > 0)
        dev_kfree_skb(skb);

    return sent;
}

static struct pathinfo *virt_select_single_path(struct virt_priv *virt,
        struct flow_table_entry *flow, struct remote_node *dest)
{
    struct list_head *slave_list = get_slave_list_head();

    struct device_node *slave = NULL;
    struct remote_link *link = NULL;
    struct pathinfo *path = NULL;

    slave = select_local_interface(virt, flow, dest, slave_list);
    if(!slave)
        goto out;

    link = select_remote_interface(virt, flow, slave, dest, &dest->links);
    if(!link)
        goto out;

    path = path_lookup_create(&virt->network, slave, link);

out:
    if(link)
        remote_link_put(link);
    if(slave)
        device_node_put(slave);

    return path;
}

static struct pathinfo *virt_select_multi_path(struct virt_priv *virt,
        struct flow_table_entry *flow, long payload_len, struct remote_node *dest)
{
    struct list_head *slave_list = get_slave_list_head();
    struct device_node *slave = NULL;
    unsigned long best_avail = 0;

    struct device_node *best_slave = NULL;
    struct remote_link *best_link = NULL;
    struct pathinfo *sel_path = NULL;

    rcu_read_lock();
    list_for_each_entry(slave, slave_list, lif.list) {
        if(can_use_device(slave, virt->max_dev_prio)) {
            struct remote_link *link;

            list_for_each_entry_rcu(link, &dest->links, rif.list) {
                if(link->rif.prio >= dest->max_link_prio) {
                    struct pathinfo *path = path_lookup_create(&virt->network, slave, link);

                    if(path && payload_len <= path->avail) {
                        unsigned long avail = (path->avail << 8) / path->cwnd;
                        if(avail > best_avail) {
                            best_avail = avail;
                            best_slave = slave;
                            best_link = link;
                        }
                    }

                    if(path)
                        virt_path_put(path);
                }
            }
        }
    }

    if(best_link)
        sel_path = path_lookup_create(&virt->network, best_slave, best_link);

    rcu_read_unlock();

    return sel_path;
}

/*
 * Select a path other than the given path that has high priority.
 */
static struct pathinfo *virt_select_same_prio(struct virt_priv *virt,
        struct remote_node *dest, struct pathinfo *path)
{
    struct list_head *slave_list = get_slave_list_head();
    struct device_node *slave = NULL;

    unsigned long best_rtt = ULONG_MAX;
    struct device_node *best_slave = NULL;
    struct remote_link *best_link = NULL;
    struct pathinfo *sel_path = NULL;

    rcu_read_lock();
    list_for_each_entry(slave, slave_list, lif.list) {
        if(can_use_device(slave, virt->max_dev_prio)) {
            struct remote_link *link;

            list_for_each_entry_rcu(link, &dest->links, rif.list) {
                if(link->rif.prio >= dest->max_link_prio) {
                    struct pathinfo *other = path_lookup_create(&virt->network, slave, link);

                    if(other && other != path) {
                        unsigned long rtt = pathinfo_est_rtt(other);
                        if(rtt < best_rtt) {
                            best_rtt = rtt;
                            best_slave = slave;
                            best_link = link;
                        }
                    }

                    if(other)
                        virt_path_put(other);
                }
            }
        }
    }

    if(best_link)
        sel_path = path_lookup_create(&virt->network, best_slave, best_link);

    rcu_read_unlock();

    return sel_path;
}

/*
 * Select a path other than the given path that has low priority.
 */
static struct pathinfo *virt_select_low_prio(struct virt_priv *virt,
        struct remote_node *dest, struct pathinfo *path)
{
    struct list_head *slave_list = get_slave_list_head();
    struct device_node *slave = NULL;

    int best_local_prio = -1;
    int best_remote_prio = -1;
    unsigned long best_rtt = ULONG_MAX;
    struct device_node *best_slave = NULL;
    struct remote_link *best_link = NULL;
    struct pathinfo *sel_path = NULL;

    rcu_read_lock();
    list_for_each_entry(slave, slave_list, lif.list) {
        if(slave->lif.prio < virt->max_dev_prio && can_use_device(slave, best_local_prio)) {
            struct remote_link *link;

            list_for_each_entry_rcu(link, &dest->links, rif.list) {
                if(link->rif.prio >= best_remote_prio && link->rif.prio < dest->max_link_prio) {
                    struct pathinfo *other = path_lookup_create(&virt->network, slave, link);

                    if(other && other != path) {
                        unsigned long rtt = pathinfo_est_rtt(other);

                        if(slave->lif.prio > best_local_prio || link->rif.prio > best_remote_prio) {
                            best_local_prio = slave->lif.prio;
                            best_remote_prio = link->rif.prio;
                            best_rtt = ULONG_MAX;
                        }

                        if(rtt < best_rtt) {
                            best_rtt = rtt;
                            best_slave = slave;
                            best_link = link;
                        }
                    }

                    if(other)
                        virt_path_put(other);
                }
            }
        }
    }

    if(best_link)
        sel_path = path_lookup_create(&virt->network, best_slave, best_link);

    rcu_read_unlock();

    return sel_path;
}

static int virt_finish_xor_packets(struct virt_priv *virt, struct pathinfo *path, struct xor_packet_buffer *buffer, struct sk_buff *skb)
{
    /* TODO: Figure out how to set these values. */
    const int headroom = 100;
    const int tailroom = 1500;

    struct tunhdr *tunhdr = (struct tunhdr *)skb->data;
    unsigned seq = ntohl(tunhdr->seq);
    int sent = 0;

    unsigned xor_seq = seq % buffer->rate;
    if(xor_seq == 0) {
        /* On the first packet of the group, allocate a buffer with enough
         * tailroom to hold an MTU-sized XORed packet. */
        struct tunhdr *xor_tunhdr;
        struct virt_skb_cb *skb_cb;

        if(buffer->skb)
            dev_kfree_skb(buffer->skb);

        buffer->skb = skb_copy_expand(skb, headroom, tailroom, GFP_ATOMIC);
        if(!buffer->skb)
            return sent;

        skb_cb = (struct virt_skb_cb *)buffer->skb->cb;
        skb_cb->flow = NULL; /* XOR packets should not retain reference to flow. */

        buffer->rate = buffer->next_rate;

        xor_tunhdr = (struct tunhdr *)buffer->skb->data;
        xor_tunhdr->flags |= TUN_FLAG_XOR_CODED;
        xor_tunhdr->xor_rate = buffer->rate;
    } else if(xor_seq == (buffer->rate - 1)) {
        /* On the last packet of the group, XOR the last packet, then send
         * out the coded packet. */
        if(buffer->skb) {
            xor_sk_buff(buffer->skb, skb, sizeof(struct tunhdr));
            virt_finish_tx(virt, buffer->skb, path);
            buffer->skb = NULL;
            sent++;
        }
    } else if(buffer->skb) {
        /* On any other packet, just XOR it. */
        xor_sk_buff(buffer->skb, skb, sizeof(struct tunhdr));
    }

    return sent;
}

static int virt_send_xor_packets(struct virt_priv *virt,
        struct sk_buff *skb, struct remote_node *dest, struct pathinfo *path)
{
    int sent = 0;

    if(path->xor_same_path.rate == 1) {
        struct sk_buff *copy = skb_copy(skb, GFP_ATOMIC);
        if(unlikely(!copy))
            goto out;

        path->xor_same_path.rate = path->xor_same_path.next_rate;

        virt_finish_tx(virt, copy, path);
        sent++;
    } else if(path->xor_same_path.rate > 1) {
        sent += virt_finish_xor_packets(virt, path, &path->xor_same_path, skb);
    } else {
        path->xor_same_path.rate = path->xor_same_path.next_rate;
    }

    if(path->xor_same_prio.rate == 1) {
        struct pathinfo *other = virt_select_same_prio(virt, dest, path);
        if(other) {
            struct sk_buff *copy = skb_copy(skb, GFP_ATOMIC);
            if(unlikely(!copy)) {
                virt_path_put(other);
                goto out;
            }

            path->xor_same_prio.rate = path->xor_same_prio.next_rate;

            virt_finish_tx(virt, copy, other);
            virt_path_put(other);
            sent++;
        }
    } else if(path->xor_same_prio.rate > 1) {
        sent += virt_finish_xor_packets(virt, path, &path->xor_same_prio, skb);
    } else {
        path->xor_same_prio.rate = path->xor_same_prio.next_rate;
    }

    if(path->xor_lower_prio.rate == 1) {
        struct pathinfo *other = virt_select_low_prio(virt, dest, path);
        if(other) {
            struct sk_buff *copy = skb_copy(skb, GFP_ATOMIC);
            if(unlikely(!copy)) {
                virt_path_put(other);
                goto out;
            }

            path->xor_lower_prio.rate = path->xor_lower_prio.next_rate;

            virt_finish_tx(virt, copy, other);
            virt_path_put(other);
            sent++;
        }
    } else if(path->xor_lower_prio.rate > 1) {
        sent += virt_finish_xor_packets(virt, path, &path->xor_lower_prio, skb);
    } else {
        path->xor_lower_prio.rate = path->xor_lower_prio.next_rate;
    }

out:
    return sent;
}

/*
 * Find a suitable path or paths for delivery and begin transmission.
 *
 * Returns 1 to indicate packet was sent (or dropped) or 0 to indicate the
 * packet was queued for later delivery.
 */
int virt_start_tx(struct virt_priv *virt, struct sk_buff *skb,
        struct remote_node *dest)
{
    struct virt_skb_cb *skb_cb = (struct virt_skb_cb *)skb->cb;
    struct flow_table_entry *flow = skb_cb->flow;

    long payload_len = skb->len - sizeof(struct tunhdr);

    if(flow->policy->action & POLICY_OP_DUPLICATE) {
        if(virt_send_duplicate(virt, skb, dest) <= 0)
            goto queue;
    } else if(flow->policy->action & POLICY_OP_MULTIPATH) {
        struct pathinfo *path;

        /* Send optional probe packet(s) on stalled paths. */
        send_probe_packet(virt, skb, dest);

        path = virt_select_multi_path(virt, flow, payload_len, dest);
        if(path) {
            virt_finish_tx(virt, skb, path);
            virt_path_put(path);
        } else {
            goto queue;
        }
    } else {
        struct pathinfo *path;

        /* Send optional probe packet(s) on stalled paths. */
        send_probe_packet(virt, skb, dest);

        path = virt_select_single_path(virt, flow, dest);
        if(path) {
            virt_send_xor_packets(virt, skb, dest, path);

            virt_finish_tx(virt, skb, path);
            virt_path_put(path);
        } else {
            goto queue;
        }
    }

    /* Update device statistics.  For the virtual interface, we only count the
     * packet once regardless of how many copies were sent. */
    virt->stats.tx_packets++;
    virt->stats.tx_bytes += payload_len;

    /* Release reference to the flow_table_entry now that skb has been
     * consumed. */
    flow_table_entry_put(flow);

    return 1;

queue:
    skb_queue_head(&dest->tx_queue, skb);

    return 0;
}

/*
 * Queue a packet for delivery via encapsulation to the destination node.  
 *
 * The pkt object is consumed.
 */
int virt_queue_tx(struct virt_priv *virt, struct packet *pkt, struct remote_node *dest)
{
    struct flow_table_entry *flow = pkt->ftable_entry;
    struct sk_buff *skb = pkt->skb;
    long payload_len = skb->len;

    struct virt_skb_cb *skb_cb = (struct virt_skb_cb *)skb->cb;
    skb_cb->virt = virt;
    skb_cb->flow = flow;
    
    /* Until the skb is dropped or sent to the device, it needs to hold a
     * reference to the flow_table_entry. */
    flow_table_entry_hold(flow);

    /* Add part of the tunnel header before freeing the packet structure. */
    virt_build_tunhdr(skb, flow, dest);

    flow->next_tx_seq++;
    dest->next_tx_seq++;

    /* Update flow statistics. */
    pkt->flow_stats->tx_packets++;
    pkt->flow_stats->tx_bytes += payload_len;

    if(flow_retx_enabled(flow->policy))
        flow_set_retx_skb(flow, skb);

    if(skb_queue_empty(&dest->tx_queue) && dest->link_count > 0) {
        virt_start_tx(virt, pkt->skb, dest);
    } else if(skb_queue_len(&dest->tx_queue) < dest->tx_queue_limit) {
        /* Add to tx_queue on the destination node and transmit later. */
        skb_queue_tail(&dest->tx_queue, skb);

        if(!timer_pending(&dest->tx_queue_timer) && dest->restart_timer) {
            unsigned long timeout = jiffies + virt_tx_queue_timer_jiffies();
            mod_timer(&dest->tx_queue_timer, timeout);
        }
    } else {
        virt->stats.tx_dropped++;
        flow_table_entry_put(skb_cb->flow);
        dev_kfree_skb(pkt->skb);
    }

    virt_free_packet(pkt);

    return 0;
}

void tx_queue_timer_fn(unsigned long arg)
{
    struct remote_node *node = (struct remote_node *)arg;

    while(skb_queue_len(&node->tx_queue) > 0) {
        struct sk_buff *skb;

        skb = skb_dequeue(&node->tx_queue);
        if(likely(skb)) {
            struct virt_skb_cb *skb_cb = (struct virt_skb_cb *)skb->cb;
            if(virt_start_tx(skb_cb->virt, skb, node) <= 0)
                break;
        }
    }

    if(skb_queue_len(&node->tx_queue) > 0 && node->restart_timer) {
        unsigned long timeout = jiffies + virt_tx_queue_timer_jiffies();
        mod_timer(&node->tx_queue_timer, timeout);
    }
}


