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
#include <linux/kernel.h> /* printk() */
#include <linux/errno.h>  /* error codes */

#include <linux/in.h>
#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/inetdevice.h>  /* struct in_device, __in_dev_get */
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/udp.h>         /* struct udphdr */
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <net/arp.h>  //arp_create

#include <linux/in6.h>
#include <asm/checksum.h>

#include "virt.h"
#include "virtDebug.h"
#include "virtParse.h"
#include "virtDevList.h"




/*
 * This function will parse TCP traffic
 */
static int parse_tcp_header(struct sk_buff *skb, struct flow_tuple *key, struct hdr_ptrs *ptrs, int direction)
{
    int rc = 0;
    struct tcphdr *tcp = NULL;

    //VIRT_DBG("got a tcp packet\n");
    // had pointer issues with tcp_hdr()
    //tcp = tcp_hdr(skb);
    //tcp = (struct tcphdr *)(skb->data + ETH_HLEN + (flow->ip_ptr->ihl * 4));
    tcp = (struct tcphdr *)((void *)ptrs->ip_ptr + (ptrs->ip_ptr->ihl * 4));
    ptrs->tcp_ptr = tcp;

    if( direction == EGRESS ) {
        key->sPort = tcp->source;
        key->dPort = tcp->dest;
    } else {
        key->sPort = tcp->dest;
        key->dPort = tcp->source;
    }

    return rc;
}

/*
 * This function will parse UDP traffic
 */
static int parse_udp_header(struct sk_buff *skb, struct flow_tuple *key, struct hdr_ptrs *ptrs, int direction)
{
    int rc = 0;
    struct udphdr *udp = NULL;

    //VIRT_DBG("got an udp packet\n");
    //udp = udp_hdr(skb);
    //udp = (struct udphdr *)(ip + (ip->ihl * 4));
    //udp = (struct udphdr *)(skb->data + ETH_HLEN + (flow->ip_ptr->ihl * 4));
    udp = (struct udphdr *)((void *)ptrs->ip_ptr + (ptrs->ip_ptr->ihl * 4));
    ptrs->udp_ptr = udp;

    if( direction == EGRESS ) {
        key->sPort = udp->source;
        key->dPort = udp->dest;
    } else {
        key->sPort = udp->dest;
        key->dPort = udp->source;
    }

    return rc;
}

/*
 * Parse ICMP packets.
 */
static int parse_icmp_header(struct sk_buff *skb, struct flow_tuple *key, struct hdr_ptrs *ptrs, int direction)
{
    struct icmphdr *icmp = (struct icmphdr *)(skb_network_header(skb) + ptrs->ip_ptr->ihl * 4);

    if(icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
        key->sPort = icmp->un.echo.id;
        key->dPort = icmp->un.echo.id;
    } else {
        key->sPort = 0;
        key->dPort = 0;
    }

    return 0;
}

/*
 * This function will handle egress IP traffic
 * and call the appropriate TCP or UDP subfunction
 *
 * This function should not rely on a pointer to the 
 * ethernet header since PPP devices don't use ethernet.
 */
static int parse_ip_header(struct sk_buff *skb, struct flow_tuple *key, struct hdr_ptrs *ptrs, int direction)
{
    int rc = 0;
    struct iphdr  *ip  = NULL;

    //VIRT_DBG("got an ip packet\n");
    ip = ip_hdr(skb);
    ptrs->ip_ptr = ip;

    // TODO: check ip->version == 4, or ip->version == 6

    if( direction == EGRESS ) {
        key->sAddr = ip->saddr;
        key->dAddr = ip->daddr;
    } else {
        key->sAddr = ip->daddr;
        key->dAddr = ip->saddr;
    }
    key->proto = (ip->protocol & 0x00ff); //TODO: proto is only an 8 bit value
    //VIRT_DBG("packet source: 0x%x dest: 0x%x proto 0x%x\n", ntohl(key->sAddr), ntohl(key->dAddr), key->proto);

    // get flow values for transport layer
    switch(ip->protocol) {
    case IPPROTO_TCP:
        rc = parse_tcp_header(skb, key, ptrs, direction);
        break;
    case IPPROTO_UDP:
        rc = parse_udp_header(skb, key, ptrs, direction);
        break;
    case IPPROTO_ICMP:
        rc = parse_icmp_header(skb, key, ptrs, direction);
        break;
    default:
        key->sPort = 0;
        key->dPort = 0;
    }

    return rc;
}

/*
 * This function will handle egress ARP traffic
 */
static int parse_arp_header(struct sk_buff *skb, struct flow_tuple *key, struct hdr_ptrs *ptrs, int direction)
{
    int rc = 0;
    //int offset = 0;

    char sender_hw[ETH_ALEN];
    __be32 sender_ip, target_ip;

    struct ethhdr *eth      = NULL;
    struct arphdr *arp      = NULL;
    char          *arp_data = NULL;
   
    eth = ptrs->eth_ptr;

    arp = arp_hdr(skb);
    //arp_data = ((char *)arp + sizeof(struct arphdr));
    VIRT_DBG("got and arp packet with ar_hrd: 0x%x ar_pro: 0x%x r_op: 0x%x\n", ntohs(arp->ar_hrd), ntohs(arp->ar_pro), ntohs(arp->ar_op));

    if( ntohs(arp->ar_op) == ARPOP_REQUEST) {
        arp_data = ((char *)arp + sizeof(struct arphdr));

        memcpy(&sender_hw, arp_data, arp->ar_hln);
        arp_data += arp->ar_hln;
        memcpy(&sender_ip, arp_data, arp->ar_pln);
        arp_data += arp->ar_pln;
        arp_data += arp->ar_hln; //skip target mac cause it is blank
        memcpy(&target_ip, arp_data, arp->ar_pln);
        VIRT_DBG("sending a arp reply to: 0x%x sender: 0x%x sender_hw: 0x%02x:%02x:%02x:%02x:%02x:%02x\n", target_ip, sender_ip,
                sender_hw[0], sender_hw[1], sender_hw[2], sender_hw[3], sender_hw[4], sender_hw[5]);

        //TODO: break this arp reply to a separate function
        // just reply to the ARP request to make the kernel happy
        arp->ar_op = htons(ARPOP_REPLY);
        arp_data = ((char *)arp + sizeof(struct arphdr));
        //memcpy(arp_data, master->dev->dev_addr, arp->ar_hln);
        arp_data += arp->ar_hln;
        memcpy(arp_data, &target_ip, arp->ar_pln);
        arp_data += arp->ar_pln;
        memcpy(arp_data, &sender_hw, arp->ar_hln);
        arp_data += arp->ar_hln;
        memcpy(arp_data, &sender_ip, arp->ar_pln);
    }

    return rc;
}



/*
 * This function will handle egress ethernet traffic
 */
static int parse_eth_header(struct sk_buff *skb, struct flow_tuple *key, struct hdr_ptrs *ptrs, int direction)
{
    int rc = 0;
    struct ethhdr *eth = NULL;

    eth = ptrs->eth_ptr;

    // TODO: do we use these values? Can we just use the header pointers?
    // store mac addresses in flow_info struct
    if( direction == EGRESS ) {
        memcpy(key->s_mac, eth->h_source, ETH_ALEN);
        memcpy(key->d_mac, eth->h_dest, ETH_ALEN);
    } else {
        memcpy(key->s_mac, eth->h_dest, ETH_ALEN);
        memcpy(key->d_mac, eth->h_source, ETH_ALEN);
    }
    key->net_proto = eth->h_proto;

    // handle the network layer
    if( ntohs(eth->h_proto) == ETH_P_IP) {
        rc = parse_ip_header(skb, key, ptrs, direction);
    } else if(ntohs(eth->h_proto) == ETH_P_ARP) {
        rc = parse_arp_header(skb, key, ptrs, direction);
    } else {
        //VIRT_DBG("received a non-ip non-arp packet of type: 0x%x\n", ntohs(eth->h_proto));
        //return virt_free_packet(pkt);
    }

    return rc;
}


int virt_parse_egress_pkt(struct packet *pkt)
{
    // TODO: for some reason eth_hdr(skb) doesn't work to grab a pointer
    //pkt->hdr_ptrs->eth_ptr = (struct ethhdr *)pkt->skb->data;
    pkt->hdr_ptrs->eth_ptr = 0;

    // since we are a ethernet driver we know there is an ethernet header to parse
    //return parse_eth_header(pkt->skb, pkt->key, pkt->hdr_ptrs, EGRESS);

    // Egress packets have no additional headers above the IP header.
    return parse_ip_header(pkt->skb, pkt->key, pkt->hdr_ptrs, EGRESS);
}

int virt_parse_ingress_pkt(struct packet *pkt)
{
    int rtn = 0;


    if( pkt->skb->dev->type == ARPHRD_ETHER ) {
        pkt->hdr_ptrs->eth_ptr = eth_hdr(pkt->skb);

        rtn = parse_eth_header(pkt->skb, pkt->key, pkt->hdr_ptrs, INGRESS);
    } else if( pkt->skb->dev->type == ARPHRD_PPP ) {
        rtn = parse_ip_header(pkt->skb, pkt->key, pkt->hdr_ptrs, INGRESS);
    } else {
        VIRT_DBG("trying to parse unknown device type: %d\n", pkt->skb->dev->type);
        rtn = -1;
    }

    return rtn;
}



