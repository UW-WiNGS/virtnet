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
#include <linux/time.h>

#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/udp.h>         /* struct udphdr */
#include <linux/skbuff.h>

#include "virt.h"
#include "virtDebug.h"
#include "virtParse.h"
#include "virtPolicy.h"
#include "virtPolicyTypes.h"
#include "virtDevList.h"
#include "virtEgressLookup.h"
#include "virtFlowTable.h"
#include "virtSelectInterface.h"
#include "virtNAT.h"


// GLOBALS
#define STATE_INIT          0
#define STATE_SYN_SENT      1
#define STATE_SYN_RECV      2
#define STATE_ESTABLISHED   3
#define STATE_FIN_SENT_1    4
#define STATE_FIN_WAIT_1    5
#define STATE_FIN_SENT_2    6
#define STATE_CLOSED        7
#define STATE_DNS_REQUEST  11
#define STATE_DNS_RESPONSE 12
#define STATE_UNKNOWN      13


// FUNCTION PROTOTYPES
static struct flow_table_entry *alloc_init_table_entry(struct packet *pkt);
static int track_connection(struct flow_table_entry *entry, struct packet *pkt);


static unsigned long next_flow_id = 0;


/*
 * This function is called from virt_tx after the packet has been parsed.
 * The function will lookup up and fill in the routing info in the packet
 * structure.
 */
int virt_egress_lookup_flow(struct virt_priv *virt, struct packet *pkt)
{
    struct flow_table_entry *entry = NULL;
    unsigned long now = jiffies;

    if(!pkt)
        return -1;

    entry = flow_table_lookup(&virt->flow_table, pkt->key);

    VIRT_DBG("egress %pI4:%hu -> %pI4:%hu %s\n",
            &pkt->key->sAddr,
            ntohs(pkt->key->sPort),
            &pkt->key->dAddr,
            ntohs(pkt->key->dPort),
            entry ? "found" : "not found");

    // if new flow build entry
    if( entry == NULL ) {

        // if table miss then we need to lookup the policy

        entry = alloc_init_table_entry(pkt);
        if( !entry )
            return -ENOMEM;

        goto setup_defaults;
    } else {
        pkt->tbl_hit = 1; // ok to free pkt->key

        // set info in packet structure
        //pkt->actions = entry->actions;
        //pkt->policy = entry->policy;
        pkt->flow_stats = entry->flow_stats;
        pkt->ftable_entry = entry;

        entry->last_touched = now;
    }

    // Copy the flow's policy mask to the packet
    pkt->policy = entry->policy;

    // track connection state
    track_connection(entry, pkt);

    return 0;

setup_defaults:
    //entry->key = pkt->key; // don't free pkt->key
    
    pkt->ftable_entry = entry;

    /* Have connections that originate locally use the default tunnel port.
     * This only affects ENCAP flows. */
    entry->rx_port = htons(virt_tunnel_source_port());

    // lookup policy
    entry->policy = virt_policy_lookup(virt, pkt, EGRESS);
    pkt->policy = entry->policy;
    if(entry->policy) {
        entry->action = entry->policy->action;
    }
    
    entry->last_touched = now;

    //pkt->actions->flow_table_entry = (void *)entry;
    pkt->tbl_hit = 1;
    flow_table_add(&virt->flow_table, entry);

    // track connection state
    track_connection(entry, pkt);

    return 0;
}

// TODO: Why is this in virtEgressLookup.c?
int virt_ingress_lookup_flow(struct virt_priv *virt, struct packet *pkt)
{
    struct flow_table_entry *entry = NULL;
    unsigned long now = jiffies;

    // hash table lookup
    entry = flow_table_lookup(&virt->flow_table, pkt->key);

    // packet might have been NAT'ed
    if( entry == NULL ) {
        struct nat_entry *nat = nat_table_ingress_lookup(pkt);
        if( nat != NULL ) {
            VIRT_DBG("ingress flow was nated\n");
            pkt->key->sAddr = nat->oldip;
            pkt->key->sPort = nat->oldport;
            // lookup the flow again
            entry = flow_table_lookup(&virt->flow_table, pkt->key);
            VIRT_DBG("ingress (2) %pI4:%hu -> %pI4:%hu %s\n",
                    &pkt->key->sAddr,
                    ntohs(pkt->key->sPort),
                    &pkt->key->dAddr,
                    ntohs(pkt->key->dPort),
                    entry ? "found" : "not found");
            // update flow info
        }
    }

    // if new flow build entry
    if( entry == NULL ) {
        entry = alloc_init_table_entry(pkt);
        if( !entry )
            return -ENOMEM;

        // if table miss then we need to lookup the policy
        goto setup_defaults;
    } else {
        pkt->tbl_hit = 1; // ok to free pkt->key

        // set info in packet structure
        //pkt->actions = entry->actions;
        pkt->policy = entry->policy;
        pkt->flow_stats = entry->flow_stats;
        pkt->ftable_entry = entry;

        entry->last_touched = now;
    }

    // track connection state
    track_connection(entry, pkt);

    return 0;

setup_defaults:
    pkt->ftable_entry = entry;

    entry->rx_port = pkt->key->sPort;

    // lookup policy
    entry->policy = virt_policy_lookup(virt, pkt, INGRESS);
    pkt->policy = entry->policy;
    if(entry->policy) {
        entry->action = entry->policy->action;
    }

    entry->last_touched = now;

    //pkt->actions->flow_table_entry = (void *)entry;
    pkt->tbl_hit = 1;
    flow_table_add(&virt->flow_table, entry);

    // track connection state
    track_connection(entry, pkt);

    return 0;
}

static int track_udp_connection(struct flow_table_entry *entry, struct packet *pkt)
{
    // handle dns

    return 0;
}


/*
 * This function tracks the state of a TCP connection. Each state name reflects
 * the state to which the tcp connection will be at the next packet.
 */
static int track_tcp_connection(struct flow_table_entry *entry, struct packet *pkt)
{
    struct tcphdr *tcp = pkt->hdr_ptrs->tcp_ptr;

    // implement TCP state table
    switch( entry->state ) {
    case STATE_INIT:
        if( tcp->syn ) {
            entry->state = STATE_SYN_SENT;
        } else {
            entry->state = STATE_UNKNOWN;
        }
        break;
    case STATE_SYN_SENT:
        if( tcp->rst ) {
            entry->state = STATE_CLOSED;
        } else if ( (tcp->syn) && (tcp->ack) ) {
            entry->state = STATE_SYN_RECV;
        } else {
            entry->state = STATE_UNKNOWN;
        }
        break;
    case STATE_SYN_RECV:
        if( tcp->rst ) {
            entry->state = STATE_CLOSED;
        } else if ( tcp->ack ) {
            entry->state = STATE_ESTABLISHED;
        } else {
            entry->state = STATE_UNKNOWN;
        }
        break;
    case STATE_ESTABLISHED:
        if( tcp->rst ) {
            entry->state = STATE_CLOSED;
        } else if( tcp->fin ) {
            entry->state = STATE_FIN_SENT_1;
        } else {
            entry->state = STATE_UNKNOWN;
        }
        break;
    case STATE_FIN_SENT_1:
        if( tcp->rst ) {
            entry->state = STATE_CLOSED;
        } else if( (tcp->fin) && (tcp->ack) ) {
            entry->state = STATE_FIN_SENT_2;
        } else if( tcp->ack ) {
            entry->state = STATE_FIN_WAIT_1;
        } else {
            entry->state = STATE_UNKNOWN;
        }
    case STATE_FIN_WAIT_1:
        if( tcp->rst ) {
            entry->state = STATE_CLOSED;
        } else if( tcp->fin ) {
            entry->state = STATE_FIN_SENT_2;
        } else {
            entry->state = STATE_UNKNOWN;
        }
        break;
    case STATE_FIN_SENT_2:
        if( tcp->ack ) {
            entry->state = STATE_CLOSED;
        } else {
            entry->state = STATE_UNKNOWN;
        }
        break;
    case STATE_CLOSED:
        if( tcp->ack ) {
            entry->state = STATE_CLOSED;
        } else {
            entry->state = STATE_UNKNOWN;
        }
        break;
    default:
        break;
    }

    return 0;
}

static int track_other_connection(struct flow_table_entry *entry, struct packet *pkt)
{
    // ping and arp probably don't need to be stored so have some
    // default actions/operations for such protocols

    return 0;
}

static int track_connection(struct flow_table_entry *entry, struct packet *pkt)
{
    int rtn = 0;
    struct iphdr *ip = (struct iphdr *)pkt->hdr_ptrs->ip_ptr;

    if( !ip )
        return rtn; //may not be an ip packet (i.e., arp)

    if( ip->protocol == IPPROTO_TCP ) {
        rtn = track_tcp_connection(entry, pkt);
    } else if( ip->protocol == IPPROTO_UDP ) {
        rtn = track_udp_connection(entry, pkt);
    } else {
        rtn = track_other_connection(entry, pkt);
    }

    return rtn;
}

/*
 * This function will allocate and initialize a new hash entry for a given
 * flow.
 */
static struct flow_table_entry *alloc_init_table_entry(struct packet *pkt)
{
    struct flow_table_entry *entry;
    struct virt_priv *virt = netdev_priv(pkt->master);

    entry = alloc_flow_table_entry();
    if(!entry)
        return NULL;

    entry->network = &virt->network;

    memcpy(entry->key, pkt->key, sizeof(struct flow_tuple)); // not need with tbl_hit flag

    entry->flow_stats->flow_id = next_flow_id++;

    //pkt->actions    = entry->actions;
    pkt->flow_stats = entry->flow_stats;

    return entry;
}

