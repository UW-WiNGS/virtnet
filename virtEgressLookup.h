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

#ifndef _VIRT_EGRESS_LOOKUP_H__
#define _VIRT_EGRESS_LOOKUP_H__

#include "virtPassive.h"

#define CONST_ALGO_NUM_LINKS 3

struct timeval;
struct packet;

struct flow_stats
{
    unsigned long rx_bytes;
    unsigned long tx_bytes;
    unsigned long rx_packets;
    unsigned long tx_packets;

    int flow_id;

    /* Last path used. */
    struct in_addr  local_addr;
    struct in_addr  remote_addr;
    __be16          local_port;
    __be16          remote_port;

    unsigned long   last_send_jiffies;
    unsigned long   last_path_change;

    /* Local device index for last packet send and received. */
    int last_rx_dev;
    int last_tx_dev;
};

struct virt_priv;

int virt_egress_handle_link_failure(struct packet *pkt);
int virt_egress_lookup_flow(struct virt_priv *virt, struct packet *pkt);
int virt_ingress_lookup_flow(struct virt_priv *virt, struct packet *pkt);
void virt_flush_table_entry(struct packet *pkt);


#endif //_VIRT_EGRESS_LOOKUP_H__
