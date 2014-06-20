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

#ifndef _VIRT_EGRESS_H__
#define _VIRT_EGRESS_H__

struct virt_priv;
struct device_node;
struct remote_node;
struct remote_link;
struct packet;

int virt_try_send_queued(struct virt_priv *virt, struct device_node *slave, 
        struct remote_link *link);
int virt_send_ack(struct virt_priv *virt, struct device_node *slave,
        struct remote_link *link);

int virt_tx(struct sk_buff *skb, struct net_device *dev);
void virt_tx_timeout (struct net_device *dev);

unsigned int send_arp(unsigned int hooknum, struct sk_buff *skb,
                              const struct net_device *in, const struct net_device *out,
                              int (*okfn)(struct sk_buff *));

int virt_start_tx(struct virt_priv *virt, struct sk_buff *skb, struct remote_node *dest);
int virt_queue_tx(struct virt_priv *virt, struct packet *pkt, struct remote_node *dest);
void tx_queue_timer_fn(unsigned long arg);

#endif //_VIRT_EGRESS_H__
