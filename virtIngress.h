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

#ifndef _VIRT_INGRESS_H__
#define _VIRT_INGRESS_H__

/* Possible actions to take on decapsulated packets. */
#define TUNNEL_FORWARD 0
#define TUNNEL_ACCEPT  1
#define TUNNEL_DROP    2
#define TUNNEL_STOLEN  3

struct net_device;
struct sk_buff;

void virt_forward_skb(struct net_device *dev, struct sk_buff *skb);

unsigned int recv_ip(unsigned int hooknum, struct sk_buff *skb,
                             const struct net_device *in, const struct net_device *out,
                             int (*okfn)(struct sk_buff *));
unsigned int recv_arp(unsigned int hooknum, struct sk_buff *skb,
                              const struct net_device *in, const struct net_device *out,
                              int (*okfn)(struct sk_buff *));

#endif //_VIRT_INGRESS_H__
