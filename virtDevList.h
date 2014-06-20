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

#ifndef _VIRT_DEV_LIST_H__
#define _VIRT_DEV_LIST_H__

#include <linux/in6.h>
#include <linux/if_ether.h>

#include "virtStats.h" //need link_stats structure
#include "virtInterface.h"

#define NUM_DEVS 1

/* Device flags. */
#define DEVICE_NO_TX    0x00000001

struct device_node
{
    struct net_device *master;

    struct interface   lif;

    struct net_device *dev;
    struct link_stats stats;
    
    u8 next_hop_addr[ETH_ALEN]; 

    __be32          gw_ip4;
    struct in6_addr gw_ip6;

    u32 flags;

    atomic_t refcnt;
};

struct in_addr;

int get_num_slaves(void);
struct list_head *get_slave_list_head(void);

int virt_add_slave(struct net_device *dev, struct net_device *slave_dev);
int virt_del_slave(struct net_device *dev, struct net_device *slave_dev);

int slave_list_destroy(struct net_device *master);
struct device_node *slave_get_by_name(const char *name);
struct device_node *slave_get_by_ifindex(int ifindex);
struct device_node *slave_get_by_addr(const struct in_addr *addr);
struct device_node *slave_list_lookup(struct net_device *net_dev);

void device_node_hold(struct device_node *dev);
void device_node_put(struct device_node *dev);

int find_max_dev_prio(void);

#endif //_VIRT_DEV_LIST_H__

