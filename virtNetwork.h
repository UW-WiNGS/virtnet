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

#ifndef _VIRT_NETWORK_H_
#define _VIRT_NETWORK_H_

#include <linux/list.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/skbuff.h>

#include "virtInterface.h"
#include "virtReorder.h"
#include "virtHashTable.h"

// remote node/link flags
#define RN_DELETION_FLAG    0x01

#define TX_QUEUE_LIMIT 100

struct virt_network {
    struct virt_hash_table node_table;
    struct virt_hash_table link_table;
    struct virt_hash_table path_table;
};

struct remote_link {
    struct interface rif;

    int index;

    struct in6_addr pub_ip6;
    
    u32 flags;

    struct remote_node* node;

    struct hlist_node hlist;

    atomic_t refcnt;
    struct rcu_head rcu;

    /* Parent data structure. */
    struct virt_network *network;
};

struct remote_node {
    int index;

    struct in_addr priv_ip;

    u32 link_count;
    u32 flags;

    struct list_head links;
    spinlock_t links_lock;

    int next_link_index;

    int max_link_prio;

    u32 next_tx_seq;
    u32 next_rx_seq;

    /* Queue packets that need to be sent to this node. */
    struct sk_buff_head tx_queue;
    unsigned tx_queue_limit;
    struct timer_list tx_queue_timer;
    bool restart_timer;

    struct reorder_head reorder_head;

    struct list_head stalled_paths;
    spinlock_t stalled_paths_lock;
    int stalled_paths_len;

    struct hlist_node hlist;
    
    atomic_t refcnt;
    struct rcu_head rcu;
    
    /* Parent data structure. */
    struct virt_network *network;
};

struct remote_node *alloc_remote_node(struct net_device *master_dev);
void add_remote_node(struct virt_network *net, struct remote_node *node);
void delete_remote_node(struct virt_network *net, struct remote_node *node);
void remote_node_hold(struct remote_node *node);
void remote_node_put(struct remote_node *node);

struct remote_link *alloc_remote_link(void);
void add_remote_link(struct virt_network *net, struct remote_node *node, 
        struct remote_link *link);
void delete_remote_link(struct virt_network *net, struct remote_link *link);
void remote_link_hold(struct remote_link *link);
void remote_link_put(struct remote_link *link);

struct remote_node *find_remote_node_by_ip(struct virt_network *net, 
        const struct in_addr *priv_ip);
struct remote_link __deprecated *find_remote_link_by_ip(struct virt_network *net, 
        const struct in_addr *pub_ip);
struct remote_link *find_remote_link_by_addr(struct virt_network *net,
        const struct in_addr *addr, __be16 port);
struct remote_link *find_remote_link_by_indices(struct virt_network *net,
        int rnode_index, int rlink_index);

int find_max_remote_link_prio(const struct remote_node *node);

int dump_remote_node_list(struct seq_file *s, void *p);
int dump_remote_link_list(struct seq_file *s, void *p);
int dump_reorder_stats(struct seq_file *s, void *p);

void remote_node_list_destroy(struct virt_network *net);

#endif //_VIRT_NETWORK_H_

