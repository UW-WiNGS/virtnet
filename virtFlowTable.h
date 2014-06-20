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

#ifndef _VIRT_FLOW_TABLE_H__
#define _VIRT_FLOW_TABLE_H__

#include <linux/spinlock.h>
#include <linux/timer.h>

#include "virtReorder.h"
#include "virtRetransmission.h"

/*
 * The flow table stores state for flows traversing the virt interface.
 * Entries are purged from the flow table when the connection ends (FIN/RST for
 * TCP) or after a period of inactivity specified by the flow_table_timeout
 * parameter.  Inactive flows are purged by calling flow_table_clean
 * periodically.
 *
 * Reading the table must be done within rcu_read_lock/rcu_read_unlock.  RCU
 * allows for multiple simultaneous readers as well as a single writer if its
 * changes are carefully controlled.
 *
 * Changes to the table's structure (add/remove) must be done within
 * spin_lock_bh/spin_unlock_bh.  Each linked list has an independent spin lock,
 * so that adding a new entry only requires locking its associated list and not
 * the whole table.
 *
 * We are using spin_lock_bh because we anticipate allowing changes to the flow
 * table from user space.
 */

struct flow_table_head {
    spinlock_t lock;
    struct hlist_head list;
};

struct flow_table {
    struct flow_table_head *head;

    unsigned bits;
    unsigned size;
    
    /* Last time we flushed stale flows from the table, in jiffies. */
    unsigned long last_flush;

    struct timer_list timer;
    spinlock_t timer_lock;
    bool restart_timer;
};

struct virt_network;

/**
 * struct flow_table_entry
 * @rx_port: Destination port of arriving packets, used as source of replies
 */
struct flow_table_entry {
    struct hlist_node hlist;
    struct flow_tuple *key;

    int state;

    /* Updated on ingress and egress lookups, time in jiffies. */
    unsigned long last_touched;

    /* Sequence numbers used for reordering / duplicate suppression for tunnel
     * packets. */
    u32 next_tx_seq;
    u32 last_rx_seq;
    unsigned long rx_bitmap;

    __be16 rx_port;

    u32 action;
    //struct flow_actions *actions;
    struct policy_entry *policy;
    struct flow_stats *flow_stats;
    struct nat_entry *nat;

    struct remote_node *rnode;

    struct virt_retx retx;

    atomic_t refcnt;
    struct rcu_head rcu;

    /* Used to lookup path information. */
    struct virt_network *network;
};

int init_flow_table(struct flow_table *ftable, unsigned bits);
struct flow_table_entry *alloc_flow_table_entry(void);
int flow_table_add(struct flow_table *ftable, struct flow_table_entry *entry);
struct flow_table_entry *flow_table_lookup(struct flow_table *ftable, struct flow_tuple *key);
int flow_table_remove(struct flow_table *ftable, struct flow_table_entry *entry);
void flow_table_destroy(struct flow_table *ftable);
void flow_table_clean(struct flow_table *ftable);
void flow_table_entry_hold(struct flow_table_entry *entry);
void flow_table_entry_put(struct flow_table_entry *entry);

struct seq_file;
void dump_flow_table(struct seq_file *s, struct virt_priv *virt);

void flow_table_kill_retx(struct flow_table *ftable);

#endif //_VIRT_FLOW_TABLE_H__

