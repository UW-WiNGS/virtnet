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

#ifndef _VIRT_POLICY_H__
#define _VIRT_POLICY_H__

#define POLICY_MAX_APP_NAME 16
#define POLICY_MAX_PROC_STR 256

#include <linux/if.h>
#include <linux/list.h>

struct packet;
struct virt_alg;
struct flow_tuple;

struct policy_type_flow {
    // Proto type policy
    //int direction; // ingress vs egress
    __u16 net_proto;
    __u32 dst_addr; // todo change to ip_addr
    __u32 src_addr; // todo change to ip_addr
    __u32 dst_netmask;
    __u32 src_netmask;
    __u16 proto;
    __u16 dst_port;
    __u16 src_port;
};

struct policy_type_app {
    char app_name[POLICY_MAX_APP_NAME];
};

struct policy_type_dev {
    char dev_name[IFNAMSIZ];
};


/*
 * Struct used by packets and cache.
 */
struct flow_policy {
    __u32 action;
    //int params_valid;
    //struct policy_params params;
    __s32 algo_type;
};

struct policy_head {
    spinlock_t lock;
    struct list_head list;
};

/* Statistics for packets matching a policy. */
struct policy_stats {
    unsigned long   rx_packets;
    unsigned long   tx_packets;
    unsigned long   rx_bytes;
    unsigned long   tx_bytes;
};

/*
 * Struct used between procfs and policy framework to add/remove/etc.
 */
struct policy_entry {
    struct list_head list;

    //__s32 command;
    __u32 table;
    __s32 type;

    struct policy_type_flow  flow;
    struct policy_type_app   app;
    struct policy_type_dev   dev;

    __u32 action; // policy mask

    __s32 algo_type;

    struct virt_alg *alg;

    struct policy_stats stats;

    atomic_t refcnt;
    struct rcu_head rcu;
};

struct virt_priv;

void policy_list_init(struct policy_head *head);
void policy_list_add(struct policy_head *head, struct policy_entry *entry, int row);
void policy_list_flush(struct policy_head *head);
void policy_list_destroy(struct policy_head *head);
void policy_hold(struct policy_entry *policy);
void policy_put(struct policy_entry *policy);

void virt_policy_setup(struct virt_priv *virt);
void virt_policy_cleanup(struct virt_priv *virt);

struct policy_entry *policy_lookup_flow(struct policy_head *head, const struct flow_tuple *key);
struct policy_entry *virt_policy_lookup(struct virt_priv *virt, struct packet *pkt, int table);

int virt_policy(struct virt_priv *virt, struct policy_entry *policy, int command, int row);

#endif //_VIRT_POLICY_H__
