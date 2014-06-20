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

#ifndef _VIRT_H__
#define _VIRT_H__

#include <linux/netdevice.h>

/*
 * Define SAFE_SHUTDOWN to skip buggy cleanup code with the drawback that
 * memory will be leaked.
 */
#define SAFE_SHUTDOWN 

/* Bits used in tunnel header to specify path history of flow. */
#define VIRT_PATH_HIST_BITS 8

#include "virtPolicy.h"
#include "virtFlowTable.h"
#include "virtNetwork.h"

// TODO: remove once default policy stuff is in place
#define USE_TUNNEL 0

#define INGRESS 0
#define EGRESS 1

#define VIRT_DEV_NAME "virt%d"
#define VIRT_DEV_PREFIX "virt"

struct hlist_head;
struct hash_entry;

/*
 * Structures
 */
struct virt_packet
{
    struct virt_packet *next;
    struct net_device *dev;
    int datalen;
    u8 data[ETH_DATA_LEN];
};

// TODO: this structure needs to be cleaned up
struct virt_priv
{
    struct net_device_stats stats;
    __be32 ip4;

    int status;
    struct virt_packet *ppool;
    struct virt_packet *rx_queue;  /* List of incoming packets */
    int rx_int_enabled;
    int tx_packetlen;
    u8 *tx_packetdata;
    struct sk_buff *skb;
    spinlock_t lock;
    struct napi_struct napi;

    int max_dev_prio;

    struct list_head vroute_table;

    struct policy_head policy_list_flow_egress;
    struct policy_head policy_list_flow_ingress;
    struct policy_head policy_list_app_egress;
    struct policy_head policy_list_app_ingress;

    struct policy_entry policy_default_egress;
    struct policy_entry policy_default_ingress;

    struct proc_dir_entry *proc_ftable;
    struct proc_dir_entry *proc_paths;

    struct proc_dir_entry *proc_remote;
    struct proc_dir_entry *proc_remote_nodes;
    struct proc_dir_entry *proc_remote_links;
    struct proc_dir_entry *proc_remote_vroutes;
    struct proc_dir_entry *proc_reorder_stats;

    struct proc_dir_entry *proc_mem_stats;

    struct flow_table flow_table;

    /* Stores information about other WiRover nodes and paths to them. */
    struct virt_network network;
};

struct packet {
    struct net_device *master;

    struct sk_buff *skb;
    struct hdr_ptrs *hdr_ptrs;

    /* Set when decapsulating tunnel packets. */
    u32 tunnel_seq;
    long reorder_delay;
    
    struct in_addr src_node;

    int tbl_hit;
    struct flow_tuple *key;
    struct policy_entry *policy;
    //struct flow_params *params;
    struct flow_stats *flow_stats;
    struct flow_table_entry *ftable_entry;
};



/*
 * Function Prototypes
 */

void virt_setup_pool(struct net_device *dev);
void virt_teardown_pool(struct net_device *dev);
struct virt_packet *virt_get_tx_buffer(struct net_device *dev);
void virt_release_buffer(struct virt_packet *pkt);
void virt_enqueue_buf(struct net_device *dev, struct virt_packet *pkt);
struct virt_packet *virt_dequeue_buf(struct net_device *dev);

void virt_free_packet(struct packet *pkt);

int is_virt_interface(const char *name);

unsigned long get_flow_table_timeout_jiffies(void);
unsigned long get_resync_timeout_jiffies(void);
unsigned short virt_tunnel_source_port(void);
unsigned virt_tx_queue_limit(void);
unsigned long get_min_reassign_delay_jiffies(void);

unsigned long virt_stall_threshold_bytes(void);
unsigned long virt_stall_threshold_packets(void);
unsigned virt_probe_interval_jiffies(void);
unsigned long virt_tx_queue_timer_jiffies(void);
unsigned long virt_rx_retain_time_jiffies(void);
unsigned virt_reorder_queue_size(void);

extern bool virt_deliver_late_packets;
extern long virt_max_reorder_delay;

#endif //_VIRT_H__
