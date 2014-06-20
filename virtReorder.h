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

#ifndef _VIRT_REORDER_H__
#define _VIRT_REORDER_H__

#define REORDER_ACCEPT 0
#define REORDER_STOLEN 1
#define REORDER_DROP   -1

struct sk_buff;
struct flow_table_entry;
struct packet;
struct virt_priv;

struct xor_entry {
    struct sk_buff *skb;

    u32 seq;
    u8 coding_rate;
    long drop_time;

    struct list_head list;
};

struct reorder_entry {
    struct sk_buff *skb;

    bool delivered;
    long store_time;
    long release_time;

    struct list_head list;
};

/* 
 * forwarded = in_order + early + late + recovered
 * received = dropped + in_order + early + late
 */
struct reorder_stats {
    long forwarded;
    long received;
    long dropped;
    long in_order;
    long early;
    long late;
    long recovered;

    /* delays stored in jiffies */
    long max_delay;
    long avg_delay;
};

/**
 * struct reorder_head
 *
 * @resync_time: deadline for resynchronizing sequence numbers
 */
struct reorder_head {
    unsigned queue_size;
    struct reorder_entry *queue;

    int tail_index;
    u32 tail_seq;
    u32 head_seq;

    struct list_head xor_list;
    unsigned xor_list_len;

    struct net_device *master_dev;

    u32 next_rx_seq;

    long resync_time;

    struct reorder_stats stats;

    struct timer_list timer;
    bool restart_timer;

    spinlock_t lock;
};

/* This must fit in sk_buff cb field. */
struct virt_skb_cb {
    struct virt_priv *virt;
    struct flow_table_entry *flow;
};

struct virt_network;

void reorder_head_init(struct net_device *master_dev, struct reorder_head *head);
void reorder_head_destroy(struct reorder_head *head);

int reorder_rx_packet(struct virt_network *net, struct packet *pkt);

int reorder_try_recover(struct reorder_head *head, struct sk_buff *xor_skb);
void insert_xor_packet(struct reorder_head *head, struct sk_buff *skb);

#ifndef before
static inline int before(u32 seq1, u32 seq2)
{
    return (s32)(seq1 - seq2) < 0;
}
#endif

#ifndef after
static inline int after(u32 seq1, u32 seq2)
{
    return (s32)(seq1 - seq2) > 0;
}
#endif

static inline int afterl(unsigned long a, unsigned long b)
{
    return (long)(a - b) > 0;
}

#endif //_VIRT_REORDER_H__
