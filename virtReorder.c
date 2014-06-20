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
#include <linux/skbuff.h>

#include "virt.h"
#include "virtCoding.h"
#include "virtDebug.h"
#include "virtDevList.h"
#include "virtReorder.h"
#include "virtHeader.h"
#include "virtIngress.h"
#include "virtNetwork.h"
#include "virtPassive.h"
#include "virtMemory.h"

static void reorder_timer_fn(unsigned long arg);

void reorder_head_init(struct net_device *master_dev, struct reorder_head *head)
{
    const unsigned queue_size = virt_reorder_queue_size();
    const long alloc_bytes = sizeof(struct reorder_entry) * queue_size;

    /* Compile-time check that virt_skb_cb is not too large to fit in sk_buff
     * cb field. */
    BUILD_BUG_ON(sizeof(struct virt_skb_cb) > sizeof(((struct sk_buff *)0)->cb));

    head->queue = kmalloc(alloc_bytes, GFP_KERNEL);
    if(head->queue) {
        memset(head->queue, 0, alloc_bytes);
        head->queue_size = queue_size;
        head->head_seq = queue_size - 1;
    } else {
        head->queue_size = 0;
        head->head_seq = 0;
    }

    head->tail_index = 0;
    head->tail_seq = 0;

    INIT_LIST_HEAD(&head->xor_list);
    head->xor_list_len = 0;

    head->master_dev = master_dev;

    head->next_rx_seq = 0;

    /* Initialize resync_time such that sequence numbers will be synchronized
     * on the first packet that we receive. */
    head->resync_time = jiffies - get_resync_timeout_jiffies();

    init_timer(&head->timer);
    head->timer.data = (unsigned long)head;
    head->timer.function = reorder_timer_fn;
    head->restart_timer = true;

    spin_lock_init(&head->lock);
}

static void __count_passed_packet(struct reorder_stats *stats)
{
    const long delay = 0;

    VIRT_DBG("Forwarded packet after delay 0\n");

    stats->forwarded++;
    if(delay > stats->max_delay)
        stats->max_delay = delay;
    stats->avg_delay = (stats->avg_delay + delay) / 2;
}

static void __count_forwarded_entry(struct reorder_stats *stats, const struct reorder_entry *entry)
{
    long now = jiffies;
    long delay = now - entry->store_time;

    VIRT_DBG("Forwarded packet after delay %lld us\n", jiffies_to_usecs(delay));

    stats->forwarded++;
    if(delay > stats->max_delay)
        stats->max_delay = delay;
    stats->avg_delay = (stats->avg_delay + delay) / 2;
}

/*
 * If the entry contains an sk_buff, either deliver the packet or free it.
 */
static void __reorder_entry_evict(struct reorder_head *head, struct reorder_entry *entry)
{
    if(entry->skb) {
        if(entry->delivered) {
            dev_kfree_skb(entry->skb);
        } else {
            virt_forward_skb(head->master_dev, entry->skb);
            __count_forwarded_entry(&head->stats, entry);
        }
        
        entry->skb = NULL;
    }
}

void reorder_head_destroy(struct reorder_head *head)
{
    int i;

    might_sleep();
    
    head->restart_timer = false;
    del_timer_sync(&head->timer);
    
    spin_lock_bh(&head->lock);
    
    for(i = 0; i < head->queue_size; i++) {
        struct reorder_entry *entry = &head->queue[i];
        __reorder_entry_evict(head, entry);
    }

    if(head->queue) {
        kfree(head->queue);
        head->queue = NULL;
    }

    head->queue_size = 0;

    spin_unlock_bh(&head->lock);
}

static bool packet_in_range(struct reorder_head *head, u32 seq)
{
    u32 lower_bound = head->tail_seq - 1;
    u32 upper_bound = head->head_seq + 1;
    return (after(seq, lower_bound) && before(seq, upper_bound));
}

static int reorder_add_index(struct reorder_head *head, int index, int amount)
{
    /* TODO: If we constrain queue_size to be a power of two, then the modulus
     * operation can be replaced with a bitmask. */
    return (index + amount) % head->queue_size;
}

static u32 reorder_seq_from_index(struct reorder_head *head, int index)
{
    int diff = reorder_add_index(head, index, head->queue_size - head->tail_index);
    u32 seq = (int)head->tail_seq + diff;
    return seq;
}

static int reorder_index_from_seq(struct reorder_head *head, u32 seq)
{
    int diff = (int)seq - (int)head->tail_seq;
    if(likely(diff >= 0 && diff < head->queue_size))
        return reorder_add_index(head, head->tail_index, diff);
    else
        return -1;
}

/* Rotate the queue such that the given sequence number fits in the head.
 * Requires that the reorder_head lock be held. */
static void __rotate_queue_to_fit(struct reorder_head *head, u32 seq)
{
    int i;

    int steps = (int)seq - (int)head->head_seq;
    if(steps < 0 || steps > head->queue_size)
        steps = head->queue_size;

    for(i = 0; i < steps; i++) {
        int index = reorder_add_index(head, head->tail_index, i);
        struct reorder_entry *entry = &head->queue[index];
        __reorder_entry_evict(head, entry);
    }

    head->tail_index = reorder_add_index(head, head->tail_index, steps);
    head->tail_seq = seq - head->queue_size + 1;
    head->head_seq = seq;
}  

/* Does the work of release_from_entry.  Assumes that entry->skb is not null. */
static int __release_from_entry(struct reorder_head *head, struct reorder_entry *entry)
{
    int released = 0;

    struct sk_buff *skb = skb_copy(entry->skb, GFP_ATOMIC);
    if(skb) {
        virt_forward_skb(head->master_dev, skb);
        entry->delivered = true;
        __count_forwarded_entry(&head->stats, entry);
        released++;
    }

    return released;
}

/* If the entry contains an sk_buff that has not already been delivered, then
 * forward the packet. */
static int release_from_entry(struct reorder_head *head, struct reorder_entry *entry)
{
    if(entry->skb && !entry->delivered)
        return __release_from_entry(head, entry);
    else
        return 0;
}

static void __advance_next_rx_seq(struct reorder_head *head, u32 next_rx_seq)
{
    const int steps = (int)next_rx_seq - (int)head->next_rx_seq;
    int start_index;
    int i;

    __rotate_queue_to_fit(head, next_rx_seq);
    if(!packet_in_range(head, head->next_rx_seq))
        goto out;
    
    start_index = reorder_index_from_seq(head, head->next_rx_seq);

    /* This should not occur after doing the rotation and checking that
     * head->next_rx_seq is still in range. */
    if(WARN_ON(start_index < 0 || start_index > head->queue_size))
        goto out;
    if(WARN_ON(steps < 0 || steps > head->queue_size))
        goto out;

    /* Starting from our old next_rx_seq, walk through and release packets up
     * to the new next_rx_seq. */
    for(i = 0; i < steps; i++) {
        int index = reorder_add_index(head, start_index, i);
        struct reorder_entry *entry = &head->queue[index];
        release_from_entry(head, entry);
    }

out:
    head->next_rx_seq = next_rx_seq;
}

/* Release packets that are queued waiting on the given sequence number. */
static int __release_from_seq(struct reorder_head *head, u32 seq)
{
    int released = 0;
    int iterations = 0;

    int index = reorder_index_from_seq(head, seq);
    if(index < 0 || index >= head->queue_size)
        goto out;

    while(iterations < head->queue_size) {
        struct reorder_entry *entry = &head->queue[index];
        if(entry->skb && !entry->delivered) {
            if(__release_from_entry(head, entry) > 0) {
                released++;
                VIRT_DBG("Released packet %u\n", reorder_seq_from_index(head, index));
            }
        } else {
            break;
        }

        index = reorder_add_index(head, index, 1);
        iterations++;
    }

out:
    return released;
}

/* Set the reorder timer for the next waiting packet.  Requires that the
 * reorder_head lock be held. */
static void __reorder_update_timer(struct reorder_head *head)
{
    int index;
    int iterations = 0;

    if(unlikely(!head->restart_timer))
        return;

    index = reorder_index_from_seq(head, head->next_rx_seq);
    if(index < 0 || index >= head->queue_size)
        return;

    while(iterations < head->queue_size) {
        struct reorder_entry *entry = &head->queue[index];
        if(entry->skb && !entry->delivered) {
            mod_timer(&head->timer, entry->release_time);
            break;
        }

        index = reorder_add_index(head, index, 1);
        iterations++;
    }
}

static int __try_infer_losses(struct reorder_head *head, struct flow_table_entry *flow, u32 rx_seq)
{
    struct list_head *slave_list = get_slave_list_head();
    struct device_node *slave_iface;
    struct remote_node *dest = flow->rnode;
    u32 cand_next_seq = rx_seq;

    if(WARN_ON(!dest))
        return 0;

    list_for_each_entry(slave_iface, slave_list, lif.list) {
        struct remote_link *dest_link;

        list_for_each_entry(dest_link, &dest->links, rif.list) {
            struct pathinfo *path = path_lookup_create(flow->network, 
                    slave_iface, dest_link);
            if(path) {
                /* If any path has a last_rx_seq before the expected next
                 * packet, then we must assume next_rx_seq may still be
                 * traveling on that path. */
                if(!after(path->last_rx_seq, head->next_rx_seq)) {
                    virt_path_put(path);
                    return 0;
                }

                /* Otherwise, we want to find the minimum (subject to
                 * wrap-around) sequence number over all paths. */
                if(!after(path->last_rx_seq, cand_next_seq))
                    cand_next_seq = path->last_rx_seq;

                virt_path_put(path);
            }
        }
    }

    if(after(cand_next_seq, head->next_rx_seq)) {
        int released;

        __advance_next_rx_seq(head, cand_next_seq);
        released = __release_from_seq(head, cand_next_seq);
        if(released > 0)
            head->next_rx_seq += released;
        __reorder_update_timer(head);
        
        return 1;
    } else {
        return 0;
    }
}

static struct reorder_entry *get_reorder_entry(struct reorder_head *head, u32 seq)
{
    int index = reorder_index_from_seq(head, seq);
    if(likely(index >= 0 && index < head->queue_size))
        return &head->queue[index];
    else
        return NULL;
}

/*
 * Must be called with the reorder_head lock held.
 *
 * Returns REORDER_STOLEN if the XOR packet has been consumed, REORDER_ACCEPT
 * if the XOR packet should be saved for later, REORDER_DROP if the XOR packet
 * should be discarded.
 *
 * skb->data should point to the tunhdr.
 */
static int __reorder_try_recover(struct reorder_head *head, struct sk_buff *skb, long now)
{
    struct tunhdr *tunhdr = (struct tunhdr *)skb->data;
    unsigned xor_seq = ntohl(tunhdr->seq);
    int coding_rate = tunhdr->xor_rate;

    const u32 lower_seq = xor_seq;
    const u32 upper_seq = xor_seq + coding_rate - 1;

    int found = 0;
    long release_time = now;

    int lower_index;
    int gap_index;
    int i;

    /* Recovery is not possible if either sequence number is out of our
     * buffer's range. */
    if(!packet_in_range(head, upper_seq))
        __rotate_queue_to_fit(head, upper_seq);
    if(!packet_in_range(head, lower_seq))
        goto drop;

    lower_index = reorder_index_from_seq(head, lower_seq);
    gap_index = lower_index;

    /* Invalid encapsulated packet. */
    if(skb->len < sizeof(struct tunhdr))
        goto drop;

    /* Count the number of packets in the XOR group that are present in the
     * queue, and find the first gap (missing packet). */
    for(i = 0; i < coding_rate; i++) {
        int index = reorder_add_index(head, lower_index, i);
        struct reorder_entry *entry = &head->queue[index];
        if(entry->skb) {
            if(index == gap_index) {
                gap_index = reorder_add_index(head, gap_index, 1);
                release_time = entry->release_time;
            }

            found++;
        }
    }

    /* If exactly one packet of the group is missing (the gap packet), then we
     * can recover it. */
    if(found == (coding_rate - 1)) {
        struct reorder_entry *gap_entry = &head->queue[gap_index];
        u32 gap_seq = reorder_seq_from_index(head, gap_index);

        gap_entry->skb = skb;
        gap_entry->delivered = false;
        gap_entry->store_time = now;
        gap_entry->release_time = release_time;

        skb_pull(gap_entry->skb, sizeof(struct tunhdr));

        for(i = 0; i < coding_rate; i++) {
            int index = reorder_add_index(head, lower_index, i);
            struct reorder_entry *entry = &head->queue[index];
            if(index != gap_index && entry->skb)
                xor_sk_buff(gap_entry->skb, entry->skb, 0);
        }

        VIRT_DBG("Recovered packet %u from XOR packet %u\n", gap_seq, xor_seq);
        head->stats.recovered++;

        if(gap_seq == head->next_rx_seq) {
            int released = __release_from_seq(head, gap_seq);
            if(released > 0)
                head->next_rx_seq += released;    
            __reorder_update_timer(head);
        } else if(after(gap_seq, head->next_rx_seq)) {
            __reorder_update_timer(head);
        } else {
            __release_from_entry(head, gap_entry);
        }

        goto stolen;
    } else if(found == coding_rate) {
        /* All packets have been received, so the coded packet is redundant. */
        goto drop;
    }

    return REORDER_ACCEPT;
stolen:
    return REORDER_STOLEN;
drop:
    return REORDER_DROP;
}

/* Check for new recovery opportunities using the data packet and old XOR-coded
 * packets. */
void __reorder_try_recover_from_seq(struct reorder_head *head, u32 seq, long now)
{
    struct xor_entry *pos;
    struct xor_entry *tmp;

    if(head->xor_list_len == 0)
        return;

    list_for_each_entry_safe(pos, tmp, &head->xor_list, list) {
        const u32 lower_bound = pos->seq - 1;
        const u32 upper_bound = pos->seq + pos->coding_rate;

        int result = REORDER_ACCEPT;
        if(after(seq, lower_bound) && before(seq, upper_bound))
            result = __reorder_try_recover(head, pos->skb, now);

        if(result == REORDER_STOLEN || result == REORDER_DROP || afterl(now, pos->drop_time)) {
            list_del(&pos->list);
            kfree(pos);

            inc_free_count(XOR_ENTRY);

            head->xor_list_len--;
        }
    }
}

/*
 * Do the work of reorder_rx_packet.  The reorder_head abstraction hides
 * whether we have independent flow buffers or a global reorder buffer.
 * Requires that the reorder_head lock be held.
 */
static int __reorder_rx_packet(struct packet *pkt, struct reorder_head *head, u32 seq, long delay)
{
    unsigned long now = jiffies;
    
    /* If no packet has been received for a while, assume our sequence numbers
     * are no longer synchronized. */
    if((long)now - (long)head->resync_time >= 0)
        head->next_rx_seq = seq;
    head->resync_time = now + get_resync_timeout_jiffies();

    /* If the packet appears to be early, first check if there were likely
     * losses, because then it may be the case that the packet is on time. */
    if(after(seq, head->next_rx_seq)) {
        struct flow_table_entry *flow = pkt->ftable_entry;
        __try_infer_losses(head, flow, seq);
    }

    head->stats.received++;

    if(seq == head->next_rx_seq) {
        /* Packet received in order.  Rotate the buffer so that the packet is
         * in range, store a copy, and deliver the packet. */
        struct reorder_entry *entry;

        if(!packet_in_range(head, seq))
            __rotate_queue_to_fit(head, seq);

        entry = get_reorder_entry(head, seq);
        if(entry) {
            int released;

            if(entry->skb) {
                goto drop;
            } else {
                entry->skb = pkt->skb;
                entry->delivered = false;
                entry->store_time = now;
                entry->release_time = now;

                __reorder_try_recover_from_seq(head, seq, now);

                released = __release_from_seq(head, seq);
                if(released > 0)
                    head->next_rx_seq += released;

                __reorder_update_timer(head);

                head->stats.in_order++;

                goto stolen;
            }
        }

        goto accept;
    } else if(after(seq, head->next_rx_seq)) {
        /* Packet received early.  Rotate the buffer so that the packet is in
         * range and queue it for later. */
        struct reorder_entry *entry;

        if(!packet_in_range(head, seq)) {
            __rotate_queue_to_fit(head, seq);
            if(!packet_in_range(head, head->next_rx_seq))
                head->next_rx_seq = head->tail_seq;
        }

        entry = get_reorder_entry(head, seq);
        if(entry) {
            if(entry->skb) {
                goto drop;
            } else {
                entry->skb = pkt->skb;
                entry->delivered = false;
                entry->store_time = now;
                entry->release_time = now + usecs_to_jiffies(delay);
            
                __reorder_try_recover_from_seq(head, seq, now);
                __reorder_update_timer(head);

                head->stats.early++;

                goto stolen;
            }
        }

        goto accept;
    } else {
        /* Packet received late.  Check for duplicate and send out. */
        struct reorder_entry *entry = get_reorder_entry(head, seq);

        if(entry) {
            if(entry->skb) {
                goto drop;
            } else {
                entry->skb = skb_copy(pkt->skb, GFP_ATOMIC);
                entry->delivered = true;
                entry->store_time = now;
                entry->release_time = now;
                
                __reorder_try_recover_from_seq(head, seq, now);

                head->stats.late++;

                goto accept;
            }
        }

        goto accept;
    }

drop:
    head->stats.dropped++;
    return REORDER_DROP;

stolen:
    return REORDER_STOLEN;

accept:
    __count_passed_packet(&head->stats);
    return REORDER_ACCEPT;
}

/*
 * Return values:
 * REORDER_ACCEPT - Packet reception should continue.
 * REORDER_STOLEN - Packet was queued, packet structure can be freed.
 * REORDER_DROP - Packet should be dropped and freed.
 */
int reorder_rx_packet(struct virt_network *net, struct packet *pkt)
{
    const u32 rx_seq = pkt->tunnel_seq;
    int ret = REORDER_DROP;
    struct remote_node *from_node = find_remote_node_by_ip(net, &pkt->src_node);

    if(from_node) {
        struct reorder_head *head = &from_node->reorder_head;
        spin_lock_bh(&head->lock);
        ret = __reorder_rx_packet(pkt, head, rx_seq, pkt->reorder_delay);
        spin_unlock_bh(&head->lock);
        remote_node_put(from_node);
    }

    return ret;
}

/*
 * Must be called with the reorder_head lock held.
 */
static int __reorder_try_release(struct reorder_head *head, long now)
{
    int released = 0;
    bool released_prev = false;
    int iterations = 0;

    u32 seq;

    int index = reorder_index_from_seq(head, head->next_rx_seq);
    if(index < 0 || index >= head->queue_size)
        goto out;

    seq = head->next_rx_seq;

    while(iterations < head->queue_size) {
        struct reorder_entry *entry = &head->queue[index];
        if(entry->skb && !entry->delivered) {
            /* Once we release one, release all subsequent packets regardless of
             * release_time until we hit a gap. */
            if(released_prev || afterl(now, entry->release_time)) {
                if(__release_from_entry(head, entry) > 0) {
                    released++;
                    head->next_rx_seq = seq + 1;
                    released_prev = true;
                    VIRT_DBG("Released packet %u\n", reorder_seq_from_index(head, index));
                }
            } else {
                /* Stop releasing packets when we find one that appears after a
                 * gap and still has time remaining. */
                break;
            }
        } else {
            /* Hit a gap. */
            released_prev = false;
        }

        seq++;
        index = reorder_add_index(head, index, 1);
        iterations++;
    }

out:
    return released;
}

/*
 * Returns REORDER_STOLEN if the XOR packet has been consumed, REORDER_ACCEPT
 * if the XOR packet should be saved for later, REORDER_DROP if the XOR packet
 * should be discarded.
 *
 * skb->data should point to the tunhdr.
 */
int reorder_try_recover(struct reorder_head *head, struct sk_buff *xor_skb)
{
    long now = jiffies;
    int retval = 0;
    
    spin_lock_bh(&head->lock);
    retval = __reorder_try_recover(head, xor_skb, now);
    spin_unlock_bh(&head->lock);

    return retval;
}

/* Must be called with the reorder_head lock held. */
void __insert_xor_packet(struct reorder_head *head, struct xor_entry *entry)
{
    struct xor_entry *pos;

    head->xor_list_len++;

    list_for_each_entry(pos, &head->xor_list, list) {
        if(before(entry->seq, pos->seq)) {
            list_add_tail(&entry->list, &pos->list);
            return;
        }
    }

    list_add_tail(&entry->list, &head->xor_list);
}

/* Store an XOR coded packet for later recovery opportunities. */
void insert_xor_packet(struct reorder_head *head, struct sk_buff *skb)
{
    struct tunhdr *tunhdr = (struct tunhdr *)skb->data;

    struct xor_entry *entry = kmalloc(sizeof(struct xor_entry), GFP_ATOMIC);
    if(!entry)
        return;
        
    inc_alloc_count(XOR_ENTRY);

    entry->skb = skb;
    entry->seq = ntohl(tunhdr->seq);
    entry->coding_rate = tunhdr->xor_rate;
    entry->drop_time = jiffies + virt_rx_retain_time_jiffies();

    spin_lock_bh(&head->lock);
    __insert_xor_packet(head, entry);
    spin_unlock_bh(&head->lock);
}

static void reorder_timer_fn(unsigned long arg)
{
    struct reorder_head *head = (struct reorder_head *)arg;
    long now = jiffies;

    spin_lock_bh(&head->lock);
    __reorder_try_release(head, now);
    __reorder_update_timer(head);
    spin_unlock_bh(&head->lock);
}

