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
#include <linux/hash.h>
#include <linux/rcupdate.h>

#include <linux/if.h> // IFNAMSIZ
#include <linux/if_ether.h>

#include "virt.h"
#include "virtDebug.h"
#include "virtParse.h"
#include "virtEgress.h"
#include "virtPolicy.h"
#include "virtEgressLookup.h"
#include "virtFlowTable.h"
#include "virtSelectInterface.h"
#include "virtNAT.h"
#include "virtMemory.h"
#include "virtRetransmission.h"

const unsigned int RETX_TIMEOUT = 250000;

static void cleanup_timer_fn(unsigned long arg);
static void flow_table_entry_destroy(struct flow_table_entry *entry);
static u32 flow_hash(struct flow_tuple *key, unsigned bits);
static int keys_equal(struct flow_tuple *key1, struct flow_tuple *key2);

/*
 * Allocate space for the flow hash table.  The size is 2^bits.
 */
int init_flow_table(struct flow_table *ftable, unsigned bits)
{
    const unsigned table_size = 1u << bits;
    const unsigned long timeout = get_flow_table_timeout_jiffies();
    int i;

    ftable->head = kmalloc(table_size * sizeof(struct flow_table_head), GFP_KERNEL);
    if(!ftable->head)
        return -ENOMEM;

    for(i = 0; i < table_size; i++) {
        struct flow_table_head *head = &ftable->head[i];
        spin_lock_init(&head->lock);
        INIT_HLIST_HEAD(&head->list);
    }

    ftable->bits = bits;
    ftable->size = table_size;
    ftable->last_flush = jiffies;

    ftable->restart_timer = true;
    spin_lock_init(&ftable->timer_lock);

    init_timer(&ftable->timer);
    ftable->timer.data = (unsigned long)ftable;
    ftable->timer.function = cleanup_timer_fn;
    mod_timer(&ftable->timer, jiffies + timeout);

    return 0;
}

/*
 * Allocate a flow_table_entry structure and the substructures.  Initializes
 * most of the values.  Caller needs to fill in the flow key and flow id,
 * though.
 */
struct flow_table_entry *alloc_flow_table_entry(void)
{
    struct flow_table_entry *entry;

    entry = kmalloc(sizeof(struct flow_table_entry), GFP_ATOMIC);
    if(!entry)
        goto fail;
    memset(entry, 0, sizeof(*entry));

    entry->key = kmalloc(sizeof(struct flow_tuple), GFP_ATOMIC);
    if(!entry->key)
        goto fail_free_entry;
    memset(entry->key, 0, sizeof(*entry->key));

    entry->flow_stats = kmalloc(sizeof(struct flow_stats), GFP_ATOMIC);
    if(!entry->flow_stats)
        goto fail_free_key;
    memset(entry->flow_stats, 0, sizeof(*entry->flow_stats));

    inc_alloc_count(FLOW_TABLE_ENTRY);

    entry->last_touched = jiffies;

    virt_retx_init(&entry->retx, RETX_TIMEOUT);

    atomic_set(&entry->refcnt, 1);

    return entry;

fail_free_key:
    kfree(entry->key);
fail_free_entry:
    kfree(entry);
fail:
    return NULL;
}

/*
 * Add an entry to the flow hash table.
 */
int flow_table_add(struct flow_table *ftable, struct flow_table_entry *entry)
{
    u32 hash = flow_hash(entry->key, ftable->bits);
    struct flow_table_head *head = &ftable->head[hash];

    if(WARN_ON(hash >= ftable->size))
        return -1;

    spin_lock_bh(&head->lock);
    hlist_add_head_rcu(&entry->hlist, &head->list);
    spin_unlock_bh(&head->lock);

    flow_table_entry_hold(entry);

    return 0;
}

/*
 * Lookup an entry in the flow hash table.
 */
struct flow_table_entry *flow_table_lookup(struct flow_table *ftable, struct flow_tuple *key)
{
    u32 hash = flow_hash(key, ftable->bits);
    struct flow_table_head *head = &ftable->head[hash];

    struct flow_table_entry *entry;
    struct hlist_node *pos;

    if(WARN_ON(hash >= ftable->size))
        return NULL;

    rcu_read_lock();
    hlist_for_each_entry_rcu(entry, pos, &head->list, hlist) {
        if(keys_equal(key, entry->key)) {
            flow_table_entry_hold(entry);
            rcu_read_unlock();
            return entry;
        }
    }
    rcu_read_unlock();

    return NULL;
}

static void cleanup_timer_fn(unsigned long arg)
{
    struct flow_table *ftable = (struct flow_table *)arg;
    const unsigned long timeout = get_flow_table_timeout_jiffies();

    flow_table_clean(ftable);

    spin_lock_bh(&ftable->timer_lock);
    if(ftable->restart_timer)
        mod_timer(&ftable->timer, jiffies + (timeout >> 2));
    spin_unlock_bh(&ftable->timer_lock);
}

/*
 * This is called when no one is looking at the entries that we removed.
 */
static void flow_table_remove_rcu(struct rcu_head *head)
{
    struct flow_table_entry *entry;

    entry = container_of(head, struct flow_table_entry, rcu);
    flow_table_entry_destroy(entry);
}

/*
 * This functions traverses the hash table and frees all entries.  This
 * function should be called when module is unloaded.
 */
void flow_table_destroy(struct flow_table *ftable)
{
    int i;

    might_sleep();

    spin_lock_bh(&ftable->timer_lock);
    ftable->restart_timer = false;
    spin_unlock_bh(&ftable->timer_lock);
    
    /* This must not be called with timer_lock held because that could cause
     * deadlock. */
    del_timer_sync(&ftable->timer);

    for(i = 0; i < ftable->size; i++) {
        struct flow_table_head *head = &ftable->head[i];
        struct hlist_node *pos;
        struct hlist_node *tmp;
        struct flow_table_entry *entry;
    
        spin_lock_bh(&head->lock);
        hlist_for_each_entry_safe(entry, pos, tmp, &head->list, hlist) {
            hlist_del_rcu(&entry->hlist);
            flow_table_entry_put(entry);
        }
        spin_unlock_bh(&head->lock);
    }

    /* Block until all of the entries have been deleted. */
    synchronize_rcu();

    kfree(ftable->head);
    ftable->head = NULL;
}

/*
 * Walk through the flow cache and remove stale flows.  Flows are removed if
 * they have been inactive for longer than flow_table_timeout.
 *
 * The function tries to limit wasted computaton by running approximately four
 * times per timeout period and returning immediately if it was run recently.
 */
void flow_table_clean(struct flow_table *ftable)
{
    int i;

    const unsigned long timeout = get_flow_table_timeout_jiffies();
    long now = jiffies;
    unsigned long deletes = 0;

    for(i = 0; i < ftable->size; i++) {
        struct flow_table_head *head = &ftable->head[i];
        struct hlist_node *pos;
        struct hlist_node *tmp;
        struct flow_table_entry *entry;

        spin_lock_bh(&head->lock);
        hlist_for_each_entry_safe(entry, pos, tmp, &head->list, hlist) {
            if(now - (long)entry->last_touched > timeout) {
                VIRT_DBG("clean: %08x:%04hx - %08x:%04hx\n",
                        entry->key->sAddr, entry->key->sPort, 
                        entry->key->dAddr, entry->key->dPort);

                hlist_del_rcu(&entry->hlist);
                flow_table_entry_put(entry);

                deletes++;
            }
        }
        spin_unlock_bh(&head->lock);
    }

    ftable->last_flush = now;

    VIRT_DBG("removed %lu stale entries\n", deletes);
}

/*
 * Increment the entry's reference count.  As long as the refcnt is positive,
 * flow_table_clean will not free it even if the flow is idle.
 */
void flow_table_entry_hold(struct flow_table_entry *entry)
{
    atomic_inc(&entry->refcnt);
}

/*
 * Decrement the entry's reference count.  If the refcnt becomes zero, then
 * the entry will be freed from memory.
 */
void flow_table_entry_put(struct flow_table_entry *entry)
{
    if(atomic_dec_and_test(&entry->refcnt))
        call_rcu(&entry->rcu, flow_table_remove_rcu);
}

/*
 * This function will free the memory consumed by a hash entry structure and
 * all memory for sub structures.
 */
static void flow_table_entry_destroy(struct flow_table_entry *entry)
{
    VIRT_DBG("destroy: %08x:%04hx - %08x:%04hx\n",
            entry->key->sAddr, entry->key->sPort, 
            entry->key->dAddr, entry->key->dPort);

    virt_retx_destroy(&entry->retx);

    if(entry->rnode) {
        remote_node_put(entry->rnode);
        entry->rnode = NULL;
    }

    if(entry->flow_stats) {
        path_release_flow(entry->network, entry->flow_stats);
        kfree(entry->flow_stats);
    }

    if(entry->nat)
        nat_table_delete(entry->nat);

    if(entry->policy)
        policy_put(entry->policy);

    if(entry->key)
        kfree(entry->key);

    kfree(entry);

    inc_free_count(FLOW_TABLE_ENTRY);
}

/*
 * Compute a hash value for the flow tuple.
 */
static u32 flow_hash(struct flow_tuple *key, unsigned bits)
{
    // TODO: What is the best way to combine values?
    u32 sum = key->sAddr + key->dAddr + key->sPort + key->dPort + key->proto;
    return hash_32(sum, bits);
}

/*
 * This function compares two sets or keys to determine hash table lookup matches.
 */
static int keys_equal(struct flow_tuple *key1, struct flow_tuple *key2)
{
    return (key1->dAddr == key2->dAddr &&
            key1->sAddr == key2->sAddr &&
            key1->dPort == key2->dPort &&
            key1->sPort == key2->sPort &&
            key1->proto == key2->proto);
}

void dump_flow_table(struct seq_file *s, struct virt_priv *virt)
{
    struct flow_table *flow_table = &virt->flow_table;
    unsigned long now = jiffies;
    int i;

    //             xxxxxxxx xxxxxxxx xxxx xxxx xxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxx xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxx
    seq_printf(s, "source   dest     prot spt  dpt  action   linksel  txdev    rxdev    rxpkts txpkts rxbytes  txbytes  lastpkt  refcnt\n");

    rcu_read_lock();
    for(i = 0; i < flow_table->size; i++) {
        struct flow_table_head *head = &flow_table->head[i];
        struct flow_table_entry *entry;
        struct hlist_node *node;

        hlist_for_each_entry_rcu(entry, node, &head->list, hlist) {
            const struct flow_tuple *flow = entry->key;
            const struct policy_entry *policy = entry->policy;
            struct net_device *last_tx_dev = NULL;
            struct net_device *last_rx_dev = NULL;
            const struct flow_stats *flowst = entry->flow_stats;

            long lastpkt = now - entry->last_touched;
            long lastpkt_msecs = -1;
            if(lastpkt > 0)
                lastpkt_msecs = jiffies_to_msecs((unsigned long)lastpkt);

            if(WARN_ON(!flow))
                continue;
            if(WARN_ON(!policy))
                continue;
            if(WARN_ON(!policy->alg))
                continue;
            if(WARN_ON(!flowst))
                continue;

            last_tx_dev = dev_get_by_index(&init_net, flowst->last_tx_dev);
            last_rx_dev = dev_get_by_index(&init_net, flowst->last_rx_dev);

            seq_printf(s, "%08x %08x %04hx %04hx %04hx %08x %-8s %-8s %-8s %6lu %6lu %8lu %8lu %8ld %6d\n",
                    flow->sAddr, flow->dAddr,
                    flow->proto, flow->sPort, flow->dPort,
                    policy->action, policy->alg->name,
                    (last_tx_dev ? last_tx_dev->name : "n/a"),
                    (last_rx_dev ? last_rx_dev->name : "n/a"),
                    flowst->rx_packets, flowst->tx_packets,
                    flowst->rx_bytes, flowst->tx_bytes,
                    lastpkt_msecs,
                    atomic_read(&entry->refcnt));

            if(last_tx_dev)
                dev_put(last_tx_dev);
            if(last_rx_dev)
                dev_put(last_rx_dev);
        }
    }
    rcu_read_unlock();
}

/*
 * Free up buffers used for retransmissions and make sure all retransmission
 * timers have been stopped.
 */
void flow_table_kill_retx(struct flow_table *ftable)
{
    int i;

    rcu_read_lock();
    for(i = 0; i < ftable->size; i++) {
        struct flow_table_head *head = &ftable->head[i];
        struct flow_table_entry *entry;
        struct hlist_node *node;

        hlist_for_each_entry_rcu(entry, node, &head->list, hlist) {
            virt_retx_destroy(&entry->retx);
        }
    }
    rcu_read_unlock();
}

