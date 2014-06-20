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

#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hash.h>

#include "virt.h"
#include "virtNetwork.h"
#include "virtPassive.h"
#include "virtHashTable.h"
#include "virtMemory.h"
#include "virtEgress.h"

static int next_node_index = 1;

static inline u32 node_hash(struct remote_node *node, unsigned bits)
{
    return hash_32(node->priv_ip.s_addr, bits);
}

static inline u32 link_hash(struct remote_link *link, unsigned bits)
{
    return hash_32(link->rif.ip4, bits);
}

/*
 * Allocate space for a remote_node structure.
 *
 * Initializes refcnt to 1.
 */
struct remote_node* alloc_remote_node(struct net_device *master_dev)
{
    struct remote_node* node;

    node = kmalloc(sizeof(struct remote_node), GFP_KERNEL);
    if(unlikely(!node))
        return NULL;

    inc_alloc_count(REMOTE_NODE);
    memset(node, 0, sizeof(struct remote_node));

    INIT_LIST_HEAD(&node->links);
    spin_lock_init(&node->links_lock);

    node->next_link_index = 1;
    node->max_link_prio = MIN_USABLE_DEVICE_PRIORITY;

    skb_queue_head_init(&node->tx_queue);
    node->tx_queue_limit = virt_tx_queue_limit();

    init_timer(&node->tx_queue_timer);
    node->tx_queue_timer.data = (unsigned long)node;
    node->tx_queue_timer.function = tx_queue_timer_fn;
    node->restart_timer = true;

    reorder_head_init(master_dev, &node->reorder_head);

    INIT_LIST_HEAD(&node->stalled_paths);
    spin_lock_init(&node->stalled_paths_lock);

    atomic_set(&node->refcnt, 1);

    return node;
}

/*
 * Add a node to the table.
 */
void add_remote_node(struct virt_network *net, struct remote_node *node)
{
    struct virt_hash_table *table = &net->node_table;

    u32 hash = node_hash(node, table->bits);

    remote_node_hold(node);
    virt_hash_table_add(table, &node->hlist, hash);

    node->index = next_node_index++;

    node->network = net;
}

/*
 * Remove the node and all of its links from the table.  If any links cannot be
 * removed, then they and the node will be marked for deletion later.
 */
void delete_remote_node(struct virt_network *net, struct remote_node *node)
{
    struct virt_hash_table *table = &net->node_table;
    u32 hash;

    might_sleep();

    node->restart_timer = false;
    del_timer_sync(&node->tx_queue_timer);

    /* Remove all links associated with the node. */
    if(node->link_count > 0) {
        struct remote_link *link;

        rcu_read_lock();
        list_for_each_entry_rcu(link, &node->links, rif.list) {
            delete_remote_link(net, link);
        }
        rcu_read_unlock();
    }

    /* Remove the node from the node table. */
    hash = node_hash(node, table->bits);
    virt_hash_table_remove(table, &node->hlist, hash);

    /* Clear out the tx_queue. */
    while(skb_queue_len(&node->tx_queue) > 0) {
        struct sk_buff *skb;

        skb = skb_dequeue(&node->tx_queue);
        if(likely(skb)) {
            struct virt_skb_cb *skb_cb = (struct virt_skb_cb *)skb->cb;

            struct flow_table_entry *flow = skb_cb->flow;
            if(flow)
                flow_table_entry_put(flow);

            dev_kfree_skb(skb);
        }
    }

    reorder_head_destroy(&node->reorder_head);

    remote_node_put(node);
}

/*
 * Increment the reference count.
 */
void remote_node_hold(struct remote_node *node)
{
    atomic_inc(&node->refcnt);
}

/*
 * Decrement the reference count.  If it reaches zero, the node will be deleted.
 */
void remote_node_put(struct remote_node *node)
{
    if(atomic_dec_and_test(&node->refcnt)) {
        kfree_rcu(node, rcu);
        inc_free_count(REMOTE_NODE);
    }
}

/*
 * Allocate a remote link structure.
 *
 * Initializes the reference count to one.
 */
struct remote_link* alloc_remote_link(void)
{
    struct remote_link* link;

    link = kmalloc(sizeof(struct remote_link), GFP_KERNEL);
    if(unlikely(!link))
        return NULL;

    inc_alloc_count(REMOTE_LINK);
    memset(link, 0, sizeof(struct remote_link));

    link->rif.type = INTERFACE_REMOTE;
    link->rif.prio = DEFAULT_DEVICE_PRIORITY;

    atomic_set(&link->refcnt, 1);

    return link;
}

/*
 * Add a remote link to a remote node.
 */
void add_remote_link(struct virt_network *net, struct remote_node* node, 
        struct remote_link* link)
{
    struct virt_hash_table *table = &net->link_table;
    u32 hash = link_hash(link, table->bits);

    remote_link_hold(link);
    virt_hash_table_add(table, &link->hlist, hash);

    link->index = node->next_link_index++;

    link->network = net;
    
    remote_node_hold(node);
    link->node = node;

    remote_link_hold(link);
    spin_lock_bh(&node->links_lock);
    list_add_tail_rcu(&link->rif.list, &node->links);
    spin_unlock_bh(&node->links_lock);

    node->link_count++;

    if(link->rif.prio > node->max_link_prio)
        node->max_link_prio = link->rif.prio;
}

/*
 * Remove the link from the table and from its parent node's list of links.
 */
void delete_remote_link(struct virt_network *net, struct remote_link *link)
{
    struct virt_hash_table *table = &net->link_table;
    u32 hash = link_hash(link, table->bits);

    /* Remove any paths involving this link before the link (and possibly its
     * node) are deleted. */
    remove_paths_to_remote(net, link);

    if(link->node) {
        struct remote_node *node = link->node;

        spin_lock_bh(&node->links_lock);
        list_del_rcu(&link->rif.list);
        spin_unlock_bh(&node->links_lock);

        if(link->rif.prio == node->max_link_prio)
            node->max_link_prio = find_max_remote_link_prio(node);
        
        node->link_count--;
        link->node = NULL;

        /* Release reference to parent node. */
        remote_node_put(node);

        /* Release reference (that node had) to link. */
        remote_link_put(link);
    }

    link->rif.prio = MIN_DEVICE_PRIORITY; /* Need flows to stop using this link. */

    virt_hash_table_remove(table, &link->hlist, hash);
    remote_link_put(link);
}

/*
 * Increment the reference count.
 */
void remote_link_hold(struct remote_link *link)
{
    atomic_inc(&link->refcnt);
}

/*
 * Decrement the reference count.  If it reaches zero, the link will be deleted.
 */
void remote_link_put(struct remote_link *link)
{
    if(atomic_dec_and_test(&link->refcnt)) {
        kfree_rcu(link, rcu);
        inc_free_count(REMOTE_LINK);
    }
}

/*
 * Lookup a node by private IP address.
 *
 * Increments reference count before returning the node.
 */
struct remote_node *find_remote_node_by_ip(struct virt_network *net, 
        const struct in_addr *priv_ip)
{
    struct virt_hash_table *table = &net->node_table;
    u32 hash = hash_32(priv_ip->s_addr, table->bits);
    struct virt_hash_head *head = &table->head[hash];

    struct remote_node *node;
    struct hlist_node *pos;

    if(WARN_ON(hash >= table->size))
        return NULL;

    rcu_read_lock();
    hlist_for_each_entry_rcu(node, pos, &head->list, hlist) {
        if(priv_ip->s_addr == node->priv_ip.s_addr) {
            remote_node_hold(node);
            rcu_read_unlock();
            return node;
        }
    }
    rcu_read_unlock();

    return NULL;
}

/*
 * Lookup a node by index.
 *
 * Does not increment reference counts or use any locking, so only call with
 * rcu read lock held.
 */
struct remote_node *__find_remote_node_by_index(struct virt_network *net, 
        int index)
{
    struct virt_hash_table *table = &net->node_table;
    int i;

    for(i = 0; i < table->size; i++) {
        struct virt_hash_head *head = &table->head[i];
        struct remote_node *node;
        struct hlist_node *pos;

        hlist_for_each_entry_rcu(node, pos, &head->list, hlist) {
            if(node->index == index)
                return node;
        }
    }

    return NULL;
}

/*
 * Lookup a link by its public IP address.
 *
 * Increments reference count before returning the link.
 */
struct remote_link *find_remote_link_by_ip(struct virt_network *net, 
        const struct in_addr *pub_ip)
{
    struct virt_hash_table *table = &net->link_table;
    u32 hash = hash_32(pub_ip->s_addr, table->bits);
    struct virt_hash_head *head = &table->head[hash];

    struct remote_link *link;
    struct hlist_node *pos;

    if(WARN_ON(hash >= table->size))
        return NULL;

    rcu_read_lock();
    hlist_for_each_entry_rcu(link, pos, &head->list, hlist) {
        if(pub_ip->s_addr == link->rif.ip4) {
            remote_link_hold(link);
            rcu_read_unlock();
            return link;
        }
    }
    rcu_read_unlock();

    return NULL;
}

/*
 * Lookup a link by its public IP address and port.
 *
 * Increments reference count before returning the link.
 */
struct remote_link *find_remote_link_by_addr(struct virt_network *net,
        const struct in_addr *addr, __be16 port)
{
    struct virt_hash_table *table = &net->link_table;
    u32 hash = hash_32(addr->s_addr, table->bits);
    struct virt_hash_head *head = &table->head[hash];

    struct remote_link *link;
    struct hlist_node *pos;

    if(WARN_ON(hash >= table->size))
        return NULL;

    rcu_read_lock();
    hlist_for_each_entry_rcu(link, pos, &head->list, hlist) {
        if(addr->s_addr == link->rif.ip4 && port == link->rif.data_port) {
            remote_link_hold(link);
            rcu_read_unlock();
            return link;
        }
    }
    rcu_read_unlock();

    return NULL;
}

/*
 * Lookup a link by the node and link indices.
 *
 * Increments reference count before returning the link.
 */
struct remote_link *find_remote_link_by_indices(struct virt_network *net, 
        int rnode_index, int rlink_index)
{
    struct remote_node *node;

    rcu_read_lock();

    node = __find_remote_node_by_index(net, rnode_index);
    if(node) {
        struct remote_link *link;

        list_for_each_entry_rcu(link, &node->links, rif.list) {
            if(link->index == rlink_index) {
                remote_link_hold(link);
                rcu_read_unlock();
                return link;
            }
        }
    }

    rcu_read_unlock();

    return NULL;
}

/*
 * Find the maximum priority among a remote_node's links.
 */
int find_max_remote_link_prio(const struct remote_node *node)
{
    int max_prio = MIN_USABLE_DEVICE_PRIORITY;
    const struct remote_link *link;

    rcu_read_lock();

    list_for_each_entry_rcu(link, &node->links, rif.list) {
        if(link->rif.prio > max_prio &&
                (link->rif.active_paths > 0 || link->rif.stalled_paths <= 0))
            max_prio = link->rif.prio;
    }

    rcu_read_unlock();

    return max_prio;
}

int dump_remote_node_list(struct seq_file *s, void *p)
{
    const struct virt_priv *virt = s->private;
    const struct virt_hash_table *remote_nodes = &virt->network.node_table;
    int i;
    
    //             xxxxxxxx xxxxx xxxx xxxxxxxx xxxxxxxx xxxxxx
    seq_printf(s, "privaddr links mpri txqueue  qlimit   refcnt\n");

    rcu_read_lock();
    for(i = 0; i < remote_nodes->size; i++) {
        const struct virt_hash_head *head = &remote_nodes->head[i];
        const struct remote_node *node;
        struct hlist_node *pos;

        hlist_for_each_entry_rcu(node, pos, &head->list, hlist) {
            seq_printf(s, "%08x %5u %4d %8u %8u %6u\n",
                    node->priv_ip.s_addr,
                    node->link_count,
                    node->max_link_prio,
                    skb_queue_len(&node->tx_queue),
                    node->tx_queue_limit,
                    atomic_read(&node->refcnt));
        }
    }
    rcu_read_unlock();

    return 0;
}

int dump_remote_link_list(struct seq_file *s, void *p)
{
    const struct virt_priv *virt = s->private;
    const struct virt_hash_table *remote_links = &virt->network.link_table;
    int i;

    //             xxxxxxxx xxxxxxxx xxxx xxxxx xxxx xxxxxx xxxxxxxxx xxxxx xxxxxx
    seq_printf(s, "privaddr pubaddr  port flags prio flows  bandwidth paths refcnt\n");

    rcu_read_lock();
    for(i = 0; i < remote_links->size; i++) {
        const struct virt_hash_head *head = &remote_links->head[i];
        const struct remote_link *link;
        struct hlist_node *pos;

        hlist_for_each_entry_rcu(link, pos, &head->list, hlist) {
            const struct remote_node *node = link->node;

            seq_printf(s, "%08x %08x %04x %05x %4d %6ld %9ld %5u %6u\n",
                    node->priv_ip.s_addr,
                    link->rif.ip4,
                    link->rif.data_port,
                    link->flags,
                    link->rif.prio,
                    link->rif.flow_count,
                    link->rif.bandwidth_hint,
                    link->rif.active_paths,
                    atomic_read(&link->refcnt));
        }
    }
    rcu_read_unlock();

    return 0;
}

int dump_reorder_stats(struct seq_file *s, void *p)
{
    const struct virt_priv *virt = s->private;
    const struct virt_hash_table *remote_nodes = &virt->network.node_table;
    int i;

    //             xxxxxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx
    seq_printf(s, "privaddr  forwarded   received    dropped   in_order      early       late  recovered  max_delay  avg_delay\n");

    rcu_read_lock();
    for(i = 0; i < remote_nodes->size; i++) {
        const struct virt_hash_head *head = &remote_nodes->head[i];
        const struct remote_node *node;
        struct hlist_node *pos;

        hlist_for_each_entry_rcu(node, pos, &head->list, hlist) {
            const struct reorder_stats *stats = &node->reorder_head.stats;

            seq_printf(s, "%08x %10ld %10ld %10ld %10ld %10ld %10ld %10ld %10u %10u\n",
                    node->priv_ip.s_addr,
                    stats->forwarded,
                    stats->received,
                    stats->dropped,
                    stats->in_order,
                    stats->early,
                    stats->late,
                    stats->recovered,
                    jiffies_to_usecs(stats->max_delay),
                    jiffies_to_usecs(stats->avg_delay));
        }
    }
    rcu_read_unlock();

    return 0;
}

void remote_node_list_destroy(struct virt_network *net)
{
    int i;

    rcu_read_lock();
    for(i = 0; i < net->node_table.size; i++) {
        struct virt_hash_head *head = &net->node_table.head[i];
        struct remote_node *node;
        struct hlist_node *pos;

        hlist_for_each_entry_rcu(node, pos, &head->list, hlist) {
            delete_remote_node(net, node);
        }
    }
    rcu_read_unlock();
}

