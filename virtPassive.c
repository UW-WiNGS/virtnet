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

#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/hash.h>

#include "virtDebug.h"
#include "virtPassive.h"
#include "virtDevList.h"
#include "virtNetwork.h"
#include "virtHeader.h"
#include "virtMemory.h"

/*
 * Allocate a new pathinfo structure.
 *
 * Initializes the refcnt to one.
 */
static struct pathinfo *alloc_pathinfo(void)
{
    unsigned long now;

    struct pathinfo *path = kmalloc(sizeof(struct pathinfo), GFP_ATOMIC);
    if(unlikely(!path))
        return 0;

    inc_alloc_count(PATHINFO);
    memset(path, 0, sizeof(*path));

    path->state = VIRT_PATH_ACTIVE;

    path->last_rx_seq = 0;

    path->start_cwnd = DEFAULT_START_CWND;
    path->min_cwnd = DEFAULT_MIN_CWND;
    path->max_cwnd = DEFAULT_MAX_CWND;
    
    path->cwnd = path->start_cwnd;
    path->avail = path->start_cwnd;

    ewma_init(&path->est_rtt, RTT_EWMA_FACTOR, RTT_EWMA_WEIGHT);
    ewma_init(&path->est_rttvar, RTTVAR_EWMA_FACTOR, RTTVAR_EWMA_WEIGHT);

    path->base_rtt = ULONG_MAX;

    now = jiffies;
    path->next_cwnd_update = now;
    path->stall_time = now;
    path->last_packet = now;

    atomic_set(&path->refcnt, 1);

    return path;
}

/*
 * Add a path to the table.
 * TODO: Support IPv6 paths.
 */
void add_path(struct virt_network *net, struct pathinfo *path)
{
    struct virt_hash_table *table = &net->path_table;
    u32 hash = hash_32(path->local_addr.ip4.s_addr + path->remote_addr.ip4.s_addr, 
            table->bits);

    virt_path_hold(path);
    virt_hash_table_add(table, &path->hlist, hash);

    path->network = net;
}

/*
 * Remove a path from the path table.  It will be freed if there are no longer
 * any references to it.
 */
void remove_path(struct virt_network *net, struct pathinfo *path)
{
    struct virt_hash_table *table = &net->path_table;
    u32 hash = hash_32(path->local_addr.ip4.s_addr + path->remote_addr.ip4.s_addr, 
            table->bits);

    virt_hash_table_remove(table, &path->hlist, hash);
    virt_path_put(path);
}

/*
 * Lookup pathinfo structure without incrementing refcnt.  Must be called with
 * rcu read lock held.
 */
struct pathinfo *__path_get_by_addr(struct virt_network *net, 
        const struct in_addr *local_addr,
        const struct in_addr *remote_addr,
        __be16 local_port, __be16 remote_port)
{
    struct virt_hash_table *table = &net->path_table;
    u32 hash = hash_32(local_addr->s_addr + remote_addr->s_addr, table->bits);
    struct virt_hash_head *head = &table->head[hash];

    struct pathinfo *path;
    struct hlist_node *pos;

    if(WARN_ON(hash >= table->size))
        return NULL;

    /* TODO: Add support for IPv6 paths. */
    hlist_for_each_entry_rcu(path, pos, &head->list, hlist) {
        if(path->net_proto == AF_INET &&
                path->local_addr.ip4.s_addr == local_addr->s_addr &&
                path->remote_addr.ip4.s_addr == remote_addr->s_addr &&
                path->local_port == local_port &&
                path->remote_port == remote_port)
            return path;
    }

    return NULL;
}

/*
 * Lookup pathinfo structure.  Increments refcnt on the returned structure.
 */
struct pathinfo *lookup_pathinfo(struct virt_network *net,
        const struct device_node *llink, 
        const struct remote_link *rlink)
{
    struct pathinfo *path;

    if(WARN_ON(!llink))
        return NULL;
    if(WARN_ON(!llink->dev))
        return NULL;
    if(WARN_ON(!rlink))
        return NULL;
    if(WARN_ON(!rlink->node))
        return NULL;

    rcu_read_lock();
    path = __path_get_by_addr(net, (const struct in_addr *)&llink->lif.ip4,
            (const struct in_addr *)&rlink->rif.ip4, 
            llink->lif.data_port, rlink->rif.data_port);
    if(path)
        virt_path_hold(path);
    rcu_read_unlock();

    return path;
}

/*
 * Lookup pathinfo structure or create if it does not exist.
 *
 * Increments the reference count on the returned structure.
 */
struct pathinfo *path_lookup_create(struct virt_network *net,
        struct device_node *llink,
        struct remote_link *rlink)
{
    struct pathinfo *path;

    path = lookup_pathinfo(net, llink, rlink);
    if(!path) {
        path = alloc_pathinfo();
        if(unlikely(!path)) {
            return NULL;
        }

        /* TODO: Support for IPv6 */
        path->net_proto = AF_INET;
        path->local_addr.ip4.s_addr = llink->lif.ip4;
        path->remote_addr.ip4.s_addr = rlink->rif.ip4;
        path->local_port = llink->lif.data_port;
        path->remote_port = rlink->rif.data_port;

        path->local_index = llink->dev->ifindex;
        path->rnode_index = rlink->node->index;
        path->rlink_index = rlink->index;

        llink->lif.active_paths++;
        rlink->rif.active_paths++;

        add_path(net, path);
    }

    return path;
}

/*
 * Lookup pathinfo structure.  Increments refcnt on the returned structure.
 */
struct pathinfo *path_get_by_addr(struct virt_network *net, 
        const struct in_addr *local_addr,
        const struct in_addr *remote_addr,
        __be16 local_port, __be16 remote_port)
{
    struct pathinfo *path;

    rcu_read_lock();
    path = __path_get_by_addr(net, local_addr, remote_addr, local_port, remote_port);
    if(path)
        virt_path_hold(path);
    rcu_read_unlock();

    return path;
}

/*
 * Lookup pathinfo structure.  Increments refcnt on the returned structure.
 */
struct pathinfo *path_get_by_addr_old(struct virt_network *net, 
        const struct in_addr *local_addr,
        const struct in_addr *remote_addr)
{
    struct virt_hash_table *table = &net->path_table;
    u32 hash = hash_32(local_addr->s_addr + remote_addr->s_addr, table->bits);
    struct virt_hash_head *head = &table->head[hash];

    struct pathinfo *path;
    struct hlist_node *pos;

    if(WARN_ON(hash >= table->size))
        return NULL;

    rcu_read_lock();
    hlist_for_each_entry_rcu(path, pos, &head->list, hlist) {
        if(path->net_proto == AF_INET &&
                path->local_addr.ip4.s_addr == local_addr->s_addr &&
                path->remote_addr.ip4.s_addr == remote_addr->s_addr) {
            virt_path_hold(path);
            rcu_read_unlock();
            return path;
        }
    }
    rcu_read_unlock();

    return NULL;
}

/*
 * Update estimated RTT and RTTVAR with the new measurement.  The method is
 * based upon TCPs RTO calculation.
 */
void update_est_rtt(struct pathinfo *path, unsigned long rtt)
{
    unsigned long srtt;

    srtt = ewma_read(&path->est_rtt);
    if(likely(srtt)) {
        unsigned long diff = abs((long)srtt - (long)rtt);
        ewma_add(&path->est_rtt, rtt);
        ewma_add(&path->est_rttvar, diff);
    } else {
        /* This is the first measurement. */
        ewma_add(&path->est_rtt, rtt);
        ewma_add(&path->est_rttvar, rtt >> 1);
    }

    srtt = ewma_read(&path->est_rtt);

    if(srtt < path->base_rtt) {
        path->base_rtt = srtt;
    } else if((srtt / 2) > path->base_rtt) {
        unsigned long now = jiffies;
        
        if(afterl(now, path->next_cwnd_update)) {
            /* Cap the cwnd here because we hit significant delay. */
            path->cwnd /= 2;
            if(path->cwnd < path->min_cwnd)
                path->cwnd = path->min_cwnd;

            if(path->avail > path->cwnd)
                path->avail = path->cwnd;

            path->next_cwnd_update = now + usecs_to_jiffies(srtt);
            
            path->base_rtt = srtt;
        }
    }
}

/*
 * Update the CWND based on the number of newly ACK'ed bytes.
 */
void update_path_cwnd(struct pathinfo *path, const struct tunhdr *tunhdr)
{
    u32 ack = ntohl(tunhdr->path_ack);
    s32 gap = (s32)ack - (s32)path->snd_una;

    VIRT_DBG("received ack: %u snd_una: %u gap: %d\n", 
            ack, path->snd_una, gap);

    if(gap > 0 && gap <= path->max_cwnd) {
        unsigned cwnd_increase = 0;
        unsigned long srtt;
        unsigned long rttvar;
        unsigned long now = jiffies;

        change_path_state_active(path);

        path->unacked_bytes = 0;
        path->unacked_packets = 0;

        path->snd_una = ack;

        srtt = pathinfo_est_rtt(path);
        rttvar = pathinfo_est_rttvar(path);

        /* This is based on the TCP RTO calculation. */
        path->stall_time = now + usecs_to_jiffies(srtt + 4 * rttvar);

        cwnd_increase = gap * gap / path->cwnd;
        if(cwnd_increase > MAX_CWND_INCREASE)
            cwnd_increase = MAX_CWND_INCREASE;
        else if(cwnd_increase < MIN_CWND_INCREASE)
            cwnd_increase = MIN_CWND_INCREASE;

        path->cwnd += cwnd_increase;
        if(path->cwnd > path->max_cwnd)
            path->cwnd = path->max_cwnd;

        if(afterl(now, path->next_cwnd_update)) {
            path->avail = path->cwnd;

            path->next_cwnd_update = now + usecs_to_jiffies(srtt);
        } else {
            path->avail += gap + cwnd_increase;
            if(path->avail > path->cwnd)
                path->avail = path->cwnd;
        }
    }
}

/*
 * Update the ACK number to be sent with the next packet.
 */
void update_path_ack(struct pathinfo *path, unsigned payload_len)
{
    path->rcv_nxt += payload_len;    
}

int update_pathinfo(struct virt_network *net, struct device_node *llink,
        struct remote_link *rlink, const struct tunhdr *tunhdr, 
        unsigned payload_len)
{
    struct pathinfo *path;
    s64 local_ts;

    path = path_lookup_create(net, llink, rlink);
    if(!path)
        return -ENOMEM;

    local_ts = ktime_to_us(ktime_get());

    if(tunhdr->flags & TUN_FLAG_TIMESTAMP_VALID) {
        long rtt = (long)((int32_t)local_ts - (int32_t)ntohl(tunhdr->recv_ts));

        VIRT_DBG("Measured rtt: %ld us\n", rtt);
        if(rtt > 0 && rtt < MAX_PASSIVE_RTT) {
            update_est_rtt(path, rtt);
        }
    }

    path->last_rx_seq = ntohl(tunhdr->seq);

    path->recv_ts = ntohl(tunhdr->send_ts);
    path->local_recv_time = local_ts;

    /* If XOR coding rate has not been set explicitly, then copy the rate used
     * by the sender. */
    if(!path->xor_set_by_admin && tunhdr_xor_bits_valid(tunhdr)) {
        path->xor_same_path.next_rate = tunhdr->xor_same_path;
        path->xor_same_prio.next_rate = tunhdr->xor_same_prio;
        path->xor_lower_prio.next_rate = tunhdr->xor_lower_prio;
    }

    update_path_cwnd(path, tunhdr);    
    update_path_ack(path, payload_len);

    /* Decrement the refcnt. */
    virt_path_put(path);

    return 0;
}

unsigned long pathinfo_update_queue(struct pathinfo *pathi, unsigned add)
{
    unsigned long drain;

    drain = pathinfo_est_bandwidth(pathi) *
        (jiffies_to_usecs(jiffies) - pathi->queue_updated);
    if(drain >= pathi->queue_len)
        pathi->queue_len = 0;
    else
        pathi->queue_len -= drain;

    pathi->queue_len += add;

    return pathi->queue_len;
}

unsigned long pathinfo_est_delay(struct pathinfo *pathi)
{
    unsigned long delay;
    unsigned long discount;

    if(unlikely(!pathi))
        return INITIAL_EST_RTT;

    delay = pathinfo_est_rtt(pathi);

    discount = jiffies_to_msecs((long)jiffies - (long)pathi->last_packet);
    if(discount > delay)
        delay = 0;
    else
        delay -= discount;

    return delay;
}

int dump_path_list(struct seq_file *s, void *p)
{
    const struct virt_priv *virt = s->private;
    const struct virt_hash_table *path_table = &virt->network.path_table;
    int i;

    //             xxxxxxxx xxxxxxxx xxxxx xxxxx xx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xx/xx/xx xxxxxx
    seq_printf(s, "local    remote   lport rport st available  cwnd       min_cwnd   max_cwnd   srtt       rttvar     base_rtt   coding   refcnt\n");

    rcu_read_lock();

    for(i = 0; i < path_table->size; i++) {
        const struct virt_hash_head *head = &path_table->head[i];
        const struct pathinfo *path;
        struct hlist_node *pos;

        hlist_for_each_entry_rcu(path, pos, &head->list, hlist) {
            seq_printf(s, "%08x %08x %-5u %-5u %-2u %-10u %-10u %-10u %-10u %-10lu %-10lu %-10lu %-2u/%-2u/%-2u %-6u\n",
                    path->local_addr.ip4.s_addr,
                    path->remote_addr.ip4.s_addr,
                    ntohs(path->local_port),
                    ntohs(path->remote_port),
                    path->state,
                    path->avail, path->cwnd, 
                    path->min_cwnd, path->max_cwnd,
                    pathinfo_est_rtt(path),
                    pathinfo_est_rttvar(path),
                    path->base_rtt,
                    path->xor_same_path.next_rate,
                    path->xor_same_prio.next_rate,
                    path->xor_lower_prio.next_rate,
                    atomic_read(&path->refcnt));
        }
    }

    rcu_read_unlock();

    return 0;
}

/*
 * Record sent bytes and check whether path has stalled.
 */
void path_update_tx_bytes(struct pathinfo *path, unsigned bytes)
{
    unsigned long now = jiffies;

    path->last_packet = now;
    path->unacked_bytes += bytes;
    path->unacked_packets++;

    if(path->state == VIRT_PATH_ACTIVE &&
            (path->unacked_bytes >= virt_stall_threshold_bytes() ||
             path->unacked_packets >= virt_stall_threshold_packets())) {
        unsigned long srtt = pathinfo_est_rtt(path);
        unsigned long rttvar = pathinfo_est_rttvar(path);

        /* This is based on the TCP RTO calculation. */
        path->stall_time = now + usecs_to_jiffies(srtt + 4 * rttvar);

        path->state = VIRT_PATH_STALL_TIME_WAIT;
    }

    if(path->state == VIRT_PATH_STALL_TIME_WAIT &&
            afterl(now, path->stall_time)) {
        change_path_state_stalled(path);
    }
}

/*
 * Increment the reference count.
 */
void virt_path_hold(struct pathinfo *path)
{
    atomic_inc(&path->refcnt);
}

/*
 * Decrement the reference count, mark the structure for deletion if it reaches
 * zero.
 */
void virt_path_put(struct pathinfo *path)
{
    if(atomic_dec_and_test(&path->refcnt)) {
        kfree_rcu(path, rcu);
        inc_free_count(PATHINFO);
    }
}

void change_path_state_active(struct pathinfo *path)
{
    struct device_node *slave;
    struct remote_link *rlink;
    
    if(path->state == VIRT_PATH_STALLED) {
        slave = slave_get_by_ifindex(path->local_index);
        if(slave) {
            struct virt_priv *virt = netdev_priv(slave->master);

            slave->lif.active_paths++;
            slave->lif.stalled_paths--;

            if(slave->lif.prio > virt->max_dev_prio)
                virt->max_dev_prio = slave->lif.prio;

            device_node_put(slave);
        }

        rlink = find_remote_link_by_indices(path->network, 
                path->rnode_index, path->rlink_index);
        if(rlink) {
            struct remote_node *node = rlink->node;

            rlink->rif.active_paths++;

            /* Remove from list of stalled paths. */
            spin_lock_bh(&node->stalled_paths_lock);
            list_del_rcu(&path->stall_list);
            node->stalled_paths_len--;
            spin_unlock_bh(&node->stalled_paths_lock);

            virt_path_put(path);

            rlink->rif.stalled_paths--;
            
            if(rlink->rif.prio > node->max_link_prio)
                node->max_link_prio = rlink->rif.prio;

            remote_link_put(rlink);
        }
    }

    path->state = VIRT_PATH_ACTIVE;
}

void change_path_state_stalled(struct pathinfo *path)
{
    struct device_node *slave;
    struct remote_link *rlink;

    if(path->state == VIRT_PATH_ACTIVE || path->state == VIRT_PATH_STALL_TIME_WAIT) {
        slave = slave_get_by_ifindex(path->local_index);
        if(slave) {
            struct virt_priv *virt = netdev_priv(slave->master);

            slave->lif.active_paths--;
            slave->lif.stalled_paths++;

            if(slave->lif.active_paths == 0 && 
                    slave->lif.prio == virt->max_dev_prio)
                virt->max_dev_prio = find_max_dev_prio();

            device_node_put(slave);
        }

        rlink = find_remote_link_by_indices(path->network, 
                path->rnode_index, path->rlink_index);
        if(rlink) {
            struct remote_node *node = rlink->node;
                
            virt_path_hold(path);

            /* Add to list of stalled paths. */
            spin_lock_bh(&node->stalled_paths_lock);
            list_add_tail_rcu(&path->stall_list, &node->stalled_paths);
            node->stalled_paths_len++;
            spin_unlock_bh(&node->stalled_paths_lock);

            rlink->rif.active_paths--;
            rlink->rif.stalled_paths++;

            if(rlink->rif.active_paths == 0 &&
                    rlink->rif.prio == node->max_link_prio)
                node->max_link_prio = find_max_remote_link_prio(node);

            remote_link_put(rlink);
        }
    }
    
    path->state = VIRT_PATH_STALLED;
}

static void remove_path_local_refs(struct pathinfo *path, struct device_node *slave)
{
    switch(path->state) {
        case VIRT_PATH_ACTIVE:
        case VIRT_PATH_STALL_TIME_WAIT:
            slave->lif.active_paths--;
            break;
        case VIRT_PATH_STALLED:
            slave->lif.stalled_paths--;
            break;
    }
}

static void remove_path_remote_refs(struct pathinfo *path, struct remote_link *link)
{
    struct remote_node *node = link->node;

    switch(path->state) {
        case VIRT_PATH_ACTIVE:
        case VIRT_PATH_STALL_TIME_WAIT:
            link->rif.active_paths--;
            break;
        case VIRT_PATH_STALLED:
            /* Remove from list of stalled paths. */
            spin_lock_bh(&node->stalled_paths_lock);
            list_del_rcu(&path->stall_list);
            node->stalled_paths_len--;
            spin_unlock_bh(&node->stalled_paths_lock);

            /* Release reference that was held for the stall_list. */
            virt_path_put(path);

            link->rif.stalled_paths--;
            break;
    }
}

void remove_paths_from_local(struct virt_network *net, struct device_node *slave)
{
    const struct virt_hash_table *path_table = &net->path_table;
    int i;

    rcu_read_lock();

    for(i = 0; i < path_table->size; i++) {
        struct virt_hash_head *head = &path_table->head[i];
        struct pathinfo *path;
        struct hlist_node *pos;

        hlist_for_each_entry_rcu(path, pos, &head->list, hlist) {
            if(path->local_addr.ip4.s_addr == slave->lif.ip4) {
                struct remote_link *link;

                remove_path_local_refs(path, slave);

                link = find_remote_link_by_addr(net, &path->remote_addr.ip4, path->remote_port);
                if(link) {
                    remove_path_remote_refs(path, link);
                    remote_link_put(link);
                }

                remove_path(net, path);
            }
        }
    }

    rcu_read_unlock();

}

void remove_paths_to_remote(struct virt_network *net, struct remote_link *link)
{
    const struct virt_hash_table *path_table = &net->path_table;
    int i;

    rcu_read_lock();

    for(i = 0; i < path_table->size; i++) {
        struct virt_hash_head *head = &path_table->head[i];
        struct pathinfo *path;
        struct hlist_node *pos;

        hlist_for_each_entry_rcu(path, pos, &head->list, hlist) {
            if(path->remote_addr.ip4.s_addr == link->rif.ip4) {
                struct device_node *slave;

                slave = slave_get_by_addr(&path->local_addr.ip4);
                if(slave) {
                    remove_path_local_refs(path, slave);
                    device_node_put(slave);
                }

                remove_path_remote_refs(path, link);
                
                remove_path(net, path);
            }
        }
    }

    rcu_read_unlock();
}

