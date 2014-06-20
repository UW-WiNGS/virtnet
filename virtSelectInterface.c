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

#include <linux/random.h>
#include <linux/module.h>

#include "virt.h"
#include "virtSelectInterface.h"
#include "virtPassive.h"
#include "virtNetwork.h"
#include "virtDevList.h"
#include "virtEgressLookup.h"
#include "virtPolicy.h"
#include "virtPolicyTypes.h"

// TODO: This guy needs a lock associated with him.
static struct list_head virt_alg_list = LIST_HEAD_INIT(virt_alg_list);

/*
 * Register an interface selection algorithm, so that policies may specify them
 * by name.
 *
 * TODO: Locking!
 * TODO: Support algorithms loaded as separate kernel modules.
 */
int virt_register_alg(struct virt_alg *alg)
{
    struct virt_alg *curr;

    if(strnlen(alg->name, MAX_ALG_NAME_LEN) >= MAX_ALG_NAME_LEN)
        return -E2BIG;

    list_for_each_entry(curr, &virt_alg_list, alg_list) {
        if(strcmp(alg->name, curr->name) == 0)
            return -EEXIST;
    }

    list_add_tail(&alg->alg_list, &virt_alg_list);

    return 0;
}

/*
 * Unregister an interface selection algorithm.
 *
 * Currently, it is unnecessary to call this when the main virt mode exits,
 * since nothing needs to be freed.  This is intended as a placeholder for
 * algorithms loaded as external modules.
 *
 * TODO: Add refcnt, the owner of this algorithm cannot disappear until all
 * references to it are cleaned up.
 */
int virt_unregister_alg(struct virt_alg *alg)
{
    list_del(&alg->alg_list);

    return 0;
}

/*
 * Find an interface selection algorithm by name.
 */
struct virt_alg *virt_alg_get_by_name(const char *name)
{
    struct virt_alg *curr;

    list_for_each_entry(curr, &virt_alg_list, alg_list) {
        if(strcmp(name, curr->name) == 0)
            return curr;
    }

    return NULL;
}

/*
 * For single-path flows, if the current path is still available, then this is
 * used to determine whether it would still be acceptable to migrate the flow.
 * The goal is to allow the link selection algorithm opportunities to
 * re-evaluate the link assignment, while minimizing the the out-of-order
 * deliveries that can result.
 */
static int can_reassign(struct virt_network *net,
        const struct policy_entry *policy, 
        const struct flow_stats *flow_stats)
{
    int action;
    struct pathinfo *last_path;
    unsigned long pkt_spacing;
    unsigned long safe_spacing;
    unsigned long now = jiffies;

    /* Reassignment is only allowed if the action is ENCAP. */
    action = POLICY_ACTION(policy->action);
    if(action != POLICY_ACT_ENCAP)
        return 0;

    last_path = path_get_by_addr(net,
            &flow_stats->local_addr, &flow_stats->remote_addr,
            flow_stats->local_port, flow_stats->remote_port);
    if(!last_path)
        return 1;

    /* Test if the spacing between the last packet and the current packet is
     * sufficiently large that we can reassign the flow without causing an out
     * of order packet. */
    safe_spacing = usecs_to_jiffies(pathinfo_safe_spacing(last_path));

    /* Done with last_path, decrement refcnt. */
    virt_path_put(last_path);

    pkt_spacing = (long)now - (long)flow_stats->last_send_jiffies;
    if(pkt_spacing >= safe_spacing)
        return 1;

    /* Test if the flow has not been reassigned too recently.
     *
     * TODO: We should also check whether the tunnel endpoint supports
     * resequencing and/or make sure it is enabled for this flow. */
    if((unsigned long)((long)now - (long)flow_stats->last_path_change) >=
            get_min_reassign_delay_jiffies()) {
        return 1;
    }

    return 0;
}

/*
 * This is the main local interface selection function.
 */
struct device_node *select_local_interface(struct virt_priv *virt, struct flow_table_entry *flow,
        const struct remote_node *dest, const struct list_head *interfaces)
{
    struct device_node *sel_iface = NULL;
    struct device_node *last_iface = NULL;
    
    if(WARN_ON(!flow->flow_stats))
        return NULL;
    if(WARN_ON(!flow->policy))
        return NULL;
    if(WARN_ON(!flow->policy->alg))
        return NULL;

    if(unlikely(list_empty(interfaces)))
        return NULL;

    last_iface = slave_get_by_addr(&flow->flow_stats->local_addr);
    if(last_iface) {
        if(!can_reassign(&virt->network, flow->policy, flow->flow_stats))
            return last_iface;

        device_node_put(last_iface);

        if(!WARN_ON(last_iface->lif.flow_count <= 0))
            last_iface->lif.flow_count--;
    }

    sel_iface = flow->policy->alg->sel_local(virt, flow, dest, interfaces);

    /* Set the last path here for NAT flows because NAT flows will
     * not pass through select_remote_interface. */
    if(sel_iface && POLICY_ACTION(flow->policy->action) == POLICY_ACT_NAT) {
        flow->flow_stats->local_addr.s_addr = sel_iface->lif.ip4;
        flow->flow_stats->local_port = sel_iface->lif.data_port;
    }

    if(sel_iface)
        sel_iface->lif.flow_count++;

    return sel_iface;
}

static void set_last_path(struct flow_stats *flow_stats, struct pathinfo *path) 
{
    if(flow_stats->local_addr.s_addr != path->local_addr.ip4.s_addr ||
            flow_stats->remote_addr.s_addr != path->remote_addr.ip4.s_addr ||
            flow_stats->local_port != path->local_port ||
            flow_stats->remote_port != path->remote_port) {
        flow_stats->last_path_change = jiffies;
        flow_stats->local_addr.s_addr = path->local_addr.ip4.s_addr;
        flow_stats->remote_addr.s_addr = path->remote_addr.ip4.s_addr;
        flow_stats->local_port = path->local_port;
        flow_stats->remote_port = path->remote_port;
    }
}

static void set_last_path_fallback(struct flow_stats *flow_stats, 
        const struct device_node *llink,
        const struct remote_link *rlink)
{
    if(flow_stats->local_addr.s_addr != llink->lif.ip4 ||
            flow_stats->remote_addr.s_addr != rlink->rif.ip4 ||
            flow_stats->local_port != llink->lif.data_port ||
            flow_stats->remote_port != rlink->rif.data_port) {
        flow_stats->last_path_change = jiffies;
        flow_stats->local_addr.s_addr = llink->lif.ip4;
        flow_stats->remote_addr.s_addr = rlink->rif.ip4;
        flow_stats->local_port = llink->lif.data_port;
        flow_stats->remote_port = rlink->rif.data_port;
    }
}

/*
 * This is the main remote interface selection function.
 *
 * Note that the returned remote_link object will have its reference count
 * incremented.  The caller must use remote_link_put when finished with it.
 */
struct remote_link *select_remote_interface(struct virt_priv *virt, struct flow_table_entry *flow, 
        const struct device_node *src, const struct remote_node *dest, 
        const struct list_head *interfaces)
{
    struct remote_link *sel_iface = NULL;
    struct remote_link *last_iface = NULL;
    
    if(WARN_ON(!flow->flow_stats))
        return NULL;
    if(WARN_ON(!flow->policy))
        return NULL;
    if(WARN_ON(!flow->policy->alg))
        return NULL;

    if(unlikely(list_empty(interfaces)))
        return NULL;

    last_iface = find_remote_link_by_addr(&virt->network,
            &flow->flow_stats->remote_addr, flow->flow_stats->remote_port);
    if(last_iface) {
        if(!can_reassign(&virt->network, flow->policy, flow->flow_stats))
            return last_iface;

        if(!WARN_ON(last_iface->rif.flow_count <= 0))
            last_iface->rif.flow_count--;

        remote_link_put(last_iface);
    }

    sel_iface = flow->policy->alg->sel_remote(virt, flow, src, dest, interfaces);

    if(sel_iface) {
        struct pathinfo *path;
            
        path = lookup_pathinfo(&virt->network, src, sel_iface);
        if(path) {
            path->last_packet = jiffies;
            set_last_path(flow->flow_stats, path);
            virt_path_put(path);
        } else {
            /* TODO: Clean up this section of code.  We have the fallback
             * function here because setting the last path is important for
             * counting the number of flows bound to each link.  However,
             * lookup_pathinfo may return NULL for the first flow sent on a new
             * path. */
            set_last_path_fallback(flow->flow_stats, src, sel_iface);
        }

        sel_iface->rif.flow_count++;
    }

    return sel_iface;
}

/*
 * Test if interface is usable.
 * 
 * 1. iface has at least one active path or zero stalled paths.
 * 2. Its priority is at least min_prio.
 * 3. (if a local device) the DEVICE_NO_TX is not set.
 */
static bool interface_is_usable(const struct interface *iface, int min_prio)
{
    if(iface->type == INTERFACE_LOCAL) {
        struct device_node *device = container_of(iface, struct device_node, lif);
        if(device->flags & DEVICE_NO_TX)
            return 0;
    }

    return (iface->prio >= min_prio &&
            (iface->active_paths > 0 || iface->stalled_paths <= 0));
}


struct interface *first_sel_common(const struct list_head *interfaces, int min_prio)
{
    struct interface *ife;

    list_for_each_entry_rcu(ife, interfaces, list) {
        if(interface_is_usable(ife, min_prio))
            return ife;
    }

    return NULL;
}

struct device_node *first_sel_local(struct virt_priv *virt, struct flow_table_entry *flow, 
        const struct remote_node *dest, const struct list_head *interfaces)
{
    struct interface *iface = first_sel_common(interfaces, virt->max_dev_prio);

    if(iface) {
        struct device_node *dev_node = container_of(iface, struct device_node, lif);
        device_node_hold(dev_node);
        return dev_node;
    } else {
        return NULL;
    }
}

struct remote_link *first_sel_remote(struct virt_priv *virt, struct flow_table_entry *flow, 
        const struct device_node *src, const struct remote_node *dest,
        const struct list_head *interfaces)
{
    struct remote_link *link = NULL;
    struct interface *iface;

    rcu_read_lock();
    iface = first_sel_common(interfaces, dest->max_link_prio);
    if(iface) {
        link = container_of(iface, struct remote_link, rif);
        remote_link_hold(link);
    }
    rcu_read_unlock();

    return link;
}

static struct virt_alg first_alg = {
    .name = "first",
    .module = THIS_MODULE,
    .sel_local = first_sel_local,
    .sel_remote = first_sel_remote,
    .alg_list = LIST_HEAD_INIT(first_alg.alg_list),
};



struct interface *random_sel_common(const struct list_head *interfaces, int min_prio)
{
    unsigned num_ifaces = 0;
    unsigned selected;
    struct interface *iface;

    list_for_each_entry_rcu(iface, interfaces, list) {
        if(interface_is_usable(iface, min_prio))
            num_ifaces++;
    }

    if(num_ifaces == 0)
        return NULL;
    
    selected = random32() % num_ifaces;
    num_ifaces = 0;

    list_for_each_entry_rcu(iface, interfaces, list) {
        if(interface_is_usable(iface, min_prio)) {
            if(num_ifaces >= selected)
                break;
            else
                num_ifaces++;
        }
    }

    return iface;
}

struct device_node *random_sel_local(struct virt_priv *virt, struct flow_table_entry *flow, 
        const struct remote_node *dest, const struct list_head *interfaces)
{
    struct interface *iface = random_sel_common(interfaces, virt->max_dev_prio);

    if(iface) {
        struct device_node *dev_node = container_of(iface, struct device_node, lif);
        device_node_hold(dev_node);
        return dev_node;
    } else {
        return NULL;
    }
}

struct remote_link *random_sel_remote(struct virt_priv *virt, struct flow_table_entry *flow, 
        const struct device_node *src, const struct remote_node *dest,
        const struct list_head *interfaces)
{
    struct remote_link *link = NULL;
    struct interface *iface;

    rcu_read_lock();
    iface = random_sel_common(interfaces, dest->max_link_prio);
    if(iface) {
        link = container_of(iface, struct remote_link, rif);
        remote_link_hold(link);
    }
    rcu_read_unlock();

    return link;
}

static struct virt_alg random_alg = {
    .name = "random",
    .module = THIS_MODULE,
    .sel_local = random_sel_local,
    .sel_remote = random_sel_remote,
    .alg_list = LIST_HEAD_INIT(random_alg.alg_list),
};



struct device_node *dynamic_sel_local(struct virt_priv *virt, struct flow_table_entry *flow, 
        const struct remote_node *dest, const struct list_head *interfaces)
{
    struct interface *curr_ife;
    struct interface *best_ife = NULL;
    unsigned long min_delay = ULONG_MAX;

    if(WARN_ON(!dest))
        return NULL;

    if(unlikely(list_empty(interfaces)))
        return NULL;

    rcu_read_lock();
    list_for_each_entry(curr_ife, interfaces, list) {
        if(interface_is_usable(curr_ife, virt->max_dev_prio)) {
            struct device_node *dev_node = container_of(curr_ife, struct device_node, lif);
            struct remote_link *dest_link;

            list_for_each_entry_rcu(dest_link, &dest->links, rif.list) {
                struct pathinfo *path;
                unsigned long path_delay;

                path = lookup_pathinfo(&virt->network, dev_node, dest_link);

                /* Returns some value, even if path is null. */
                path_delay = pathinfo_est_delay(path);

                if(path)
                    virt_path_put(path);

                if(path_delay < min_delay) {
                    min_delay = path_delay;
                    best_ife = curr_ife;
                }
            }
        }
    }
    rcu_read_unlock();

    if(best_ife) {
        struct device_node *dev_node = container_of(best_ife, struct device_node, lif);
        device_node_hold(dev_node);

        return dev_node;
    } else {
        return NULL;
    }
}

struct remote_link *dynamic_sel_remote(struct virt_priv *virt, struct flow_table_entry *flow, 
        const struct device_node *src, const struct remote_node *dest,
        const struct list_head *interfaces)
{
    struct remote_link *best_ife = NULL;
    unsigned long min_delay = ULONG_MAX;
    struct remote_link *dest_link;
    
    if(WARN_ON(!dest))
        return NULL;

    if(unlikely(list_empty(interfaces)))
        return NULL;

    rcu_read_lock();

    list_for_each_entry_rcu(dest_link, &dest->links, rif.list) {
        if(interface_is_usable(&dest_link->rif, dest->max_link_prio)) {
            struct pathinfo *path;
            unsigned long path_delay;

            path = lookup_pathinfo(&virt->network, src, dest_link);

            /* Returns some value, even if path is null. */
            path_delay = pathinfo_est_delay(path);

            if(path)
                virt_path_put(path);

            if(path_delay < min_delay) {
                min_delay = path_delay;
                best_ife = dest_link;
            }
        }
    }

    if(best_ife)
        remote_link_hold(best_ife);

    rcu_read_unlock();

    return best_ife;
}

static struct virt_alg dynamic_alg = {
    .name = "dynamic",
    .module = THIS_MODULE,
    .sel_local = dynamic_sel_local,
    .sel_remote = dynamic_sel_remote,
    .alg_list = LIST_HEAD_INIT(dynamic_alg.alg_list),
};



static struct interface *wrr_sel_common(const struct list_head *interfaces, 
        int min_prio)
{
    struct interface *ife;

    long min_flows = LONG_MAX;
    long sel_bandwidth = LONG_MIN;
    long max_reserve = LONG_MIN;
    struct interface *sel_ife = NULL;

    bool use_min_flows = false;

    /* Find the maximum constant by which we can multiply all of the weights
     * without exceeding LONG_MAX.  We will then multiply by that constant so
     * that the subsequent integer division will have greater precision. */
    long wmult = LONG_MAX;
    list_for_each_entry_rcu(ife, interfaces, list) {
        if(interface_is_usable(ife, min_prio)) {
            if(ife->flow_count < min_flows || (ife->flow_count == min_flows &&
                        ife->bandwidth_hint > sel_bandwidth)) {
                min_flows = ife->flow_count;
                sel_bandwidth = ife->bandwidth_hint;
                sel_ife = ife;
            }

            if(ife->bandwidth_hint > 0) {
                long cand = LONG_MAX / ife->bandwidth_hint;
                if(cand < wmult)
                    wmult = cand;
            } else {
                use_min_flows = true;
            }
        }
    }

    /* If any of the eligible interfaces had an undefined bandwidth hint, then
     * we revert to round-robin based on flow_count. */
    if(use_min_flows)
        goto out;

    list_for_each_entry_rcu(ife, interfaces, list) {
        if(interface_is_usable(ife, min_prio)) {
            long reserve = (wmult * ife->bandwidth_hint) / (ife->flow_count + 1);
            if(reserve > max_reserve || (reserve == max_reserve && 
                        ife->bandwidth_hint > sel_bandwidth)) {
                max_reserve = reserve;
                sel_bandwidth = ife->bandwidth_hint;
                sel_ife = ife;
            }
        }
    }

out:
    return sel_ife;
}

struct device_node *wrr_sel_local(struct virt_priv *virt, struct flow_table_entry *flow, 
        const struct remote_node *dest, const struct list_head *interfaces)
{
    struct interface *iface = wrr_sel_common(interfaces, 
            virt->max_dev_prio);

    if(iface) {
        struct device_node *dev_node = container_of(iface, struct device_node, lif);
        device_node_hold(dev_node);
        return dev_node;
    } else {
        return NULL;
    }
}

struct remote_link *wrr_sel_remote(struct virt_priv *virt, struct flow_table_entry *flow, 
        const struct device_node *src, const struct remote_node *dest,
        const struct list_head *interfaces)
{
    struct remote_link *link = NULL;
    struct interface *iface;

    rcu_read_lock();
    iface = wrr_sel_common(interfaces, dest->max_link_prio);
    if(iface) {
        link = container_of(iface, struct remote_link, rif);
        remote_link_hold(link);
    }
    rcu_read_unlock();

    return link;
}

static struct virt_alg wrr_alg = {
    .name = "wrr",
    .module = THIS_MODULE,
    .sel_local = wrr_sel_local,
    .sel_remote = wrr_sel_remote,
    .alg_list = LIST_HEAD_INIT(wrr_alg.alg_list),
};



static struct interface *rr_sel_common(const struct list_head *interfaces, 
        int min_prio, unsigned int counter)
{
    unsigned num_ifaces = 0;
    unsigned selected;
    struct interface *iface;

    list_for_each_entry_rcu(iface, interfaces, list) {
        if(interface_is_usable(iface, min_prio))
            num_ifaces++;
    }

    if(num_ifaces == 0)
        return NULL;
    
    selected = counter % num_ifaces;
    num_ifaces = 0;

    list_for_each_entry_rcu(iface, interfaces, list) {
        if(interface_is_usable(iface, min_prio)) {
            if(num_ifaces >= selected)
                break;
            else
                num_ifaces++;
        }
    }

    return iface;
}

struct device_node *rr_sel_local(struct virt_priv *virt, struct flow_table_entry *flow, 
        const struct remote_node *dest, const struct list_head *interfaces)
{
    static unsigned int counter = 0;

    struct interface *iface = rr_sel_common(interfaces, 
            virt->max_dev_prio, counter++);

    if(iface) {
        struct device_node *dev_node = container_of(iface, struct device_node, lif);
        device_node_hold(dev_node);
        return dev_node;
    } else {
        return NULL;
    }
}

struct remote_link *rr_sel_remote(struct virt_priv *virt, struct flow_table_entry *flow, 
        const struct device_node *src, const struct remote_node *dest,
        const struct list_head *interfaces)
{
    static unsigned int counter = 0;

    struct remote_link *link = NULL;
    struct interface *iface;

    rcu_read_lock();
    iface = rr_sel_common(interfaces, dest->max_link_prio, counter++);
    if(iface) {
        link = container_of(iface, struct remote_link, rif);
        remote_link_hold(link);
    }
    rcu_read_unlock();

    return link;
}

static struct virt_alg rr_alg = {
    .name = "rr",
    .module = THIS_MODULE,
    .sel_local = rr_sel_local,
    .sel_remote = rr_sel_remote,
    .alg_list = LIST_HEAD_INIT(rr_alg.alg_list),
};


void path_release_flow(struct virt_network *net, struct flow_stats *flow)
{
    struct device_node *local_if;
    struct remote_link *remote_if;

    local_if = slave_get_by_addr(&flow->local_addr);
    if(local_if) {
        if(!WARN_ON(local_if->lif.flow_count <= 0))
            local_if->lif.flow_count--;
        device_node_put(local_if);
    }

    remote_if = find_remote_link_by_addr(net, &flow->remote_addr, flow->remote_port);
    if(remote_if) {
        if(!WARN_ON(remote_if->rif.flow_count <= 0))
            remote_if->rif.flow_count--;
        remote_link_put(remote_if);
    }

    memset(&flow->local_addr, 0, sizeof(flow->local_addr));
    memset(&flow->remote_addr, 0, sizeof(flow->remote_addr));
}

/*
 * Register all of the internal algorithms.
 */
int virt_register_algorithms(void)
{
    virt_register_alg(&first_alg);
    virt_register_alg(&random_alg);
    virt_register_alg(&dynamic_alg);
    virt_register_alg(&wrr_alg);
    virt_register_alg(&rr_alg);

    return 0;
}

