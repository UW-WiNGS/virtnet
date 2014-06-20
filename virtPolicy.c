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

#include <linux/netdevice.h>

#include "virt.h"      // struct packet
#include "virtDebug.h"
#include "virtParse.h" // struct flow_tuple
#include "virtPolicy.h"
#include "virtPolicyTypes.h"
#include "virtSelectInterface.h"

const __u32 DEFAULT_POLICY_EGRESS = POLICY_ACT_NAT;
const __u32 DEFAULT_POLICY_INGRESS = POLICY_ACT_PASS;

//////////////////////////////////////
// DATA structure management functions 
//////////////////////////////////////

void policy_list_init(struct policy_head *head)
{
    spin_lock_init(&head->lock);
    INIT_LIST_HEAD(&head->list);
}

/*
 * Add a policy entry to list.  Assumes the entry is not already part of a list.
 *
 * row specifies where in the list to insert the new entry.
 *
 * row < 0: append to tail
 * row = 0: insert at head
 * row > 0: insert after the row'th entry
 */
void policy_list_add(struct policy_head *head, struct policy_entry *entry, int row)
{
    struct list_head *curr;

    spin_lock_bh(&head->lock);

    atomic_inc(&entry->refcnt);

    if(row < 0) {
        list_add_tail_rcu(&entry->list, &head->list);
    } else if(row == 0) {
        list_add_rcu(&entry->list, &head->list);
    } else {
        int i = 0;
        int added = 0;

        list_for_each(curr, &head->list) {
            if(++i >= row) {
                list_add_rcu(&entry->list, curr);
                added = 1;
                break;
            }
        }

        if(!added)
            list_add_tail_rcu(&entry->list, &head->list);
    }
    
    spin_unlock_bh(&head->lock);
}

/*
 * Remove entry from its policy list and decrement its refcnt.  If it becomes
 * zero, entry will be freed.
 *
 * Must be called with the list's lock held.
 */
static void policy_list_remove(struct policy_entry *entry)
{
    list_del_rcu(&entry->list);
    policy_put(entry);
}

/*
 * Remove all entries from the policy list and decrement their reference counters.
 */
void policy_list_flush(struct policy_head *head)
{
    struct policy_entry *entry;
    struct policy_entry *tmp;

    spin_lock_bh(&head->lock);
    list_for_each_entry_safe(entry, tmp, &head->list, list) {
        policy_list_remove(entry);
    }
    spin_unlock_bh(&head->lock);
}

void policy_list_destroy(struct policy_head *head)
{
    struct policy_entry *entry;
    struct policy_entry *tmp;

    spin_lock_bh(&head->lock);
    list_for_each_entry_safe(entry, tmp, &head->list, list) {
        list_del_rcu(&entry->list);
        policy_put(entry);
    }
    spin_unlock_bh(&head->lock);
}

/*
 * Increment a policy_entry's refcnt.
 */
void policy_hold(struct policy_entry *policy)
{
    if(WARN_ON(!policy))
        return;

    atomic_inc(&policy->refcnt);
}

/*
 * Decrement a policy_entry's refcnt and free if it reaches zero.
 */
void policy_put(struct policy_entry *policy)
{
    if(WARN_ON(!policy))
        return;

    if(atomic_dec_and_test(&policy->refcnt)) {
        kfree_rcu(policy, rcu);
    }
}

/*
 * Initialize the policy lists.
 */
void virt_policy_setup(struct virt_priv *virt)
{
    policy_list_init(&virt->policy_list_flow_egress);
    policy_list_init(&virt->policy_list_flow_ingress);
    policy_list_init(&virt->policy_list_app_egress);
    policy_list_init(&virt->policy_list_app_ingress);

    virt->policy_default_egress.action = DEFAULT_POLICY_EGRESS;
    virt->policy_default_egress.alg = virt_alg_get_by_name("wrr");
    atomic_set(&virt->policy_default_egress.refcnt, 1);

    virt->policy_default_ingress.action = DEFAULT_POLICY_INGRESS;
    virt->policy_default_egress.alg = virt_alg_get_by_name("wrr");
    atomic_set(&virt->policy_default_ingress.refcnt, 1);
}

/*
 * Cleanup the policy lists and free the memory.
 */
void virt_policy_cleanup(struct virt_priv *virt)
{
    policy_list_destroy(&virt->policy_list_flow_egress);
    policy_list_destroy(&virt->policy_list_flow_ingress);
    policy_list_destroy(&virt->policy_list_app_egress);
    policy_list_destroy(&virt->policy_list_app_ingress);
}

struct policy_entry *policy_lookup_flow(struct policy_head *head, const struct flow_tuple *key)
{
    struct policy_entry *curr;

    VIRT_DBG("lookup: %pI4:%hu - %pI4:%hu\n",
            &key->sAddr, ntohs(key->sPort),
            &key->dAddr, ntohs(key->dPort));

    rcu_read_lock();
    list_for_each_entry_rcu(curr, &head->list, list) {
        if( ((key->dAddr & curr->flow.dst_netmask) == curr->flow.dst_addr) &&
            ((key->sAddr & curr->flow.src_netmask) == curr->flow.src_addr) &&
            ((key->dPort == curr->flow.dst_port) || (curr->flow.dst_port == 0)) &&
            ((key->sPort == curr->flow.src_port) || (curr->flow.src_port == 0)) &&
            ((key->proto == curr->flow.proto) || (curr->flow.proto == 0)) ) {
            policy_hold(curr);
            rcu_read_unlock();
            return curr;
        }
    }
    rcu_read_unlock();

    return NULL;
}

/*
 * Get default policy.
 */
static struct policy_entry *get_default_policy(struct virt_priv *virt, struct packet *pkt, int table)
{
    if(table == EGRESS) {
        policy_hold(&virt->policy_default_egress);
        return &virt->policy_default_egress;
    } else if(table == INGRESS) {
        policy_hold(&virt->policy_default_ingress);
        return &virt->policy_default_ingress;
    } else {
        VIRT_DBG("Unrecognized table: %d\n", table);
        return NULL;
    }
}

/*
 * Get the appropriate list head for the given type and table.
 */
static struct policy_head *get_policy_list(struct virt_priv *virt, int type, int table)
{
    switch(type) {
        case POLICY_TYPE_FLOW:
            switch(table) {
                case EGRESS:
                    return &virt->policy_list_flow_egress;
                case INGRESS:
                    return &virt->policy_list_flow_ingress;
                default:
                    VIRT_DBG("Unsupported flow table: %d\n", table);
                    return NULL;
            }
        case POLICY_TYPE_APP:
            switch(table) {
                case EGRESS:
                    return &virt->policy_list_app_egress;
                case INGRESS:
                    return &virt->policy_list_app_ingress;
                default:
                    VIRT_DBG("Unsupported app table: %d\n", table);
                    return NULL;
            }
        default:
            VIRT_DBG("Unsupported policy type: %d\n", type);
            return NULL;
    }
}


/*
 * Search all policies for matching to current flow/packet.
 */
struct policy_entry *virt_policy_lookup(struct virt_priv *virt, struct packet *pkt, int table)
{
    struct policy_head *flow_head;
    struct policy_entry *flow_entry;
    struct flow_tuple reversed_key;
    const struct flow_tuple *key = pkt->key;

    flow_head = get_policy_list(virt, POLICY_TYPE_FLOW, table);
    if(!flow_head)
        goto return_default;

    if(table == INGRESS) {
        reversed_key.dAddr = pkt->key->sAddr;
        reversed_key.sAddr = pkt->key->dAddr;
        reversed_key.dPort = pkt->key->sPort;
        reversed_key.sPort = pkt->key->dPort;
        reversed_key.proto = pkt->key->proto;
        reversed_key.net_proto = pkt->key->net_proto;
        key = &reversed_key;
    }
    
    flow_entry = policy_lookup_flow(flow_head, key);
    if(!flow_entry)
        goto return_default;

    return flow_entry;

return_default:
    return get_default_policy(virt, pkt, table);
}

/*
 * Add policy to proper list.
 */
static int policy_add(struct virt_priv *virt, struct policy_entry *policy, int row)
{
    struct policy_head *head;

    head = get_policy_list(virt, policy->type, policy->table);
    if(!head)
        return -EINVAL;

    policy_list_add(head, policy, row);
    
    return 0;
}

static int policy_equal(const struct policy_entry *a, const struct policy_entry *b)
{
    return ((a->flow.dst_addr    == b->flow.dst_addr) &&
            (a->flow.src_addr    == b->flow.src_addr) &&
            (a->flow.dst_netmask == b->flow.dst_netmask) &&
            (a->flow.src_netmask == b->flow.src_netmask) &&
            (a->flow.dst_port    == b->flow.dst_port) &&
            (a->flow.src_port    == b->flow.src_port) &&
            (a->flow.net_proto   == b->flow.net_proto) &&
            (a->action           == b->action) &&
            (!a->alg || !b->alg || a->alg == b->alg));
}

/*
 * Delete policy from proper list.
 *
 * If row is negative, delete the first policy that matches the specification.
 * If row is non-negative, delete the row'th policy.
 */
//TODO: create subfunctions
static int policy_del(struct virt_priv *virt, struct policy_entry *policy, int row)
{
    struct policy_head *head;
    struct policy_entry *curr;
    struct policy_entry *tmp;
    int i = 0;
    int found = 0;

    if( policy->type == POLICY_TYPE_FLOW ) {
        if( policy->table == EGRESS ) {
            head = &virt->policy_list_flow_egress;
        } else if( policy->table == INGRESS ) {
            head = &virt->policy_list_flow_ingress;
        } else {
            return -EINVAL;
        }

        spin_lock_bh(&head->lock);
        list_for_each_entry_safe(curr, tmp, &head->list, list) {
            if( (row >= 0 && i++ == row) || 
                    (row < 0 && policy_equal(curr, policy)) ) {

                found = 1;

                policy_list_remove(curr);

                break;
            }
        }
        spin_unlock_bh(&head->lock);
    } else if( policy->type == POLICY_TYPE_APP ) {
        if( policy->table == EGRESS ) {
            head = &virt->policy_list_app_egress;
        } else if( policy->table == INGRESS ) {
            head = &virt->policy_list_app_ingress;
        } else {
            return -EINVAL;
        }

        spin_lock_bh(&head->lock);
        list_for_each_entry_safe(curr, tmp, &head->list, list) {
            if( (row >= 0 && i++ == row) || (row < 0 &&
                    strcmp(curr->app.app_name, policy->app.app_name) == 0)) {
                found = 1;

                policy_list_remove(curr);

                break;
            }
        }
        spin_unlock_bh(&head->lock);
    } else if( policy->type == POLICY_TYPE_DEV ) {
        // get device node struct
        // iterate list on device and remove if a match
        return -EINVAL;
    } else {
        //unknown type
        return -EINVAL;
    }

    if(found)
        return 0;
    else
        return -ENOENT;
}

static int policy_flush(struct virt_priv *virt, struct policy_entry *policy)
{
    struct policy_head *head;

    head = get_policy_list(virt, policy->type, policy->table);
    if(!head)
        return -EINVAL;

    policy_list_flush(head);

    return 0;
}

/*
 * Perform policy operation to add, remove, update, or flush policies.
 */
int virt_policy(struct virt_priv *virt, struct policy_entry *policy, int command, int row)
{
    int rtn = 0;

    switch(command) {
        case POLICY_CMD_APPEND:
            rtn = policy_add(virt, policy, POLICY_ROW_NONE);
            break;
        case POLICY_CMD_DELETE:
            rtn = policy_del(virt, policy, row);
            break;
        case POLICY_CMD_INSERT:
            /* Default to inserting at top if row is not specified. */
            if(row < 0)
                row = 0;
            rtn = policy_add(virt, policy, row);
            break;
        case POLICY_CMD_REPLACE:
            /* Row must be specified for replace command to work properly. */
            if(row < 0)
                return -EINVAL;

            rtn = policy_del(virt, policy, row);
            if(rtn == 0)
                rtn = policy_add(virt, policy, row);

            break;
        case POLICY_CMD_FLUSH:
            rtn = policy_flush(virt, policy);
            break;
        default:
            VIRT_DBG("Unrecognized command: %d", command);
    }

    return rtn;
}

