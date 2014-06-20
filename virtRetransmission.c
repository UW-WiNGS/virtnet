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
#include <linux/skbuff.h>
#include <linux/spinlock.h>

#include "virtRetransmission.h"
#include "virtEgress.h"
#include "virtNetwork.h"
#include "virtPolicy.h"
#include "virtPolicyTypes.h"
#include "virtFlowTable.h"

static void retx_timer_fn(unsigned long arg)
{
    struct virt_retx *retx = (struct virt_retx *)arg;

    unsigned long next_timer_base = jiffies;

    struct sk_buff *skb = NULL;
    struct virt_skb_cb *skb_cb;
    struct flow_table_entry *flow;
    struct remote_node *dest;

    spin_lock_bh(&retx->lock);
    if(retx->skb)
        skb = skb_clone(retx->skb, GFP_ATOMIC);
    spin_unlock_bh(&retx->lock);

    if(!skb)
        goto out;

    skb_cb = (struct virt_skb_cb *)skb->cb;
    if(WARN_ON(!skb_cb))
        goto out;

    flow = skb_cb->flow;
    if(WARN_ON(!flow))
        goto out;

    dest = flow->rnode;
    if(WARN_ON(!dest))
        goto out;

    if(afterl(flow->last_touched, retx->last_updated)) {
        next_timer_base = flow->last_touched;
        retx->last_updated = flow->last_touched;
        consume_skb(skb);
    } else {
        if(skb_queue_empty(&dest->tx_queue) && dest->link_count > 0) {
            flow_table_entry_hold(flow);
            virt_start_tx(skb_cb->virt, skb, dest);
        } else {
            consume_skb(skb);
        }
    }

out:
    spin_lock_bh(&retx->lock);
    if(retx->restart_timer)
        mod_timer(&retx->timer, next_timer_base + retx->timeout_jiffies);
    spin_unlock_bh(&retx->lock);
}

void virt_retx_init(struct virt_retx *retx, unsigned int timeout_usecs)
{
    retx->skb = NULL;
    retx->last_updated = 0;
    retx->timeout_jiffies = usecs_to_jiffies(timeout_usecs);

    retx->restart_timer = true;

    init_timer(&retx->timer);
    retx->timer.data = (unsigned long)retx;
    retx->timer.function = retx_timer_fn;

    spin_lock_init(&retx->lock);
}

void virt_retx_destroy(struct virt_retx *retx)
{
    spin_lock_bh(&retx->lock);
    if(retx->skb)
        consume_skb(retx->skb);
    retx->restart_timer = false;
    spin_unlock_bh(&retx->lock);

    del_timer_sync(&retx->timer);
}

void flow_set_retx_skb(struct flow_table_entry *flow, struct sk_buff *skb)
{
    spin_lock_bh(&flow->retx.lock);

    if(flow->retx.skb)
        consume_skb(flow->retx.skb);

    flow->retx.skb = skb_clone(skb, GFP_ATOMIC);
    flow->retx.last_updated = flow->last_touched;

    if(flow->retx.restart_timer)
        mod_timer(&flow->retx.timer, flow->last_touched + flow->retx.timeout_jiffies);

    spin_unlock_bh(&flow->retx.lock);
}

int flow_retx_enabled(const struct policy_entry *policy)
{
    return (policy->action & POLICY_OP_RETX);
}

