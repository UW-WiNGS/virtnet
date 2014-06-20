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

#ifndef _VIRT_RETRANSMISSION_H_
#define _VIRT_RETRANSMISSION_H_

#include <linux/spinlock.h>
#include <linux/timer.h>

struct flow_table_entry;
struct policy_entry;
struct sk_buff;

struct virt_retx {
    struct sk_buff *skb;
    unsigned long last_updated;
    unsigned long timeout_jiffies;

    struct timer_list timer;
    spinlock_t lock;
    bool restart_timer;
};

void virt_retx_init(struct virt_retx *retx, unsigned int timeout_usecs);
void virt_retx_destroy(struct virt_retx *retx);
void flow_set_retx_skb(struct flow_table_entry *flow, struct sk_buff *skb);

int flow_retx_enabled(const struct policy_entry *policy);

#endif /* _VIRT_RETRANSMISSION_H_ */
