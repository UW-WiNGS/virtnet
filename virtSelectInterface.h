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

#ifndef _VIRT_SELECT_INTERFACE_H_
#define _VIRT_SELECT_INTERFACE_H_

#include <linux/list.h>
#include "virtPolicyTypes.h"

/* Allows for 256 interfaces with maximum latency of 16 seconds.  Beyond that,
 * overflows will occur. */
#define MAX_WEIGHT      (ULONG_MAX / 256)

#define MIN_PACKET_SPACING      5000000

#define MAX_ALG_NAME_LEN        16

struct virt_priv;
struct packet;
struct device_node;
struct remote_node;
struct remote_link;
struct module;

struct virt_alg {
    const char *name;
    struct module *module;

    struct device_node *(*sel_local)
        (struct virt_priv *virt, struct flow_table_entry *flow, 
         const struct remote_node *dest,
         const struct list_head *interfaces);
    struct remote_link *(*sel_remote)
        (struct virt_priv *virt, struct flow_table_entry *flow, 
         const struct device_node *src, const struct remote_node *dest,
         const struct list_head *interfaces);

    struct list_head alg_list;
};

int virt_register_alg(struct virt_alg *alg);
int virt_unregister_alg(struct virt_alg *alg);
struct virt_alg *virt_alg_get_by_name(const char *name);

struct device_node *select_local_interface(struct virt_priv *virt, struct flow_table_entry *flow,
        const struct remote_node *dest, const struct list_head *interfaces);
struct remote_link *select_remote_interface(struct virt_priv *virt, struct flow_table_entry *flow,
        const struct device_node *src, const struct remote_node *dest,
        const struct list_head *interfaces);

void path_release_flow(struct virt_network *net, struct flow_stats *flow);

int virt_register_algorithms(void);

#endif /* _VIRT_SELECT_INTERFACE_H_ */

