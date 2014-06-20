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
#include <linux/errno.h>

#include "virt.h"
#include "virtNetwork.h"
#include "virtRoute.h"

int virt_init_vroute_table(struct virt_priv *virt)
{
    if(!virt)
        return -ENODEV;

    INIT_LIST_HEAD(&virt->vroute_table);

    return 0;
}

void virt_free_vroute_table(struct virt_priv *virt)
{
    struct vroute *vroute;
    struct vroute *tmp;

    if(!virt)
        return;

    list_for_each_entry_safe(vroute, tmp, &virt->vroute_table, vroute_list) {
        list_del(&vroute->vroute_list);
        kfree(vroute);
    }
}

int virt_add_vroute(struct virt_priv *virt, 
                __be32 dest, __be32 netmask, __be32 node_ip)
{
    struct remote_node *node;
    struct vroute *vroute;
    struct vroute *new_vroute;
    struct list_head *insert;
    uint32_t h_netmask;

    if(!virt)
        return -ENODEV;

    if((dest & netmask) != dest)
        return -EINVAL;

    /* Check that the destination node exists. */
    node = find_remote_node_by_ip(&virt->network, (struct in_addr *)&node_ip);
    if(node)
        remote_node_put(node);
    else
        return -ENOENT;

    new_vroute = kzalloc(sizeof(struct vroute), GFP_KERNEL);
    if(!new_vroute)
        return -ENOMEM;

    new_vroute->dest    = dest;
    new_vroute->netmask = netmask;
    new_vroute->node_ip = node_ip;

    h_netmask = ntohl(netmask);

    if(list_empty(&virt->vroute_table)) {
        list_add(&new_vroute->vroute_list, &virt->vroute_table);
        return 0;
    }
    
    insert = &virt->vroute_table;
    list_for_each_entry(vroute, &virt->vroute_table, vroute_list) {
        /* Entries are stored in descending order, so the first time this
         * occurs will be the insertion point. */
        if(h_netmask >= ntohl(vroute->netmask)) {
            insert = &vroute->vroute_list;
            break;
        }
    }

    /* Prevent duplicate entries. */
    list_for_each_entry_from(vroute, &virt->vroute_table, vroute_list) {
        if(netmask == vroute->netmask) {
            if(dest == vroute->dest) {
                kfree(new_vroute);
                return -EEXIST;
            }
        } else {
            break;
        }
    }

    list_add_tail(&new_vroute->vroute_list, insert);
    return 0;
}

int virt_delete_vroute(struct virt_priv *virt,
                __be32 dest, __be32 netmask, __be32 node_ip)
{
    struct vroute *vroute;
    struct vroute *tmp;

    if(!virt)
        return -ENODEV;

    if((dest & netmask) != dest)
        return -EINVAL;

    list_for_each_entry_safe(vroute, tmp, &virt->vroute_table, vroute_list) {
        if(vroute->dest == dest &&
                vroute->netmask == netmask &&
                vroute->node_ip == node_ip) {
            list_del(&vroute->vroute_list);
            kfree(vroute);
            return 0;
        }
    }

    return -ENOENT;
}

__be32 virt_route(struct virt_priv *virt, __be32 dest)
{
    struct vroute *vroute;

    if(!virt)
        return 0;

    list_for_each_entry(vroute, &virt->vroute_table, vroute_list) {
        if((vroute->netmask & dest) == vroute->dest)
            return vroute->node_ip;
    }

    return 0;
}

