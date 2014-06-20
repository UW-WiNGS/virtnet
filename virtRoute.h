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

#ifndef _VIRT_ROUTE_
#define _VIRT_ROUTE_

#include <linux/list.h>

struct vroute {
    __be32  dest;
    __be32  netmask;
    __be32  node_ip;

    struct list_head vroute_list;
};

struct virt_priv;

int  virt_init_vroute_table(struct virt_priv *virt);
void virt_free_vroute_table(struct virt_priv *virt);

int  virt_add_vroute(struct virt_priv *virt, 
        __be32 dest, __be32 netmask, __be32 node_ip);
int  virt_delete_vroute(struct virt_priv *virt,
        __be32 dest, __be32 netmask, __be32 node_ip);

__be32 virt_route(struct virt_priv *virt, __be32 dest);

#endif /* _VIRT_ROUTE_ */

