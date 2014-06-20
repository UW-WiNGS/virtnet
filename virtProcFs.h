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

#ifndef _VIRT_PROC_FS_H__
#define _VIRT_PROC_FS_H__

#include <linux/types.h>

#define PROC_REMOTE_ADD     0
#define PROC_REMOTE_DELETE  1

struct policy_list_entry;

struct virt_proc_policy_iter {
    loff_t pos;
    int table;
    struct list_head *entry;

    struct virt_priv *virt;
};

struct virt_proc_remote_node {
    unsigned op;
    struct in_addr priv_ip;
} __attribute__((__packed__));

struct virt_proc_remote_link {
    unsigned    op;

    // priv_ip identifies the node to which this link belongs, so the node must
    // be added before a link is added.
    struct in_addr priv_ip;
    struct in_addr pub_ip;
    __be16 data_port;
} __attribute__((__packed__));

int virt_setup_proc(struct net_device *master);
int virt_cleanup_proc(struct virt_priv *virt);


#endif //_VIRT_PROC_FS_H__
