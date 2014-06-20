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

#ifndef _VIRT_HASH_TABLE_
#define _VIRT_HASH_TABLE_

struct virt_hash_head {
    spinlock_t lock;
    struct hlist_head list;
};

struct virt_hash_table {
    struct virt_hash_head *head;

    unsigned bits;
    unsigned size;
};

int virt_hash_table_init(struct virt_hash_table *table, unsigned bits);
int virt_hash_table_add(struct virt_hash_table *table, struct hlist_node *entry, u32 hash);
int virt_hash_table_remove(struct virt_hash_table *table, struct hlist_node *entry, u32 hash);

#endif /* _VIRT_HASH_TABLE_ */
