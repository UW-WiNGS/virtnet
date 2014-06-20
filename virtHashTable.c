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
#include <linux/rculist.h>

#include "virtHashTable.h"

/*
 * Allocate space for the hash table.  The size is 2^bits.
 */
int virt_hash_table_init(struct virt_hash_table *table, unsigned bits)
{
    const unsigned table_size = 1u << bits;
    int i;

    table->head = kmalloc(table_size * sizeof(struct virt_hash_head), GFP_KERNEL);
    if(!table->head)
        return -ENOMEM;

    for(i = 0; i < table_size; i++) {
        struct virt_hash_head *head = &table->head[i];
        spin_lock_init(&head->lock);
        INIT_HLIST_HEAD(&head->list);
    }

    table->bits = bits;
    table->size = table_size;

    return 0;
}

/*
 * Add an entry to the hash table.
 */
int virt_hash_table_add(struct virt_hash_table *table, struct hlist_node *entry, u32 hash)
{
    struct virt_hash_head *head = &table->head[hash];

    if(WARN_ON(hash >= table->size))
        return -1;

    spin_lock_bh(&head->lock);
    hlist_add_head_rcu(entry, &head->list);
    spin_unlock_bh(&head->lock);

    return 0;
}

/*
 * Remove an entry from the hash table.  Does not free any memory.
 */
int virt_hash_table_remove(struct virt_hash_table *table, struct hlist_node *entry, u32 hash)
{
    struct virt_hash_head *head = &table->head[hash];

    if(WARN_ON(hash >= table->size))
        return -1;

    spin_lock_bh(&head->lock);
    hlist_del_rcu(entry);
    spin_unlock_bh(&head->lock);

    return 0;
}

