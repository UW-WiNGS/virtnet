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

#include <linux/bug.h>
#include <linux/seq_file.h>

#include "virtMemory.h"
#include "virtDebug.h"

static struct virt_mem_stats mem_stats[] = {
    [REMOTE_NODE]       = {"remote_node",       0, 0},
    [REMOTE_LINK]       = {"remote_link",       0, 0},
    [PATHINFO]          = {"pathinfo",          0, 0},
    [FLOW_TABLE_ENTRY]  = {"flow_table_entry",  0, 0},
    [REORDER_ENTRY]     = {"reorder_entry",     0, 0},
    [XOR_ENTRY]         = {"xor_entry",         0, 0},
};

void inc_alloc_count(enum virt_mem_type type)
{
    if(WARN_ON(type >= MAX_VIRT_MEM_TYPE))
        return;
    mem_stats[type].alloc_count++;
}

void inc_free_count(enum virt_mem_type type)
{
    if(WARN_ON(type >= MAX_VIRT_MEM_TYPE))
        return;
    mem_stats[type].free_count++;
}

int dump_mem_stats(struct seq_file *s, void *p)
{
    int i;

    //             xxxxxxxxxxxxxxxx xxxxxxxxx xxxxxxxxx
    seq_printf(s, "type             allocated freed    \n");

    for(i = 0; i < MAX_VIRT_MEM_TYPE; i++) {
        seq_printf(s, "%-16s %9ld %9ld\n",
                mem_stats[i].type,
                mem_stats[i].alloc_count,
                mem_stats[i].free_count);
    }

    return 0;
}

void warn_on_memory_leaks()
{
    int i;

    for(i = 0; i < MAX_VIRT_MEM_TYPE; i++) {
        long diff = mem_stats[i].alloc_count - mem_stats[i].free_count;

        if(diff > 0) {
            printk(KERN_ALERT "Warning: %ld %s objects were leaked.\n",
                    diff, mem_stats[i].type);
        } else if(diff < 0) {
            printk(KERN_ALERT "Warning: %ld %s objects were freed without being allocated.\n",
                    diff, mem_stats[i].type);
        }
    }
}
