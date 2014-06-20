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

#ifndef _VIRT_MEMORY_
#define _VIRT_MEMORY_

struct virt_mem_stats {
    const char *type;
    long alloc_count;
    long free_count;
};

enum virt_mem_type {
    REMOTE_NODE,
    REMOTE_LINK,
    PATHINFO,
    FLOW_TABLE_ENTRY,
    REORDER_ENTRY,
    XOR_ENTRY,
    MAX_VIRT_MEM_TYPE
};

void inc_alloc_count(enum virt_mem_type type);
void inc_free_count(enum virt_mem_type type);

struct seq_file;
int dump_mem_stats(struct seq_file *s, void *p);

void warn_on_memory_leaks(void);

#endif /* _VIRT_MEMORY_ */
