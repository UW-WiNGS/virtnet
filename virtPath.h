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

#ifndef _VIRT_PATH_
#define _VIRT_PATH_

#include <linux/types.h>

enum {
    LOCAL_BANDWIDTH_HINT = 0,
    REMOTE_BANDWIDTH_HINT,
};

struct virt_perf_hint {
    int type;

    union {
        int local_dev;
        __be32 remote_addr;
    } vph_dev;
#define vph_local_dev vph_dev.local_dev
#define vph_remote_addr vph_dev.remote_addr

    long bandwidth;
};

struct net_device;

int local_bandwidth_hint(struct net_device *master, const struct virt_perf_hint *hint);
int remote_bandwidth_hint(struct net_device *master, const struct virt_perf_hint *hint);

#endif /* _VIRT_PATH_ */
