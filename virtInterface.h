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

#ifndef _VIRT_INTERFACE_H_
#define _VIRT_INTERFACE_H_

#include <linux/list.h>

#define DEFAULT_DEVICE_PRIORITY 0
#define MAX_DEVICE_PRIORITY 127
#define MIN_DEVICE_PRIORITY -128
#define MIN_USABLE_DEVICE_PRIORITY 0

/*
 * The interface structure is an abstraction used for both physical interfaces
 * and remote interfaces.
 */

enum interface_type {
    INTERFACE_UNKNOWN = 0,
    INTERFACE_LOCAL,
    INTERFACE_REMOTE,
};

struct interface {
    struct list_head list;

    enum interface_type type;

    __be32 ip4;
    __be16 data_port;

    unsigned    est_delay;
    long flow_count;

    long bandwidth_hint;

    /* Number of active and stalled paths using this interface. */
    int active_paths;
    int stalled_paths;

    int prio;
};

#endif //_VIRT_INTERFACE_H_

