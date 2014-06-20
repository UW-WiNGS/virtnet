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

#include <linux/netdevice.h>

#include "virt.h"
#include "virtPath.h"
#include "virtDevList.h"
#include "virtPassive.h"
#include "virtDebug.h"
#include "virtNetwork.h"

/*
 * TODO Right now, this uses some messy code to work with the existing pathinfo
 * list and remote node table.  Those should eventually be refactored, perhaps
 * into a single data structure.  The user-level should be able to add and remove
 * paths in addition to supplying performance hints.
 */

int local_bandwidth_hint(struct net_device *master, const struct virt_perf_hint *hint)
{
    struct device_node *device;

    if(hint->bandwidth < 0)
        return -EINVAL;

    device = slave_get_by_ifindex(hint->vph_local_dev);
    if(!device)
        return -ENOENT;

    device->lif.bandwidth_hint = hint->bandwidth;

    device_node_put(device);

    return 0;
}

int remote_bandwidth_hint(struct net_device *master, const struct virt_perf_hint *hint)
{
    struct virt_priv *virt = netdev_priv(master);
    struct remote_link *link;

    if(hint->bandwidth < 0)
        return -EINVAL;

    /* TODO: API needs to be updated to allow specifying remote link by IP address and port. */
    link = find_remote_link_by_ip(&virt->network, 
            (struct in_addr *)&hint->vph_remote_addr);
    if(!link)
        return -ENOENT;

    link->rif.bandwidth_hint = hint->bandwidth;

    remote_link_put(link);

    return 0;
}

