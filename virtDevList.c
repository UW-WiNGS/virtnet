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

#include <linux/module.h>
#include <linux/version.h>

#include <linux/sched.h>
#include <linux/kernel.h>

#include <linux/in.h>
#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/inetdevice.h>  /* struct in_device, __in_dev_get */
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/udp.h>         /* struct udphdr */
#include <linux/skbuff.h>

#include "virt.h"
#include "virtDebug.h"
#include "virtDevList.h"
#include "virtPassive.h"

static struct list_head slave_list_head_ = LIST_HEAD_INIT(slave_list_head_);


/* ------------ device_node linked list functions ------------- */

int get_num_slaves(void)
{
    return NUM_DEVS;
}


/*
 * get_slave_list_head: (global)
 *      return linked list head
 *
 * global access funtions for slave device linked list
 */
struct list_head *get_slave_list_head(void)
{
    return &slave_list_head_;
}

/* //TODO: add locking for these add/del functions
 * slave_list_add_node: (local)
 *      add a device to the linked list
 * slave_list_del_node: (local)
 *      remove a device from the linked list
 *
 * low level list managment funtions
 */
int slave_list_add_node(struct device_node *dev)
{
    list_add_tail(&dev->lif.list, &slave_list_head_);

    return 0;
}

int slave_list_del_node(struct device_node *dev)
{
    list_del(&dev->lif.list);

    return 0;
}

/*
 * Search slave list by interface name.  Does not increment the reference count.
 */
static struct device_node *__slave_get_by_name(const char *name)
{
    struct device_node *curr;

    //TODO: read_lock(&bond->lock) read_unlock(&bond->lock)
    list_for_each_entry(curr, &slave_list_head_, lif.list) {
        if( strncmp(name, curr->dev->name, IFNAMSIZ) == 0 ) {
            return curr;
        }
    }

    return NULL;
}

/*
 * slave_get_by_name: (local)
 *      search device list given the device's name
 *
 * Increments the reference count of the device_node, so the caller
 * should call device_node_put when done.
 */
struct device_node *slave_get_by_name(const char *name)
{
    struct device_node *dev = __slave_get_by_name(name);
    if(dev)
        device_node_hold(dev);

    return dev;   
}

/*
 * Increments the reference count of the device_node, so the caller
 * should call device_node_put when done.
 */
struct device_node *slave_get_by_ifindex(int ifindex)
{
    struct device_node *curr;

    //TODO: read_lock(&bond->lock) read_unlock(&bond->lock)
    list_for_each_entry(curr, &slave_list_head_, lif.list) {
        if( curr->dev->ifindex == ifindex ) {
            device_node_hold(curr);
            return curr;
        }
    }

    return NULL;   
}

/*
 * Increments the reference count of the device_node, so the caller
 * should call device_node_put when done.
 */
struct device_node *slave_get_by_addr(const struct in_addr *addr)
{
    struct device_node *curr;

    //TODO: read_lock(&bond->lock) read_unlock(&bond->lock)
    list_for_each_entry(curr, &slave_list_head_, lif.list) {
        if(curr->lif.ip4 == addr->s_addr) {
            device_node_hold(curr);
            return curr;
        }
    }

    return NULL;   
}

/*
 * Requires that RTNL lock is held, which is true for ioctl and netlink calls.
 */
int virt_add_slave(struct net_device *dev, struct net_device *slave_dev)
{
    struct device_node *new_slave;
    struct virt_priv *priv;

    // Make sure device is not already enslaved
    if(__slave_get_by_name(slave_dev->name))
        return 0;

    // Create the new node and initialize the values
    new_slave = kmalloc(sizeof(struct device_node), GFP_KERNEL);
    if(!new_slave)
        return -ENOMEM;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    netdev_set_bond_master(slave_dev, dev);
#else
    netdev_set_master(slave_dev, dev);
#endif

    priv = netdev_priv(dev);

    memset(new_slave, 0, sizeof(struct device_node));
    new_slave->master = dev;
    new_slave->dev = slave_dev;
    new_slave->flags = 0;

    new_slave->lif.type = INTERFACE_LOCAL;
    new_slave->lif.prio = DEFAULT_DEVICE_PRIORITY;
    new_slave->lif.ip4 = inet_select_addr(slave_dev, 0, RT_SCOPE_UNIVERSE);

    if(new_slave->lif.prio > priv->max_dev_prio)
        priv->max_dev_prio = new_slave->lif.prio;

    atomic_set(&new_slave->refcnt, 1);

    // add the node to the slave list
    slave_list_add_node(new_slave);

    return 0;
}

/*
 * Requires that RTNL lock is held, which is true for ioctl and netlink calls.
 */
int virt_del_slave(struct net_device *dev, struct net_device *slave_dev)
{
    struct device_node *temp;
    struct virt_priv *priv;

    // Make sure device is part of the list
    temp = __slave_get_by_name(slave_dev->name);
    if(!temp)
        return 0;

    priv = netdev_priv(dev);

    // Remove the slave from the list
    slave_list_del_node(temp);

    // Inform anyone holding a reference to the device_node that they should drop it.
    temp->flags |= DEVICE_NO_TX;
    
    // Update the global priority level
    if(temp->lif.prio >= priv->max_dev_prio) {
        temp->lif.prio = MIN_DEVICE_PRIORITY; /* Need flows to stop using this device. */
        priv->max_dev_prio = find_max_dev_prio();
    }

    /* netdev_set_bond_master will decrement the refcnt on the slave device,
     * but we want to hold a reference to the device until the device_node is
     * finally destroyed. */
    dev_hold(slave_dev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    netdev_set_bond_master(slave_dev, NULL);
#else
    netdev_set_master(slave_dev, NULL);
#endif

    remove_paths_from_local(&priv->network, temp);

    // If there are no outstanding references to the device, it will be freed.
    device_node_put(temp);

    return 0;
}

/*
 * dev_list_destroy: (global)
 *      remove all devices from the linked list and free mem
 */
int slave_list_destroy(struct net_device *master)
{
    struct device_node *curr, *tmp;
    struct virt_priv *priv = netdev_priv(master);

    list_for_each_entry_safe(curr, tmp, &slave_list_head_, lif.list) {
        // Remove the slave from the list
        slave_list_del_node(curr);

        // Inform anyone holding a reference to the device_node that they should drop it.
        curr->flags |= DEVICE_NO_TX;

        /* Need to hold RTNL lock for netdev_set_bond_master */
        rtnl_lock();

        /* netdev_set_bond_master will decrement the refcnt on the slave device,
         * but we want to hold a reference to the device until the device_node is
         * finally destroyed. */
        dev_hold(curr->dev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
        netdev_set_bond_master(curr->dev, NULL);
#else
        netdev_set_master(curr->dev, NULL);
#endif
        
        rtnl_unlock();

        // If there are no outstanding references to the device, it will be freed.
        device_node_put(curr);
    }
        
    // Update the global priority level
    priv->max_dev_prio = DEFAULT_DEVICE_PRIORITY;

    return 0;
}

/*
 * Increments the device_node reference count.
 */
void device_node_hold(struct device_node *dev)
{
    atomic_inc(&dev->refcnt);
}

/*
 * Decrements the device_node reference count and frees it if the count reaches
 * zero.
 */
void device_node_put(struct device_node *dev)
{
    if(atomic_dec_and_test(&dev->refcnt)) {
        dev_put(dev->dev);

        kfree(dev);
    }
}

/*
 * Find the maximum priority out of the device list.
 */
int find_max_dev_prio(void)
{
    int max_prio = MIN_USABLE_DEVICE_PRIORITY;
    struct device_node *curr;

    list_for_each_entry(curr, &slave_list_head_, lif.list) {
        if(curr->lif.prio > max_prio && 
                (curr->lif.active_paths > 0 || curr->lif.stalled_paths <= 0))
            max_prio = curr->lif.prio;
    }

    return max_prio;
}


