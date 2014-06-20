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
#include <linux/kernel.h> /* printk() */
#include <linux/slab.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/in.h>
#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/inetdevice.h>  /* struct in_device, __in_dev_get */
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <net/arp.h>
#include <net/ndisc.h>
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/udp.h>         /* struct udphdr */
#include <linux/skbuff.h>

#include "virt.h"
#include "virtIoctl.h"
#include "virtDebug.h"
#include "virtDevList.h"
#include "virtHeader.h"
#include "virtRoute.h"
#include "virtPassive.h"
#include "virtPolicy.h"
#include "virtPolicyTypes.h"
#include "virtNetwork.h"
#include "virtSelectInterface.h"
#include "virtPath.h"

static int ioctl_enslave(struct net_device *master_dev, struct ifreq *ifr);
static int ioctl_release(struct net_device *master_dev, struct ifreq *ifr);

/*
 * This function adds a device to the slave list and sends
 * a arp point to init the next_hop_mac address
 */
static int ioctl_enslave(struct net_device *master_dev, struct ifreq *ifr)
{
    int rc = 0;
    struct net_device *slave_dev;

    VIRT_DBG("calling ioctl_enslave device: %s\n", ifr->ifr_slave);

    // dev_get_by_name increments refcnt on slave_dev
    slave_dev = dev_get_by_name(&init_net, ifr->ifr_slave);
    if(!slave_dev)
        return -ENODEV;

    rc = virt_add_slave(master_dev, slave_dev);

    dev_put(slave_dev);

    return rc;
}

static int ioctl_release(struct net_device *master_dev, struct ifreq *ifr)
{
    int rc = 0;
    struct device_node *slave;

    VIRT_DBG("calling ioctl_release device: %s\n", ifr->ifr_slave);

    /* If the device disappears, dev_get_by_name will return NULL even though
     * we might still hold a reference to the net_device.  Therefore, we need
     * to query our internal list for the device instead of calling
     * dev_get_by_name. */
    slave = slave_get_by_name(ifr->ifr_slave);
    if(!slave)
        return -ENODEV;

    rc = virt_del_slave(master_dev, slave->dev);

    device_node_put(slave);

    return rc;
}

static int ioctl_setgwaddr(const struct ifreq *ifr)
{
    struct gwaddr_req gwaddr;
    struct device_node *slave = 0;
    struct net_device *dev = 0;

    if( copy_from_user(&gwaddr, ifr->ifr_data, sizeof(gwaddr)) != 0 )
        return -EINVAL;

    slave = slave_get_by_name(gwaddr.ifname);
    if(!slave)
        return -ENODEV;

    dev = slave->dev;

    if(gwaddr.family == AF_INET) {
        slave->gw_ip4 = gwaddr.gwaddr_ip4;

        if(slave->gw_ip4) {
            struct neighbour *neigh;

            // Try to find the next hop in the ARP table.  If we can find it,
            // it will save us the trouble of initiating an ARP request.
            neigh = neigh_lookup(&arp_tbl, &slave->gw_ip4, dev);
            if(neigh && (neigh->nud_state & NUD_VALID)) {
                memcpy(slave->next_hop_addr, neigh->ha, ETH_ALEN);

                VIRT_DBG("next_hop for %s: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
                        gwaddr.ifname,
                        neigh->ha[0], neigh->ha[1], neigh->ha[2],
                        neigh->ha[3], neigh->ha[4], neigh->ha[5]);
            } else {
                struct sk_buff *skb = arp_create(ARPOP_REQUEST, ETH_P_ARP, 
                        slave->gw_ip4, dev, slave->lif.ip4, NULL, 
                        dev->dev_addr, NULL);
                if(!skb)
                    goto out;

                arp_xmit(skb);
            }
        } else {
            memset(slave->next_hop_addr, 0x00, ETH_ALEN);
        }
    } else if(gwaddr.family == AF_INET6) {
        memcpy(&slave->gw_ip6, &gwaddr.gwaddr_ip6, sizeof(slave->gw_ip6));
/*
        if(slave->gw_ip6.s6_addr32[0] | slave->gw_ip6.s6_addr32[1] |
                slave->gw_ip6.s6_addr32[2] | slave->gw_ip6.s6_addr32[3]) {
            struct neighbour *neigh;

            neigh = neigh_lookup(&nd_tbl, &slave->gw_ip6, dev);
            if(neigh && (neigh->nud_state & NUD_VALID)) {
                memcpy(slave->next_hop_addr, neigh->ha, ETH_ALEN);
            }
        }
*/
    } else {
        device_node_put(slave);
        return -EINVAL;
    }
    
out:
    device_node_put(slave);
    return 0;
}

static int ioctl_addvroute(struct net_device *master, const struct ifreq *ifr)
{
    struct virt_priv *virt = netdev_priv(master);
    struct vroute_req vroute_req;

    if( copy_from_user(&vroute_req, ifr->ifr_data, sizeof(vroute_req)) != 0 )
        return -EINVAL;

    return virt_add_vroute(virt, vroute_req.dest, vroute_req.netmask, 
            vroute_req.node_ip);
}

static int ioctl_delvroute(struct net_device *master, const struct ifreq *ifr)
{
    struct virt_priv *virt = netdev_priv(master);
    struct vroute_req vroute_req;

    if( copy_from_user(&vroute_req, ifr->ifr_data, sizeof(vroute_req)) != 0 )
        return -EINVAL;

    return virt_delete_vroute(virt, vroute_req.dest, vroute_req.netmask, 
            vroute_req.node_ip);
}

static int ioctl_setpolicy(struct net_device *master, const struct ifreq *ifr)
{
    int command;
    struct policy_req p_req;
    struct policy_entry *policy;
    struct virt_priv *virt = netdev_priv(master);

    policy = (struct policy_entry *)kmalloc(sizeof(struct policy_entry), GFP_KERNEL);
    if( !policy ) {
        return -ENOMEM;
    }

    /* Make sure the counters are zeroed out. */
    memset(&policy->stats, 0, sizeof(policy->stats));

    if( copy_from_user(&p_req, ifr->ifr_data, sizeof(p_req)) != 0 )
        return -EINVAL;

    if( (p_req.type < 0) || (p_req.type >= POLICY_TYPE_MAX) ) {
        VIRT_DBG("invalid input for policy type\n");
        kfree(policy);
        return -EINVAL;
    }

    command = p_req.command;
    policy->type = p_req.type;
    policy->action = p_req.action;

    if( p_req.table & POLICY_TBL_OUTPUT ) {
        policy->table = EGRESS;
    } else {
        policy->table = INGRESS;
    }

    // copy matching param
    switch( policy->type ) {
    case POLICY_TYPE_DEFAULT:
        break;
    case POLICY_TYPE_FLOW:
        policy->flow.net_proto = p_req.net_proto;
        policy->flow.dst_addr = (p_req.dst_addr & p_req.dst_netmask);
        policy->flow.src_addr = (p_req.src_addr & p_req.src_netmask);
        policy->flow.dst_netmask = p_req.dst_netmask;
        policy->flow.src_netmask = p_req.src_netmask;
        policy->flow.proto = p_req.proto;
        policy->flow.dst_port = p_req.dst_port;
        policy->flow.src_port = p_req.src_port;
        break;
    case POLICY_TYPE_APP:
        strncpy(policy->app.app_name, p_req.app_name, POLICY_MAX_APP_NAME);
        break;
    case POLICY_TYPE_DEV:
        strncpy(policy->dev.dev_name, p_req.dev_name, IFNAMSIZ);
        break;
    default:
        VIRT_DBG("unknown policy type\n");
        kfree(policy);
        return -EINVAL;
    }

    if(p_req.alg_name[0]) {
        policy->alg = virt_alg_get_by_name(p_req.alg_name);
        if(!policy->alg) {
            kfree(policy);
            return -EINVAL;
        }
    } else {
        /* TODO: Need a better way to choose a default link selection algorithm. */
        policy->alg = virt_alg_get_by_name("random");
    }

    /* The policy list will increment refcnt before inserting it. */
    atomic_set(&policy->refcnt, 0);

    VIRT_DBG("calling virt_policy with policy: %p\n", policy);
    virt_policy(virt, policy, command, p_req.row);

    return 0;
}

static int ioctl_setlprio(struct net_device *master, const struct ifreq *ifr)
{
    struct virt_setlprio_req req;
    struct virt_priv *priv = netdev_priv(master);
    struct device_node *slave;
    int old_prio;
    
    if(copy_from_user(&req, ifr->ifr_data, sizeof(req)) != 0)
        return -EINVAL;

    slave = slave_get_by_name(req.ifname);
    if(!slave)
        return -ENODEV;

    old_prio = slave->lif.prio;
    slave->lif.prio = req.prio;

    if(req.prio < old_prio) {
        if(old_prio >= priv->max_dev_prio)
            priv->max_dev_prio = find_max_dev_prio();
    } else if(req.prio > old_prio) {
        if(req.prio > priv->max_dev_prio)
            priv->max_dev_prio = req.prio;
    }

    device_node_put(slave);

    return 0;
}

static int __deprecated ioctl_setrprio(struct net_device *master, const struct ifreq *ifr)
{
    struct virt_setrprio_req req;
    struct virt_priv *priv = netdev_priv(master);
    struct remote_node *node;
    struct remote_link *link;
    int old_prio;
    
    if(copy_from_user(&req, ifr->ifr_data, sizeof(req)) != 0)
        return -EINVAL;

    /* TODO: API needs to be updated to specify remote link by IP address + port. */
    link = find_remote_link_by_ip(&priv->network, (struct in_addr *)&req.link_ip);
    if(!link)
        return -ENODEV;

    old_prio = link->rif.prio;
    link->rif.prio = req.prio;

    node = link->node;
    if(node) {
        if(req.prio < old_prio) {
            if(old_prio >= node->max_link_prio)
                node->max_link_prio = find_max_remote_link_prio(node);
        } else if(req.prio > old_prio) {
            if(req.prio > node->max_link_prio)
                node->max_link_prio = req.prio;
        }
    }

    remote_link_put(link);

    return 0;
}

static int ioctl_perfhint(struct net_device *master, const struct ifreq *ifr)
{
    struct virt_perf_hint hint;

    if(copy_from_user(&hint, ifr->ifr_data, sizeof(hint)) != 0)
        return -EINVAL;

    switch(hint.type) {
        case LOCAL_BANDWIDTH_HINT:
            return local_bandwidth_hint(master, &hint);
        case REMOTE_BANDWIDTH_HINT:
            return remote_bandwidth_hint(master, &hint);
        default:
            VIRT_DBG("perf hint type %d is invalid\n", hint.type);
            return -EINVAL;
    }
}

static int conf_add_remote_node(struct net_device *master, 
        const struct virt_conf_remote_node *msg)
{
    struct virt_priv *virt = netdev_priv(master);
    struct remote_node *node;

    node = find_remote_node_by_ip(&virt->network, &msg->priv_ip);
    if(node) {
        remote_node_put(node);
        return -EEXIST;
    }

    node = alloc_remote_node(master);
    if(!node)
        return -ENOMEM;

    node->priv_ip.s_addr = msg->priv_ip.s_addr;

    add_remote_node(&virt->network, node);

    remote_node_put(node);

    return 0;
}

static int conf_del_remote_node(struct net_device *master, 
        const struct virt_conf_remote_node *msg)
{
    struct virt_priv *virt = netdev_priv(master);
    struct remote_node *node;

    node = find_remote_node_by_ip(&virt->network, &msg->priv_ip);
    if(!node)
        return -EINVAL;

    delete_remote_node(&virt->network, node);

    remote_node_put(node);

    return 0;
}

static int conf_add_remote_link(struct net_device *master, 
        const struct virt_conf_remote_link *msg)
{
    struct virt_priv *virt = netdev_priv(master);
    struct remote_node *node = NULL;
    struct remote_link *link = NULL;
    int ret = 0;

    node = find_remote_node_by_ip(&virt->network, &msg->priv_ip);
    if(!node) {
        ret = -EINVAL;
        goto out;
    }

    /* Older user-space daemons did not set the data_port field. */
    if(msg->data_port)
        link = find_remote_link_by_addr(&virt->network, &msg->pub_ip, msg->data_port);
    else
        link = find_remote_link_by_ip(&virt->network, &msg->pub_ip);

    if(link) {
        ret = -EEXIST;
        goto out;
    }

    link = alloc_remote_link();
    if(!link) {
        ret = -EEXIST;
        goto out;
    }

    link->rif.ip4       = msg->pub_ip.s_addr;
    link->rif.data_port = msg->data_port;

    add_remote_link(&virt->network, node, link);

out:
    if(link)
        remote_link_put(link);
    if(node)
        remote_node_put(node);

    return ret;
}

static int conf_del_remote_link(struct net_device *master, 
        const struct virt_conf_remote_link *msg)
{
    struct virt_priv *virt = netdev_priv(master);
    struct remote_link *link;

    link = find_remote_link_by_addr(&virt->network, &msg->pub_ip, msg->data_port);
    if(link) {
        delete_remote_link(&virt->network, link);
        remote_link_put(link);
        return 0;
    } else {
        return -EINVAL;
    }
}

static int __deprecated conf_set_xor_rate(struct net_device *master,
        const struct virt_conf_xor_rate *msg)
{
    struct virt_priv *virt = netdev_priv(master);
    struct pathinfo *path;

    path = path_get_by_addr_old(&virt->network, &msg->local_addr, &msg->remote_addr);
    if(likely(path)) {
        path->xor_same_path.next_rate = msg->same_path;
        path->xor_same_prio.next_rate = msg->same_prio;
        path->xor_lower_prio.next_rate = msg->lower_prio;
        path->xor_set_by_admin = true;
        virt_path_put(path);
        return 0;
    } else {
        return -EEXIST;
    }
}

static int conf_set_xor_rate2(struct net_device *master,
        const struct virt_conf_xor_rate2 *msg)
{
    struct virt_priv *virt = netdev_priv(master);
    struct pathinfo *path;

    path = path_get_by_addr(&virt->network, 
            &msg->local_addr, &msg->remote_addr,
            msg->local_port, msg->remote_port);
    if(likely(path)) {
        path->xor_same_path.next_rate = msg->same_path;
        path->xor_same_prio.next_rate = msg->same_prio;
        path->xor_lower_prio.next_rate = msg->lower_prio;
        path->xor_set_by_admin = true;
        virt_path_put(path);
        return 0;
    } else {
        return -EEXIST;
    }
}

static int conf_get_dev_flags(struct net_device *master,
        struct virt_conf_dev_flags *msg)
{
    struct device_node *slave;

    slave = slave_get_by_name(msg->ifname);
    if(!slave) {
        msg->flags = 0;
        return -ENODEV;
    }

    msg->flags = slave->flags;

    device_node_put(slave);

    return 0;
}

static int conf_set_dev_flags(struct net_device *master,
        const struct virt_conf_dev_flags *msg)
{
    struct device_node *slave;

    slave = slave_get_by_name(msg->ifname);
    if(!slave)
        return -ENODEV;

    slave->flags = msg->flags;

    /* Refresh the source address we are using, since the user-level may have
     * called this in response to an address change. */
    if(!(msg->flags & DEVICE_NO_TX))
        slave->lif.ip4 = inet_select_addr(slave->dev, 0, RT_SCOPE_UNIVERSE);

    device_node_put(slave);

    return 0;
}

static int conf_set_remote_prio(struct net_device *master, 
        const struct virt_conf_remote_link *msg)
{
    struct virt_priv *virt = netdev_priv(master);
    struct remote_node *node = NULL;
    struct remote_link *link = NULL;
    int old_prio;
    int ret = 0;

    node = find_remote_node_by_ip(&virt->network, &msg->priv_ip);
    if(!node) {
        ret = -EINVAL;
        goto out;
    }

    /* Older user-space daemons did not set the data_port field. */
    link = find_remote_link_by_addr(&virt->network, &msg->pub_ip, msg->data_port);
    if(!link) {
        ret = -EINVAL;
        goto out;
    }

    old_prio = link->rif.prio;
    link->rif.prio = msg->prio;

    if(msg->prio < old_prio) {
        if(old_prio >= node->max_link_prio)
            node->max_link_prio = find_max_remote_link_prio(node);
    } else if(msg->prio > old_prio) {
        if(msg->prio > node->max_link_prio)
            node->max_link_prio = msg->prio;
    }

out:
    if(link)
        remote_link_put(link);
    if(node)
        remote_node_put(node);

    return ret;
}

static int ioctl_conf(struct net_device *master, const struct ifreq *ifr)
{
    struct virt_conf_message msg;
    int send_back = false;
    int result;

    if(copy_from_user(&msg, ifr->ifr_data, sizeof(msg)) != 0)
        return -EINVAL;

    switch(msg.op) {
        case VIRT_CONF_ADD_REMOTE_NODE:
            result = conf_add_remote_node(master, &msg.msg.remote_node);
            break;
        case VIRT_CONF_DEL_REMOTE_NODE:
            result = conf_del_remote_node(master, &msg.msg.remote_node);
            break;
        case VIRT_CONF_ADD_REMOTE_LINK:
            result = conf_add_remote_link(master, &msg.msg.remote_link);
            break;
        case VIRT_CONF_DEL_REMOTE_LINK:
            result = conf_del_remote_link(master, &msg.msg.remote_link);
            break;
        case VIRT_CONF_SET_XOR_RATE:
            result = conf_set_xor_rate(master, &msg.msg.xor_rate);
            break;
        case VIRT_CONF_SET_XOR_RATE2:
            result = conf_set_xor_rate2(master, &msg.msg.xor_rate2);
            break;
        case VIRT_CONF_GET_DEV_FLAGS:
            result = conf_get_dev_flags(master, &msg.msg.dev_flags);
            send_back = true;
            break;
        case VIRT_CONF_SET_DEV_FLAGS:
            result = conf_set_dev_flags(master, &msg.msg.dev_flags);
            break;
        case VIRT_CONF_SET_REMOTE_PRIO:
            result = conf_set_remote_prio(master, &msg.msg.remote_link);
            break;
        default:
            result = -EINVAL;
    }

    if(send_back) {
        if(copy_to_user(ifr->ifr_data, &msg, sizeof(msg)) != 0)
            return -EINVAL;
    }

    return result;
}

/*
 * Main ioctl function that will call all sub ioctl functions
 */
int virt_ioctl(struct net_device *master_dev, struct ifreq *ifr, int cmd)
{
    VIRT_DBG("ioctl cmd: %d\n", cmd);

    switch (cmd) {
    case SIOCVIRTENSLAVE:
    case SIOCBONDENSLAVE:
        VIRT_DBG("ioctl cmd: SIOCVIRTENSLAVE\n");
        return ioctl_enslave(master_dev, ifr);
    case SIOCVIRTRELEASE:
    case SIOCBONDRELEASE:
        VIRT_DBG("ioctl cmd: SIOCVIRTRELEASE\n");
        return ioctl_release(master_dev, ifr);
    case SIOCVIRTSETHWADDR:
        VIRT_DBG("ioctl cmd: SIOCVIRTSETHWADDR\n");
        break;
    case SIOCVIRTSETGWADDR:
        return ioctl_setgwaddr(ifr);
    case SIOCVIRTSETPOLICY:
        VIRT_DBG("ioctl cmd: SIOCVIRTSETPOLICY\n");
        return ioctl_setpolicy(master_dev, ifr);
    case SIOCVIRTADDVROUTE:
        return ioctl_addvroute(master_dev, ifr);
    case SIOCVIRTDELVROUTE:
        return ioctl_delvroute(master_dev, ifr);
    case SIOCVIRTSETLPRIO:
        return ioctl_setlprio(master_dev, ifr);
    case SIOCVIRTSETRPRIO:
        return ioctl_setrprio(master_dev, ifr);
    case SIOCVIRTPERFHINT:
        return ioctl_perfhint(master_dev, ifr);
    case SIOCVIRTCONF:
        return ioctl_conf(master_dev, ifr);
    default:
        break;
    }

    return 1;
}


/*
 * This function returns that standard stats structure
 * back to the caller.
 */
struct net_device_stats *virt_stats(struct net_device *dev)
{
    struct virt_priv *priv = netdev_priv(dev);
    return &priv->stats;
}



/*
 * The "change_mtu" method is usually not needed.
 * If you need it, it must be like this.
 */
//TODO: this should be removed cause we will use the mtu 
// of the slave devices (probably min mtu of slaves)
int virt_change_mtu(struct net_device *dev, int new_mtu)
{
    unsigned long flags;
    struct virt_priv *priv = netdev_priv(dev);
    spinlock_t *lock = &priv->lock;

    /* check ranges */
    if ((new_mtu < 68) || (new_mtu > 1500))
        return -EINVAL;
    /*
     * Do anything you need, and the accept the value
     */
    spin_lock_irqsave(lock, flags);
    dev->mtu = new_mtu;
    spin_unlock_irqrestore(lock, flags);
    return 0; /* success */
}



/*
 * Configuration changes (passed on by ifconfig)
 */
// TODO: we should look at this more carefully to not allow changes to the device
int virt_config(struct net_device *dev, struct ifmap *map)
{
    if (dev->flags & IFF_UP) /* can't act on a running interface */
        return -EBUSY;

    /* Don't allow changing the I/O address */
    if (map->base_addr != dev->base_addr) {
        VIRT_ERR(KERN_WARNING "virt: Can't change I/O address\n");
        return -EOPNOTSUPP;
    }

    /* Allow changing the IRQ */
    if (map->irq != dev->irq) {
        dev->irq = map->irq;
            /* request_irq() is delayed to open-time */
    }

    /* ignore other fields */
    return 0;
}






