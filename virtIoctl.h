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

#ifndef _VIRT_IOCTL_H__
#define _VIRT_IOCTL_H__

#include <linux/if.h>
#include "virtPolicyTypes.h"

#define SIOCVIRTENSLAVE   (SIOCDEVPRIVATE + 0)
#define SIOCVIRTRELEASE   (SIOCDEVPRIVATE + 1)
#define SIOCVIRTSETHWADDR (SIOCDEVPRIVATE + 2)
#define SIOCVIRTSETGWADDR (SIOCDEVPRIVATE + 3)
#define SIOCVIRTADDVROUTE (SIOCDEVPRIVATE + 4)
#define SIOCVIRTDELVROUTE (SIOCDEVPRIVATE + 5)
#define SIOCVIRTSETPOLICY (SIOCDEVPRIVATE + 6)
#define SIOCVIRTSETLPRIO  (SIOCDEVPRIVATE + 7)
#define SIOCVIRTSETRPRIO  (SIOCDEVPRIVATE + 8)
#define SIOCVIRTPERFHINT  (SIOCDEVPRIVATE + 9)
#define SIOCVIRTCONF      (SIOCDEVPRIVATE + 15)

#define POLICY_MAX_APP_NAME 16

/* Enforce maximum coding rate so that it fits in four bits. */
#define MAX_XOR_CODING_RATE 15

struct net_device;
struct ifreq;
struct in6_addr;

struct policy_req {
    int command;
    int row;

    __u32 action;
    __u16 table;
    __s32 type; //algo type
    // flow policy
    __u16 net_proto;
    __u32 src_addr;
    __u32 dst_addr;
    __u32 src_netmask;
    __u32 dst_netmask;
    __u16 proto;
    __u16 src_port;
    __u16 dst_port;
    // app policy
    char app_name[POLICY_MAX_APP_NAME];
    // dev policy
    char dev_name[IFNAMSIZ];

    // rate limit params
    int max_rate;

    // encrypt params
    // compression params
    // coding params

    // algo params
    char alg_name[MAX_ALG_NAME_LEN];
    int slave_count;
    char slave_list[3][IFNAMSIZ];
    int slave_weight[3];

};

struct gwaddr_req {
    char     ifname[IFNAMSIZ];

    // family should be either AF_INET or AF_INET6
    uint16_t family;

    union {
        __be32          ip4_u;
        struct in6_addr ip6_u;
    } nl_u;
#define gwaddr_ip4 nl_u.ip4_u
#define gwaddr_ip6 nl_u.ip6_u
};

struct virt_setlprio_req {
    char ifname[IFNAMSIZ];
    int prio;
};

struct virt_setrprio_req {
    __be32 node_ip;
    __be32 link_ip;
    int prio;
};

struct vroute_req {
    __be32  dest;
    __be32  netmask;
    __be32  node_ip;
};


#define VIRT_CONF_ADD_REMOTE_NODE   0x0000
#define VIRT_CONF_DEL_REMOTE_NODE   0x0001
#define VIRT_CONF_ADD_REMOTE_LINK   0x0002
#define VIRT_CONF_DEL_REMOTE_LINK   0x0003
#define VIRT_CONF_SET_XOR_RATE      0x0004
#define VIRT_CONF_SET_XOR_RATE2     0x0005
#define VIRT_CONF_GET_DEV_FLAGS     0x0006
#define VIRT_CONF_SET_DEV_FLAGS     0x0007
/* Reserved for: #define VIRT_CONF_SET_LOCAL_PRIO    0x0008 */
#define VIRT_CONF_SET_REMOTE_PRIO   0x0009

struct virt_conf_remote_node {
    struct in_addr priv_ip;
};

struct virt_conf_remote_link {
    // priv_ip identifies the node to which this link belongs, so the node must
    // be added before a link is added.
    struct in_addr priv_ip;
    struct in_addr pub_ip;

    __be16 data_port;

    /* prio is only used for VIRT_CONF_SET_REMOTE_PRIO */
    int prio;
};

struct virt_conf_xor_rate {
    /* local_addr and remote_addr identify the path */
    struct in_addr local_addr;
    struct in_addr remote_addr;

    /* XOR coding rates interpreted as the number of packets used to produce a
     * coded packet.  Setting the rate to zero disables coding; setting it to
     * one results in duplication. 
     * 
     * same_path: coded packets are sent on the same path as the data packets.
     * same_prio: coded packets are sent on other paths with the same priority.
     * lower_prio: coded packets are sent on paths with lower priority.
     */
    unsigned char same_path;
    unsigned char same_prio;
    unsigned char lower_prio;
};

struct virt_conf_xor_rate2 {
    /* The combination of addresses and ports identifies the path. */
    struct in_addr local_addr;
    struct in_addr remote_addr;
    __be16 local_port;
    __be16 remote_port;

    /* XOR coding rates interpreted as the number of packets used to produce a
     * coded packet.  Setting the rate to zero disables coding; setting it to
     * one results in duplication. 
     * 
     * same_path: coded packets are sent on the same path as the data packets.
     * same_prio: coded packets are sent on other paths with the same priority.
     * lower_prio: coded packets are sent on paths with lower priority.
     */
    unsigned char same_path;
    unsigned char same_prio;
    unsigned char lower_prio;
};

struct virt_conf_dev_flags {
    char ifname[IFNAMSIZ];
    __u32 flags;
};

struct virt_conf_message {
    unsigned op;

    union {
        struct virt_conf_remote_node remote_node;
        struct virt_conf_remote_link remote_link;
        struct virt_conf_xor_rate    xor_rate;
        struct virt_conf_xor_rate2   xor_rate2;
        struct virt_conf_dev_flags   dev_flags;
    } msg;
};

int virt_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);
struct net_device_stats *virt_stats(struct net_device *dev);
int virt_change_mtu(struct net_device *dev, int new_mtu);
int virt_config(struct net_device *dev, struct ifmap *map);


#endif //_VIRT_IOCTL_H__
