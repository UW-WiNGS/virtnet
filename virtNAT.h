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

#ifndef __VIRTNAT_H
#define __VIRTNAT_H



struct nat_key {
    __be16 proto;
    __be32 daddr;
    __be32 saddr;
    __be16 dport;
    __be16 sport;
};

struct nat_table_head {
    spinlock_t lock;
    struct hlist_head list;
};

struct nat_entry {
    struct hlist_node hlist;
    struct nat_key key;

    __be32 oldip; // TODO: ipv6 compatible
    __be32 newip;
    __be16 oldport;
    __be16 newport;

    // TODO: if tcp port 80 track these values
    //__be32 seq_no;
    //__be32 ack_no;
};



int init_nat_table(unsigned bits);
void nat_table_destroy(void);
void nat_table_delete(struct nat_entry *entry);
struct nat_entry *nat_table_ingress_lookup(struct packet *pkt);

int virt_nat_egress_pkt(struct packet *pkt, const struct device_node *slave);
int virt_denat_ingress_packet(struct packet *pkt);


//int setup_netlink_socket(void);
//void teardown_netlink_socket(void);
//void nat_ipc_input(struct sk_buff *skb);
//int nat_ipc_output(struct packet *pkt, const struct device_node *slave);


#endif //__VIRTNAT_H
