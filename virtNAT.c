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
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/udp.h>         /* struct udphdr */
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/route.h>

#include <linux/time.h>

#include <linux/hash.h>
#include <linux/in6.h>
#include <asm/checksum.h>

#include <linux/netlink.h>

#include "virt.h"
#include "virtDevList.h"
#include "virtDebug.h"
#include "virtParse.h"
#include "virtNAT.h"

// TODO:
// - track used ports in the case that numbers wrap around
// - when a policy is cleared but flow was nat, clear entry in nat table also
// - FUTURE: check if link has failed and try to remap


static struct nat_table_head *__nat_table = NULL;

unsigned __nat_table_bits = 0;
unsigned get_nat_table_bits(void) {
    return __nat_table_bits;
}
void set_nat_table_bits(unsigned value) {
    __nat_table_bits = value;
}

unsigned __nat_table_size = 0;
unsigned get_nat_table_size(void) {
    return __nat_table_size;
}
void set_nat_table_size(unsigned value) {
    __nat_table_size = value;
}



#define MIN_NAT_PORT 32000
#define MAX_NAT_PORT 65000
static int __next_avail_port = 0;
static int get_nat_port(void)
{
    int rtn_port;

    if( __next_avail_port < MIN_NAT_PORT ) {
        __next_avail_port = MIN_NAT_PORT; // wrap around
        return __next_avail_port++;
    }

    rtn_port = __next_avail_port;

    // incr value and check for overflow
    __next_avail_port++;
    if( __next_avail_port > MAX_NAT_PORT )
        __next_avail_port = MIN_NAT_PORT; // wrap around

    // FIXME: should check if this port is in use, if so skip and try next port
    return rtn_port;
}




/*
 * Allocate space for the flow hash table.  The size is 2^bits.
 */
int init_nat_table(unsigned bits)
{
    const unsigned table_size = 1u << bits;
    int i;

    if(WARN_ON(__nat_table)) {
        VIRT_DBG("initialization should be called only once\n");
        return 0;
    }

    __nat_table = kmalloc(table_size * sizeof(struct nat_table_head), GFP_KERNEL);
    if(!__nat_table)
        return -ENOMEM;

    for(i = 0; i < table_size; i++) {
        struct nat_table_head *head = &__nat_table[i];
        spin_lock_init(&head->lock);
        INIT_HLIST_HEAD(&head->list);
    }

    set_nat_table_bits(bits);
    set_nat_table_size(table_size);

    return 0;
}

/*
 * Allocate a nat_entry structure.  The refcnt field is initialized to
 * one.
 */
static struct nat_entry *alloc_nat_entry(void)
{
    struct nat_entry *entry;

    entry = kmalloc(sizeof(struct nat_entry), GFP_ATOMIC);
    if(!entry)
        return NULL;

    memset(entry, 0, sizeof(*entry));

    return entry;
}


/*
 * Compute a hash value for the key tuple.
 */
static u32 nat_hash(struct nat_key *key, unsigned bits)
{
    // TODO: What is the best way to combine values?
    u32 sum = key->saddr + key->daddr + key->sport + key->dport + key->proto;
    return hash_32(sum, bits);
}


/*
 * This function compares two sets or keys to determine hash table lookup matches.
 */
static int keys_equal(struct nat_key *key1, struct nat_key *key2)
{
    return (key1->daddr == key2->daddr &&
            key1->saddr == key2->saddr &&
            key1->dport == key2->dport &&
            key1->sport == key2->sport &&
            key1->proto == key2->proto);
}


/*
 * Add an entry to the nat hash table.
 */
int nat_table_add(struct nat_entry *entry)
{
    u32 hash = nat_hash(&entry->key, get_nat_table_bits());
    struct nat_table_head *head = &__nat_table[hash];

    if(WARN_ON(hash >= get_nat_table_size()))
        return -1;

    spin_lock_bh(&head->lock);
    hlist_add_head_rcu(&entry->hlist, &head->list);
    spin_unlock_bh(&head->lock);

    return 0;
}


/*
 * Lookup an entry in the nat hash table.
 */
struct nat_entry *nat_table_lookup(struct nat_key *key)
{
    u32 hash = nat_hash(key, get_nat_table_bits());
    struct nat_table_head *head = &__nat_table[hash];

    struct nat_entry *entry;
    struct hlist_node *pos;

    if(WARN_ON(hash >= get_nat_table_size()))
        return NULL;

    rcu_read_lock();
    hlist_for_each_entry_rcu(entry, pos, &head->list, hlist) {
        if(keys_equal(key, &entry->key)) {
            rcu_read_unlock();
            return entry;
        }
    }
    rcu_read_unlock();

    return NULL;
}


struct nat_entry *nat_table_ingress_lookup(struct packet *pkt)
{
    struct iphdr *ip   = pkt->hdr_ptrs->ip_ptr;
    struct tcphdr *tcp = pkt->hdr_ptrs->tcp_ptr;
    struct udphdr *udp = pkt->hdr_ptrs->udp_ptr;
    //struct net_device *master = NULL;
    struct nat_entry *entry = NULL;
    struct nat_key key;

    if(WARN_ON(!ip))
        return NULL;

    // lookup the stored values for denat
    memset(&key, 0, sizeof(struct nat_key));
    key.proto = ip->protocol;
    key.saddr = ip->daddr;
    key.daddr = ip->saddr;

    if( ip->protocol == IPPROTO_TCP ) {
        if(WARN_ON(!tcp))
            return NULL;
        key.sport = tcp->dest;
        key.dport = tcp->source;
    } else if( ip->protocol == IPPROTO_UDP ) {
        if(WARN_ON(!udp))
            return NULL;
        key.sport = udp->dest;
        key.dport = udp->source;
    } else if( ip->protocol == IPPROTO_ICMP ) {
        struct icmphdr *icmp = (struct icmphdr *)(skb_network_header(pkt->skb) + ip->ihl * 4);
        if(icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
            key.sport = icmp->un.echo.id;
            key.dport = icmp->un.echo.id;
        }
    }

    entry = nat_table_lookup(&key);
    return entry;
}

/*
 * Free a nat_entry.  The NAT table is protected along with the flow table with
 * RCU locking.  This function must be called within the context of an RCU
 * callback.  Basically, it should only be called by flow_table_entry_destroy.
 */
void nat_table_delete(struct nat_entry *entry)
{
    hlist_del(&entry->hlist);
    kfree(entry);
}

/*
 * Free the hash table.  All of the entries should have been freed already
 * by calling flow_table_destroy.
 */
void nat_table_destroy(void)
{
    kfree(__nat_table);
    __nat_table = NULL;
}

/*
 * This function will update the source IP and
 * update the transport and network checksums
 */
int virt_nat_egress_pkt(struct packet *pkt, const struct device_node *slave)
{
    int rc = 0;
    struct iphdr  *ip  = NULL;
    struct udphdr *udp = NULL;
    struct tcphdr *tcp = NULL;
    struct sk_buff *skb = pkt->skb;
    struct nat_entry *entry = NULL;
    __be32 oldip=0, newip=0;
    __be16 oldport=0, newport=0;
    __be32 destip=0;
    __be16 destport=0;

    ip = (struct iphdr *)pkt->hdr_ptrs->ip_ptr;

    // store ip addresses
    oldip = ip->saddr;
    newip = slave->lif.ip4; // TODO: ipv6 compatible
    destip = ip->daddr;

    // get the new port number (will be used for TCP/UDP/ICMP)
    if( pkt->ftable_entry->nat == NULL ) {
        newport = htons(get_nat_port());
    } else {
        newport = pkt->ftable_entry->nat->newport;
    }


    // iptables hashes on ip_addr, any port details, and protonum
    // - /net/ipv4/netfilter/nf_nat_core.c - hash_by_src()
    // *** for now assume all traffic comes from an IPtables NAT => don't have to worry out port collisions

    if( ip->protocol == IPPROTO_TCP ) {

        tcp = (struct tcphdr *)pkt->hdr_ptrs->tcp_ptr;

        oldport = tcp->source;
        destport = tcp->dest;

        // update checksum values
        inet_proto_csum_replace4(&tcp->check, skb, oldip, newip, 1);
        inet_proto_csum_replace2(&tcp->check, skb, oldport, newport, 0);
        if( !tcp->check )
            tcp->check = CSUM_MANGLED_0;

        tcp->source = newport;

    } else if( ip->protocol == IPPROTO_UDP ) {

        udp = (struct udphdr *)pkt->hdr_ptrs->udp_ptr;

        // update source port number
        oldport = udp->source;
        destport = udp->dest;

        // update checksum values
        // code taken from net/ipv4/netfilter/nf_nat_udp.c udp_manip_pkt() line 33 in 2.6.18
        inet_proto_csum_replace4(&udp->check, skb, oldip, newip, 1);
        inet_proto_csum_replace2(&udp->check, skb, oldport, newport, 0);
        if( !udp->check )
            udp->check = CSUM_MANGLED_0;

        udp->source = newport;

    } else if( ip->protocol == IPPROTO_ICMP ) {
        // TODO: if we want to overwrite the ID we need to compute ICMP checksum
        //struct icmphdr *icmp = (struct icmphdr *)(skb_network_header(pkt->skb) + ip->ihl * 4);

        // update source port number
        oldport = 0;
        destport = 0;
        newport = 0;

        //if(icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
        //    oldport = icmp->un.echo.id;
        //    destport = newport;

        //    icmp->un.echo.id = newport;
        //}
    }

    // update the ip checksum
    ip->saddr = newip;
    ip->check = 0;
    ip->check = ip_fast_csum((unsigned char *)ip, ip->ihl);

    // if this flow has not already been stored then store it in the nat table
    if( pkt->ftable_entry->nat == NULL ) {
        entry = alloc_nat_entry();
        if(!entry)
            return -ENOMEM;

        // all values should be stored in network order
        entry->key.saddr = newip;
        entry->key.daddr = destip;
        entry->key.proto = ip->protocol;
        entry->key.sport = newport;
        entry->key.dport = destport;
        entry->oldip   = oldip; 
        entry->newip   = newip;
        entry->oldport = oldport;
        entry->newport = newport;

        nat_table_add(entry);

        pkt->ftable_entry->nat = entry;
    }

    return rc;
}

int virt_denat_ingress_packet(struct packet *pkt)
{
    struct iphdr *ip   = pkt->hdr_ptrs->ip_ptr;
    struct tcphdr *tcp = pkt->hdr_ptrs->tcp_ptr;
    struct udphdr *udp = pkt->hdr_ptrs->udp_ptr;
    //struct icmphdr *icmp = NULL;
    struct net_device *master = NULL;
    struct sk_buff *skb = pkt->skb;
    struct nat_entry *entry = NULL;
    __be32 oldip, newip;
    __be16 oldport, newport;
    struct nat_key key;

    //struct timeval currTime;
    //s64 start_time, stop_time, diff_time;
    //virt = netdev_priv(master);

    ////ip = ip_hdr(pkt->skb);

    if(WARN_ON(!ip)) {
        return -1;
    }

    // lookup the stored values for denat
    memset(&key, 0, sizeof(struct nat_key));
    key.proto = ip->protocol;
    key.saddr = ip->daddr;
    key.daddr = ip->saddr;

    if( ip->protocol == IPPROTO_TCP ) {
        if(WARN_ON(!tcp)) {
            return -1;
        }
        key.sport = tcp->dest;
        key.dport = tcp->source;
    } else if( ip->protocol == IPPROTO_UDP ) {
        if(WARN_ON(!tcp)) {
            return -1;
        }
        key.sport = udp->dest;
        key.dport = udp->source;
    } else if( ip->protocol == IPPROTO_ICMP ) {
        // TODO: if we want to overwrite the ID we need to compute ICMP checksum
        //icmp = (struct icmphdr *)(skb_network_header(pkt->skb) + ip->ihl * 4);
        //if(icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
        //    key.sport = icmp->un.echo.id;
        //    key.dport = icmp->un.echo.id;
        //}
    }

    //do_gettimeofday(&currTime);
    //start_time = timeval_to_ns(&currTime);
    entry = nat_table_lookup(&key);

    //do_gettimeofday(&currTime);
    //stop_time = timeval_to_ns(&currTime);
    //diff_time = stop_time - start_time;
    //VIRT_DBG("lookup nat table entry: %lld\n", diff_time);
    if( !entry ) {
        VIRT_DBG("ERROR nat lookup failed");
        return -1;
    }

    // grab the nat info
    oldip = entry->newip;
    newip = entry->oldip;
    oldport = entry->newport;
    newport = entry->oldport;

    if( ip->protocol == IPPROTO_TCP ) {

        //tcp = (struct tcphdr *)(pkt->skb->data + (ip->ihl * 4));

        inet_proto_csum_replace4(&tcp->check, skb, oldip, newip, 1);
        inet_proto_csum_replace2(&tcp->check, skb, oldport, newport, 0);
        //if( !tcp->check )
        //    tcp->check = CSUM_MANGLED_0;

        tcp->dest = newport;

    } else if( ip->protocol == IPPROTO_UDP ) {

        //udp = (struct udphdr *)(skb->data + (ip->ihl * 4));

        // this should just recalculate the checksum
        // code taken from net/ipv4/netfilter/nf_nat_udp.c udp_manip_pkt() line 33
        inet_proto_csum_replace4(&udp->check, skb, oldip, newip, 1);
        inet_proto_csum_replace2(&udp->check, skb, oldport, newport, 0);
        //if( !udp->check )
        //    udp->check = CSUM_MANGLED_0;

        udp->dest = newport;

    } else if( ip->protocol == IPPROTO_ICMP ) {
        //icmp->un.echo.id = newport;
    }

    ip->daddr = newip;
    ip->check = 0;         // and rebuild the checksum (ip needs it)
    ip->check = ip_fast_csum((unsigned char *)ip,ip->ihl);

    master = pkt->master;
    if(WARN_ON(!master))
        return -1;

    return 0;
}



#ifdef USE_NAT_IPC

#define NETLINK_WIROVER 20 // FIXME: define in usr/include/linux/netlink.h


struct sock *nl_sock = NULL;

int setup_netlink_socket(void)
{
    nl_sock = netlink_kernel_create(&init_net, NETLINK_WIROVER, 0, nat_ipc_input, NULL, THIS_MODULE);
    if( nl_sock == NULL ) {
        printk(KERN_ERR " Could not create netlink socket.\n");
        return -1;
    }

    return 0;
}

void teardown_netlink_socket(void)
{
    netlink_kernel_release(nl_sock);
    return;
}

#define MAX_PAYLOAD 1024
int nat_ipc_output(struct packet *pkt, const struct device_node *slave)
{
    //struct sock *nl_sock = NULL;
    struct sk_buff *skb = NULL;
    struct nlmsghdr *nlh;
    //int err;

    skb = alloc_skb(NLMSG_SPACE(MAX_PAYLOAD), GFP_ATOMIC);
    nlh = (struct nlmsghdr *)skb->data;
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = 0; // from kernel
    nlh->nlmsg_flags = 0;
    strcpy(NLMSG_DATA(nlh), "Hello from kernel!");
    //NETLINK_CB(skb).groups = 1;
    NETLINK_CB(skb).pid = 0; // from kernel
    //NETLINK_CB(skb).dst_pid = 0; // multicast
    NETLINK_CB(skb).dst_group = 1; // send to group 1

    netlink_broadcast(nl_sock, skb, 0, 1, GFP_KERNEL);

    return 1;
}

void nat_ipc_input(struct sk_buff *skb)
{
    VIRT_DBG("*** nat_ipc_input() called\n");
    return;
}


#endif // USE_NAT_IPC


