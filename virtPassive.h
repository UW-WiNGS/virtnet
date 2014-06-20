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

#ifndef _VIRT_PASSIVE_
#define _VIRT_PASSIVE_

#include <linux/types.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/average.h>

#include <linux/in.h>
#include <linux/in6.h>

/* Putting tight bounds on these helps ensure good passive measurements. */
#define MAX_SERVICE_TIME    1000000
#define MAX_PASSIVE_RTT     5000000

/* Increasing the factor increases the precision of the calculation, but
 * the maximum value before overflow is ULONG_MAX/(factor*weight). */
#define RTT_EWMA_FACTOR     128
#define RTT_EWMA_WEIGHT     8
#define RTTVAR_EWMA_FACTOR  128
#define RTTVAR_EWMA_WEIGHT  4

/* Just a dummy value. */
#define INITIAL_EST_RTT     1000

/* Assume 1 megabit. */
#define EST_BANDWIDTH 1000000

#define USECS_PER_SEC 1000000

#define DEFAULT_SAFE_SPACING    5000000

#define DEFAULT_START_CWND      15000
#define DEFAULT_MIN_CWND        1500
#define DEFAULT_MAX_CWND        12500000

#define MAX_CWND_INCREASE       1500
#define MIN_CWND_INCREASE       1

/* Multiple of RTT to be used as stall time (as a power of two). */
#define PATH_STALL_RTT_MULT     2

/* Path states. */
enum {
    VIRT_PATH_DEAD= 0,
    VIRT_PATH_ACTIVE,
    VIRT_PATH_STALL_TIME_WAIT,
    VIRT_PATH_STALLED,
};

struct virt_network;

struct xor_packet_buffer {
    struct sk_buff *skb;
    int rate;
    int next_rate;
};

/**
 * struct pathinfo
 * @base_rtt: short-term minimum RTT, used to check for increasing RTT
 * @last_rx_seq: last packet sequence number received on this path
 */
struct pathinfo {
    int index;

    int net_proto;

    union {
        struct in_addr ip4;
        struct in6_addr ip6;
    } local_addr;

    union {
        struct in_addr ip4;
        struct in6_addr ip6;
    } remote_addr;

    __be16 local_port;
    __be16 remote_port;

    int local_index;
    int rnode_index;
    int rlink_index;

    int state;

    /* Information about last packet received along this path, used to fill in
     * tunnel header of next outgoing packet. */
    uint16_t    prev_len;
    int32_t     recv_ts;
    s64         local_recv_time;

    /* Local time of the last valid measurement that we helped the other side
     * to complete.  This is used to compute the other side's rtt estimation
     * error, which increases over time. */
    s64         local_meas_sent_time;

    struct ewma est_rtt;
    struct ewma est_rttvar;

    unsigned long base_rtt;

    u32 cwnd;
    u32 avail;

    /* Variables related to the progression  of sequence numbers and ACKs.
     * The naming convention is similar to the Linux TCP implementation.
     * @snd_nxt: next sequence number we send
     * @snd_una: first unacknowledged byte we sent
     * @rcv_nxt: next byte expected */
    u32 snd_nxt;
    u32 snd_una;
    u32 rcv_nxt;

    /* Parameters set by user that control cwnd adjustment algorithm. */
    u32 start_cwnd;
    u32 min_cwnd;
    u32 max_cwnd;

    u32 last_rx_seq;

    unsigned long next_cwnd_update;
    unsigned long stall_time;

    /* Count number of unacknowledged bytes/packets in a time window. */
    unsigned long unacked_bytes;
    unsigned long unacked_packets;

    unsigned long   queue_len;
    unsigned        queue_updated;

    /* Time in jiffies of last packet sent. */
    unsigned long   last_packet;

    /* XOR coding packet buffers. */
    struct xor_packet_buffer xor_same_path;
    struct xor_packet_buffer xor_same_prio;
    struct xor_packet_buffer xor_lower_prio;
    bool xor_set_by_admin;

    struct list_head stall_list;
    struct hlist_node hlist;

    atomic_t refcnt;
    struct rcu_head rcu;

    /* Parent data structure. */
    struct virt_network *network;
};

struct device_node;
struct remote_link;
struct tunhdr;
struct seq_file;
struct virt_priv;

void add_path(struct virt_network *net, struct pathinfo *path);
void remove_path(struct virt_network *net, struct pathinfo *path);

struct pathinfo *__lookup_pathinfo(struct virt_network *net,
        const struct device_node *llink, 
        const struct remote_link *rlink);
struct pathinfo *lookup_pathinfo(struct virt_network *net,
        const struct device_node *llink, 
        const struct remote_link *rlink);

struct pathinfo *path_lookup_create(struct virt_network *net,
        struct device_node *llink,
        struct remote_link *rlink);
struct pathinfo *path_get_by_addr(struct virt_network *net,
        const struct in_addr *local_addr,
        const struct in_addr *remote_addr,
        __be16 local_port, __be16 remote_port);
struct pathinfo __deprecated *path_get_by_addr_old(struct virt_network *net,
        const struct in_addr *local_addr,
        const struct in_addr *remote_addr);

void update_est_rtt(struct pathinfo *path, unsigned long rtt);
int update_pathinfo(struct virt_network *net, struct device_node *llink,
        struct remote_link *rlink, const struct tunhdr *tunhdr,
        unsigned payload_len);
unsigned long pathinfo_update_queue(struct pathinfo *pathi, unsigned add);
unsigned long pathinfo_est_delay(struct pathinfo *pathi);
int dump_path_list(struct seq_file *s, void *p);

void path_update_tx_bytes(struct pathinfo *path, unsigned bytes);

void virt_path_hold(struct pathinfo *path);
void virt_path_put(struct pathinfo *path);

void change_path_state_active(struct pathinfo *path);
void change_path_state_stalled(struct pathinfo *path);

void remove_paths_from_local(struct virt_network *net, struct device_node *slave);
void remove_paths_to_remote(struct virt_network *net, struct remote_link *link);


static inline unsigned long pathinfo_est_rtt(const struct pathinfo *path)
{
    return ewma_read(&path->est_rtt);
}

static inline unsigned long pathinfo_est_rttvar(const struct pathinfo *path)
{
    return ewma_read(&path->est_rttvar);
}

static inline unsigned long pathinfo_est_bandwidth(const struct pathinfo *pathi)
{
    // TODO: Need a better estimate of bandwidth!
    return EST_BANDWIDTH;
}

/*
 * Estimate the amount of interpacket spacing needed to guard against reorders
 * if we try to migrate a flow.  This is based on the TCP RTO calculation.
 */
static inline unsigned long pathinfo_safe_spacing(const struct pathinfo *path)
{
    unsigned long rtt = pathinfo_est_rtt(path);
    unsigned long rttvar = pathinfo_est_rttvar(path);
    
    if(likely(rtt))
        return (rtt + (rttvar << 2));
    else
        return DEFAULT_SAFE_SPACING;
}

__attribute__((__deprecated__)) static inline uint32_t get_tunhdr_timestamp(void)
{
    return (uint32_t)ktime_to_us(ktime_get());
}

#endif //_VIRT_PASSIVE_

