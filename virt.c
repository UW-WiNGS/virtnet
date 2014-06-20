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
#include <linux/init.h>
#include <linux/moduleparam.h>
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
#include <linux/skbuff.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>

#include <net/ip_vs.h>
#include <net/ip.h>  // has ip_hdrlen()

#include "virt.h"
#include "virtIoctl.h"
#include "virtDebug.h"
#include "virtPolicy.h"
#include "virtProcFs.h"
#include "virtDevList.h"
#include "virtEgress.h"
#include "virtEgressLookup.h" //virt_free_lookup_table
#include "virtIngress.h"
#include "virtHeader.h"
#include "virtRoute.h"
#include "virtSelectInterface.h"
#include "virtFlowTable.h"
#include "virtNAT.h"
#include "virtMemory.h"
#include "virtInterface.h"


char virt_driver_name[]            = "virt";
static char virt_driver_string[]   = "WiRover Virtual Network Driver";
#define DRV_VERSION                  "1.4"
const char virt_driver_version[]   = DRV_VERSION;
static const char virt_copyright[] = "Copyright (C) 2014 Joshua Hare, Lance Hartung, and Suman Banerjee";

MODULE_AUTHOR("Joshua Hare and Lance Hartung");
MODULE_DESCRIPTION("Virtual Network Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);


/* Default timeout period */
#define VIRT_TIMEOUT 5   /* In jiffies */
static int timeout = VIRT_TIMEOUT;
module_param(timeout, int, 0);
MODULE_PARM_DESC(timeout, "timeout value for watchdog");

int pool_size = 8;
module_param(pool_size, int, 0);
MODULE_PARM_DESC(pool_size, "size of buffer pool");

/* Source port for tunnel connections that originate locally. */
static unsigned short tunnel_source_port = 8080;
module_param(tunnel_source_port, ushort, 0444);
MODULE_PARM_DESC(tunnel_source_port, "source port to use for new tunnel connections");

/* Timeout for inactive flows in cache in milliseconds.  Default value is one
 * hour.  We use a conservative value because this can break flows. */
static unsigned long flow_table_timeout = 3600000;
module_param(flow_table_timeout, ulong, 0644);
MODULE_PARM_DESC(flow_table_timeout, "timeout for inactive flows in cache (msecs)");

/* Size of flow hash table as a power of two.  This is read-only because we
 * do not want to resize the table at runtime. */
static unsigned flow_table_bits = 16;
module_param(flow_table_bits, uint, 0444);
MODULE_PARM_DESC(flow_table_bits, "size of flow hash table (power of two)");

/* Resynchronization timeout - sequence numbers are assumed to be out-of-sync
 * if no packet has been received in this time. */
static unsigned long resync_timeout = 5000;
module_param(resync_timeout, ulong, 0644);
MODULE_PARM_DESC(resync_timeout, "timeout for sequence number synchronization (msecs)");

static unsigned tx_queue_limit = 100;
module_param(tx_queue_limit, uint, 0644);
MODULE_PARM_DESC(tx_queue_limit, "maximum number of queued packets");

bool virt_deliver_late_packets = 0;
module_param(virt_deliver_late_packets, bool, 0644);

long virt_max_reorder_delay = 500000;
module_param(virt_max_reorder_delay, long, 0644);

unsigned long min_reassign_delay = 3000;
module_param(min_reassign_delay, ulong, 0644);
MODULE_PARM_DESC(min_reassign_delay, 
        "minimum time between nonessential single-path flow reassignments (msecs)");

unsigned long stall_threshold_bytes = ULONG_MAX;
module_param(stall_threshold_bytes, ulong, 0644);
MODULE_PARM_DESC(stall_threshold_bytes, "threshold of unacknowledged bytes");

unsigned long stall_threshold_packets = ULONG_MAX;
module_param(stall_threshold_packets, ulong, 0644);
MODULE_PARM_DESC(stall_threshold_packets, "threshold of unacknowledged packets");

/* Size of remote node hash table as a power of two.  This is read-only because
 * we do not want to resize the table at runtime. */
static unsigned remote_node_table_bits = 7;
module_param(remote_node_table_bits, uint, 0444);
MODULE_PARM_DESC(remote_node_table_bits, "size of remote node table (power of two)");

/* Size of remote link hash table as a power of two.  This is read-only because
 * we do not want to resize the table at runtime. */
static unsigned remote_link_table_bits = 9;
module_param(remote_link_table_bits, uint, 0444);
MODULE_PARM_DESC(remote_link_table_bits, "size of remote link table (power of two)");

/* Size of path hash table as a power of two.  This is read-only because
 * we do not want to resize the table at runtime. */
static unsigned path_table_bits = 16;
module_param(path_table_bits, uint, 0444);
MODULE_PARM_DESC(remote_link_table_bits, "size of path table (power of two)");

/* Probe packets (duplicates of data packets) are sent periodically on stalled
 * paths.  The interval between probes will be probe_inteval (in ms). */
static unsigned probe_interval = 200;
module_param(probe_interval, uint, 0644);
MODULE_PARM_DESC(probe_interval, "interval between probes on stalled paths (msecs)");

/* Interval between checking tx_queue for packets that can be sent. */
static unsigned long tx_queue_timer = 10;
module_param(tx_queue_timer, ulong, 0644);
MODULE_PARM_DESC(tx_queue_timer, "interval between checking tx_queue (msecs)");

/* Minimum time to retain copies of received packets for recovery opportunities. */
static unsigned long rx_retain_time = 10000;
module_param(rx_retain_time, ulong, 0644);
MODULE_PARM_DESC(rx_retain_time, "min time to retain copies of received packets for recovery opportunities (msecs)");

/* Size of reorder queue in packets. */
static unsigned reorder_queue_size = 128;
module_param(reorder_queue_size, uint, 0644);
MODULE_PARM_DESC(reorder_queue_size, "maximum number of packets to store in reorder queue");

/* -------------------------------- Globals -------------------------------- */

/* TODO: Make a list when we can support multiple virtual interfaces. */
static struct net_device *master_dev = NULL;

/* -------------------------------- Prototypes -------------------------------- */
void virt_setup(struct net_device *dev);
static __init int virt_init(void);
void virt_cleanup(struct net_device *dev);
static __exit void virt_exit(void);
int virt_open(struct net_device *dev);
int virt_close(struct net_device *dev);

/* -------------------------------- Structures -------------------------------- */

static const struct net_device_ops virt_netdev_ops = {
	.ndo_open       = virt_open,
	.ndo_stop       = virt_close,
	.ndo_set_config = virt_config,
	.ndo_start_xmit = virt_tx,
	.ndo_do_ioctl   = virt_ioctl,
	.ndo_get_stats  = virt_stats,
	.ndo_change_mtu = virt_change_mtu,
	.ndo_tx_timeout = virt_tx_timeout,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    .ndo_add_slave  = virt_add_slave,
    .ndo_del_slave  = virt_del_slave,
#endif
};

#ifndef VIRT_USE_RTABLE
static struct nf_hook_ops nf_rx_arp_ops = {
    .hook     = (nf_hookfn *)recv_arp,
    .hooknum  = NF_ARP_IN,
    .pf       = NFPROTO_ARP,
    .priority = NF_IP_PRI_FIRST,
};

/*
static struct nf_hook_ops nf_tx_arp_ops = {
    .hook     = (nf_hookfn *)send_arp,
    .hooknum  = NF_ARP_OUT,
    .pf       = NFPROTO_ARP,
    .priority = NF_IP_PRI_FIRST,
};
*/
#endif /* !VIRT_USE_RTABLE */

static struct nf_hook_ops nf_ops = {
    .hook     = (nf_hookfn *)recv_ip,
    .hooknum  = NF_INET_LOCAL_IN,
    .pf       = NFPROTO_IPV4,
    .priority = NF_IP_PRI_LAST,
};


/* -------------------------------- Load/Unload -------------------------------- */

/*
 * The init function (sometimes called probe).
 * It is invoked by register_netdev()
 */
void virt_setup(struct net_device *dev)
{
	struct virt_priv *priv;
    
    if(unlikely(!dev))
        return;

    // setup net_device structure
    dev->type = ARPHRD_ETHER;
    dev->hard_header_len = ETH_HLEN;
    dev->needed_headroom = VIRT_HEADER_MAX_LEN;
    dev->mtu = ETH_DATA_LEN;
    dev->addr_len = ETH_ALEN;
    dev->tx_queue_len = ETH_DATA_LEN;
    //dev->features = NETIF_F_NO_CSUM;
    //IFF_NOARP is problematic because eth_header behaves differently with it.
    //dev->flags = IFF_NOARP;
	dev->watchdog_timeo = timeout;

    dev->header_ops = NULL;

    dev->netdev_ops = &virt_netdev_ops;

	memset(dev->dev_addr,  0x00, ETH_ALEN);
	memset(dev->broadcast, 0xff, ETH_ALEN);

	/*
	 * Then, initialize the priv field. This encloses the statistics
	 * and a few private fields.
	 */
	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(struct virt_priv));
    priv->max_dev_prio = MIN_USABLE_DEVICE_PRIORITY;
	spin_lock_init(&priv->lock);
	virt_setup_pool(dev);
}


static __init int virt_init(void)
{
	int result, ret = -ENOMEM;
    struct virt_priv *virt;
	
	printk(KERN_ALERT "Loading virt interface module.\n");
    printk(KERN_INFO "%s - version %s\n",
           virt_driver_string, virt_driver_version);

    printk(KERN_INFO "%s\n", virt_copyright);

	/* Allocate the devices */
	master_dev = alloc_netdev(sizeof(struct virt_priv), VIRT_DEV_NAME, virt_setup);
	if( master_dev == NULL)
		goto out;

    virt = netdev_priv(master_dev);

    if( nf_register_hook(&nf_ops) != 0)
        VIRT_ERR("netfilter register hook failed\n");
#ifndef VIRT_USE_RTABLE
    if( nf_register_hook(&nf_rx_arp_ops) != 0)
        VIRT_ERR("netfilter register arp hook failed\n");
//    if( nf_register_hook(&nf_tx_arp_ops) != 0)
//        VIRT_ERR("netfilter register arp hook failed\n");
#endif

    if(virt_init_vroute_table(virt) < 0)
        VIRT_ERR("virt_init_vroute_table failed");

    if(virt_register_algorithms() < 0)
        VIRT_ERR("virt_register_algorithms failed\n");

	// don't register until everything is completely initialized
	// cause it is callable after register
	ret = -ENODEV;
    if( (result = register_netdev(master_dev)) )
        printk("virt: error %i registering device \"%s\"\n", result, master_dev->name);
    else
        ret = 0;

    virt_policy_setup(virt);
    
    // TODO: set an independent size for the nat table
    if(init_nat_table(flow_table_bits) != 0)
        VIRT_ERR("init_nat_table failed");

    if(virt_hash_table_init(&virt->network.node_table, remote_node_table_bits) != 0)
        VIRT_ERR("remote node table initialization failed");
    if(virt_hash_table_init(&virt->network.link_table, remote_link_table_bits) != 0)
        VIRT_ERR("remote link table initialization failed");
    if(virt_hash_table_init(&virt->network.path_table, path_table_bits) != 0)
        VIRT_ERR("path table initialization failed");

    if(init_flow_table(&virt->flow_table, flow_table_bits) != 0)
        VIRT_ERR("init_flow_table failed");

    if( virt_setup_proc(master_dev) != 0 )
        VIRT_ERR("procfs setup failed");

out:
	if( ret ) 
		virt_cleanup(master_dev);
	return ret;
}
module_init(virt_init);

static void stop_all_timers(struct virt_priv *virt)
{
    const struct virt_hash_table *remote_nodes = &virt->network.node_table;
    int i;

    rcu_read_lock();
    for(i = 0; i < remote_nodes->size; i++) {
        struct virt_hash_head *head = &remote_nodes->head[i];
        struct remote_node *node;
        struct hlist_node *pos;

        hlist_for_each_entry_rcu(node, pos, &head->list, hlist) {
            node->restart_timer = false;
            del_timer(&node->tx_queue_timer);

            node->reorder_head.restart_timer = false;
            del_timer(&node->reorder_head.timer);
        }
    }
    rcu_read_unlock();

    virt->flow_table.restart_timer = false;
    del_timer(&virt->flow_table.timer);
}

void virt_cleanup(struct net_device *dev)
{
    struct virt_priv *priv = netdev_priv(dev);

    /* Need to clean up slave list before unregistering, because the slaves may hold
     * references to our device. */
    VIRT_DBG("cleanup slave list\n");
    slave_list_destroy(dev);
    
    unregister_netdev(dev);

    virt_free_vroute_table(priv);

    VIRT_DBG("cleanup proc files\n");
    virt_cleanup_proc(priv);

    flow_table_kill_retx(&priv->flow_table);

#ifdef SAFE_SHUTDOWN
    stop_all_timers(priv);
#else
    VIRT_DBG("cleanup lookup table\n");
    flow_table_destroy(&priv->flow_table);
    nat_table_destroy(); // must not be called before flow_table_destroy
    virt_policy_cleanup(priv);
    remote_node_list_destroy(&priv->network);
#endif

    nf_unregister_hook(&nf_ops);
#ifndef VIRT_USE_RTABLE
    nf_unregister_hook(&nf_rx_arp_ops);
//    nf_unregister_hook(&nf_tx_arp_ops);
#endif

    virt_teardown_pool(dev);
    free_netdev(dev);

    /* Wait for rcu objects to be cleaned up. */
    synchronize_rcu();

    /* Check whether we missed anything. */
    warn_on_memory_leaks();

    VIRT_DBG("cleanup finished\n");
}



static __exit void virt_exit(void)
{
	printk(KERN_ALERT "Unloading virt interface module.\n");

    /* TODO: Loop over all virtual interfaces when we can support multiple. */
    virt_cleanup(master_dev);
}
module_exit(virt_exit);


/*
 * Open and close
 */

int virt_open(struct net_device *dev)
{
    struct in_device *in_dev;
    struct in_ifaddr **ifap = NULL;
    struct in_ifaddr *ifa = NULL;
    struct virt_priv *virt = netdev_priv(dev);

    VIRT_INFO("virt_open()... \n");

    // TODO: make a function to init the master dev
    // this code is modeled from net/ipv4/devinet.c devinet_ioctl()
    // get the ip_ptr from the net_device structure
    in_dev = in_dev_get(dev);
    if( in_dev != NULL )
    {
        // in_dev (ip_ptr) has a ifa_list to loop through
        for(ifap = &in_dev->ifa_list; (ifa = *ifap) != NULL; ifap = &ifa->ifa_next)
        {
            if( strncmp(dev->name, ifa->ifa_label, IFNAMSIZ) == 0)
            {
                // save off the master's IP address
                virt->ip4 = ifa->ifa_local;
            }
        }
    }
    in_dev_put(in_dev);

	netif_start_queue(dev);

	return 0;
}

int virt_close(struct net_device *dev)
{
    VIRT_INFO("virt_close()... \n");

	netif_stop_queue(dev); /* can't transmit any more */
	return 0;
}





/* -------------------------------- Transmit -------------------------------- */

/*
 * Set up a device's packet pool.
 */
// TODO: do we still need this code???
void virt_setup_pool(struct net_device *dev)
{
	struct virt_priv *priv = netdev_priv(dev);
	int i;
	struct virt_packet *pkt;

	priv->ppool = NULL;
	for (i = 0; i < pool_size; i++) {
		pkt = kmalloc (sizeof (struct virt_packet), GFP_KERNEL);
		if (pkt == NULL) {
			VIRT_ERR(KERN_NOTICE "Ran out of memory allocating packet pool\n");
			return;
		}
		pkt->dev = dev;
		pkt->next = priv->ppool;
		priv->ppool = pkt;
	}
}

void virt_teardown_pool(struct net_device *dev)
{
	struct virt_priv *priv = netdev_priv(dev);
	struct virt_packet *pkt;
    
	while ((pkt = priv->ppool)) {
		priv->ppool = pkt->next;
		kfree (pkt);
		/* FIXME - in-flight packets ? */
	}
}    

/*
 * Buffer/pool management.
 */
struct virt_packet *virt_get_tx_buffer(struct net_device *dev)
{
	struct virt_priv *priv = netdev_priv(dev);
	unsigned long flags;
	struct virt_packet *pkt;
    
	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->ppool;
	priv->ppool = pkt->next;
	if (priv->ppool == NULL) {
		VIRT_ERR(KERN_INFO "Pool empty\n");
		netif_stop_queue(dev);
	}
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;
}


void virt_release_buffer(struct virt_packet *pkt)
{
	unsigned long flags;
	struct virt_priv *priv = netdev_priv(pkt->dev);
	
	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->ppool;
	priv->ppool = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
	if (netif_queue_stopped(pkt->dev) && pkt->next == NULL)
		netif_wake_queue(pkt->dev);
}

void virt_enqueue_buf(struct net_device *dev, struct virt_packet *pkt)
{
	unsigned long flags;
	struct virt_priv *priv = netdev_priv(dev);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->rx_queue;  /* FIXME - misorders packets */
	priv->rx_queue = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
}

struct virt_packet *virt_dequeue_buf(struct net_device *dev)
{
	struct virt_priv *priv = netdev_priv(dev);
	struct virt_packet *pkt;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->rx_queue;
	if (pkt != NULL)
		priv->rx_queue = pkt->next;
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;
}

/*
 * Free a packet structure.
 */
void virt_free_packet(struct packet *pkt)
{
    if(WARN_ON(!pkt))
        return;

    if(pkt->ftable_entry)
        flow_table_entry_put(pkt->ftable_entry);

    if(pkt->hdr_ptrs)
        kfree(pkt->hdr_ptrs);
    
    if(pkt->key)
        kfree(pkt->key);

    //kfree(pkt->flow_stats);

    kfree(pkt);
}

/*
 * Test if the device name is a virtual interface.
 */
int is_virt_interface(const char *name)
{
    return (strncmp(name, VIRT_DEV_PREFIX, strlen(VIRT_DEV_PREFIX)) == 0);
}

/*
 * Get the timeout for inactive flows in jiffies.
 */
unsigned long get_flow_table_timeout_jiffies(void)
{
    return msecs_to_jiffies(flow_table_timeout);
}

/*
 * Get the sequence number synchronization timeout in jiffies.
 */
unsigned long get_resync_timeout_jiffies(void)
{
    return msecs_to_jiffies(resync_timeout);
}

/*
 * Get the source port for tunnel connections originating locally.
 */
unsigned short virt_tunnel_source_port(void)
{
    return tunnel_source_port;
}

/*
 * Get the maximum number of packets in the tx_queue.
 */
unsigned virt_tx_queue_limit(void)
{
    return tx_queue_limit;
}

/*
 * Get the minimum time between nonessential single-path flow reassignments in
 * jiffies.
 */
unsigned long get_min_reassign_delay_jiffies(void)
{
    return msecs_to_jiffies(min_reassign_delay);
}

/*
 * Get the threshold of unacknowledged bytes for declaring link stalled.
 */
unsigned long virt_stall_threshold_bytes(void)
{
    return stall_threshold_bytes;
}

/*
 * Get the threshold of unacknowledged packets for declaring link stalled.
 */
unsigned long virt_stall_threshold_packets(void)
{
    return stall_threshold_packets;
}

/*
 * Get the interval between probes on stalled paths.
 */
unsigned virt_probe_interval_jiffies(void)
{
    return msecs_to_jiffies(probe_interval);
}

/*
 * Get the timer interval in jiffies.
 */
unsigned long virt_tx_queue_timer_jiffies(void)
{
    return msecs_to_jiffies(tx_queue_timer);
}

/*
 * Get the time in jiffies to retain received packets for recovery opportunities
 * via network coding.
 */
unsigned long virt_rx_retain_time_jiffies(void)
{
    return msecs_to_jiffies(rx_retain_time);
}

unsigned virt_reorder_queue_size(void)
{
    return reorder_queue_size;
}

