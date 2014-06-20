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
#include <linux/kernel.h> /* printk() */
#include <linux/proc_fs.h>
#include <linux/list.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include "virt.h"
#include "virtStats.h"
#include "virtDebug.h"
#include "virtPolicy.h"
#include "virtProcFs.h"
#include "virtDevList.h"
#include "virtPolicyTypes.h"
#include "virtNetwork.h"
#include "virtRoute.h"
#include "virtSelectInterface.h"
#include "virtFlowTable.h"
#include "virtParse.h"
#include "virtEgressLookup.h"
#include "virtPassive.h"
#include "virtMemory.h"

// examples: http://www.rt-embedded.com/blog/archives/creating-and-using-proc-files/


// code in this file is based off of code from Documentation/DocBook/procfs_example.c
#define MODULE_PROC_NAME "virtmod"

// Wrapper around remove_proc_entry that checks the pointer and sets it to null
// after removing.
#define REMOVE_PROC_ENTRY(name, parent_entry, entry)  \
do {                                    \
    if(entry) {                         \
        remove_proc_entry(name, parent_entry); \
        entry = NULL;                      \
    }                                   \
} while(0)

/* ------------------------ globals --------------------------- */
static struct proc_dir_entry *proc_dir_virtmod          = NULL;

static struct proc_dir_entry *proc_dir_stats            = NULL;
static struct proc_dir_entry *proc_file_module_stats    = NULL;
static struct proc_dir_entry *proc_file_link_stats      = NULL;

static struct proc_dir_entry *proc_dir_stats_timing     = NULL;
static struct proc_dir_entry *proc_file_get_timing      = NULL;
static struct proc_dir_entry *proc_file_log_timing      = NULL;

static struct proc_dir_entry *proc_dir_slaves           = NULL;
static struct proc_dir_entry *proc_file_slave_list      = NULL;

static struct proc_dir_entry *proc_dir_policy           = NULL;
static struct proc_dir_entry *proc_file_policy          = NULL;

/* ----------------------- prototypes -------------------------- */
static int proc_read_slave_list(char *page, char **start, off_t off, int count, int *eof, void *data);

static int proc_read_module_stats(char *page, char **start, off_t off, int count, int *eof, void *data);

static int proc_read_link_stats(char *page, char **start, off_t off, int count, int *eof, void *data);

static int proc_read_get_timing(char *page, char **start, off_t off, int count, int *eof, void *data);
static int proc_read_log_timing(char *page, char **start, off_t off, int count, int *eof, void *data);

static int proc_write_log_timing(struct file *flip, const char *buff, unsigned long len, void *data);

static int setup_remote_proc(struct virt_priv *virt);
static int proc_read_vroutes(char *page, char **start, off_t off, int count, int *eof, void *data);

static int setup_policy_proc(struct virt_priv *virt);
static int setup_ftable(struct virt_priv *virt);
static int setup_paths(struct virt_priv *virt);
static int setup_mem_stats(struct virt_priv *virt);

/* ------------------------ functions ------------------------- */

/*
 * virt_setup_proc: (global)
 *      setup the proc file directory and files
 * virt_cleanup_proc: (global)
 *      remove the procfile directories and files
 */
int virt_setup_proc(struct net_device *master)
{
    struct virt_priv *virt = netdev_priv(master);
    int ret = 0;

    // create module's root proc directory
    proc_dir_virtmod = proc_mkdir(MODULE_PROC_NAME, NULL);
    if( proc_dir_virtmod == NULL ) {
        ret = -ENOMEM;
        goto error;
    }

    // create stats directory structure
    proc_dir_stats = proc_mkdir("stats", proc_dir_virtmod);
    if( proc_dir_stats == NULL ) {
        ret = -ENOMEM;
        goto error_dir_stats;
    }

    proc_file_module_stats = create_proc_read_entry("module_stats", 0,
                                proc_dir_stats, proc_read_module_stats, master);
    if( proc_file_module_stats == NULL ) {
        ret = -ENOMEM;
        goto error_file_module_stats;
    }

    proc_file_link_stats = create_proc_read_entry("link_stats", 0,
                                proc_dir_stats, proc_read_link_stats, NULL);
    if( proc_file_link_stats == NULL ) {
        ret = -ENOMEM;
        goto error_file_link_stats;
    }

    proc_dir_stats_timing = proc_mkdir("timing", proc_dir_stats);
    if( proc_dir_stats_timing == NULL ) {
        ret = -ENOMEM;
        goto error_dir_timing;
    }

    proc_file_get_timing = create_proc_read_entry("timing_stats", 0,
                                proc_dir_stats_timing, proc_read_get_timing, NULL);
    if( proc_file_get_timing == NULL ) {
        ret = -ENOMEM;
        goto error_file_get_timing;
    }

    proc_file_log_timing = create_proc_entry("log_timing", 644,
                                proc_dir_stats_timing);
    if( proc_file_log_timing == NULL ) {
        ret = -ENOMEM;
        goto error_file_log_timing;
    }

    //proc_file_log_timing->owner      = THIS_MODULE;
    proc_file_log_timing->data       = NULL;
    proc_file_log_timing->read_proc  = proc_read_log_timing;
    proc_file_log_timing->write_proc = proc_write_log_timing;

    // create slave directory
    proc_dir_slaves = proc_mkdir("slaves", proc_dir_virtmod);
    if( proc_dir_slaves == NULL ) {
        ret = -ENOMEM;
        goto error_dir_slaves;
    }

    // create proc file for slave list
    proc_file_slave_list = create_proc_read_entry("slave_list", 0,
                                proc_dir_slaves, proc_read_slave_list, NULL);
    if( proc_file_slave_list == NULL ) {
        ret = -ENOMEM;
        goto error_file_slave_list;
    }

    // Create proc files for remote node and link lists.
    // If this fails, the module will be unable to perform tunneling.
    if( (ret = setup_remote_proc(virt)) != 0 ) {
        VIRT_DBG("Failed creating proc files for remote nodes and links.\n");
    }

    ret = setup_policy_proc(virt);
    if(ret != 0) {
        VIRT_DBG("Failed to create policy proc files.\n");
    }

    ret = setup_ftable(virt);
    if(ret != 0) {
        VIRT_DBG("Failed to create ftable proc file (returned %d).\n", ret);
    }
    
    ret = setup_paths(virt);
    if(ret != 0) {
        VIRT_DBG("Failed to create paths proc file (returned %d).\n", ret);
    }

    ret = setup_mem_stats(virt);
    if(ret != 0) {
        VIRT_DBG("Failed to create mem_stats proc file (returned %d).\n", ret);
    }

    return 0;

error_file_slave_list:
    REMOVE_PROC_ENTRY("slaves", proc_dir_virtmod, proc_dir_slaves);
error_dir_slaves:
    REMOVE_PROC_ENTRY("log_timing", proc_dir_stats_timing, proc_file_log_timing);
error_file_log_timing:
    REMOVE_PROC_ENTRY("timing_stats", proc_dir_stats_timing, proc_file_get_timing);
error_file_get_timing:
    REMOVE_PROC_ENTRY("timing", proc_dir_stats, proc_dir_stats_timing);
error_dir_timing:
    REMOVE_PROC_ENTRY("link_stats", proc_dir_stats, proc_file_link_stats);
error_file_link_stats:
    REMOVE_PROC_ENTRY("module_stats", proc_dir_stats, proc_file_module_stats);
error_file_module_stats:
    REMOVE_PROC_ENTRY("stats", proc_dir_virtmod, proc_dir_stats);
error_dir_stats:
    REMOVE_PROC_ENTRY(MODULE_PROC_NAME, NULL, proc_dir_virtmod);
error:
    return ret;
}


int virt_cleanup_proc(struct virt_priv *virt)
{
    REMOVE_PROC_ENTRY("mem_stats", proc_dir_virtmod, virt->proc_mem_stats);
    REMOVE_PROC_ENTRY("paths", proc_dir_virtmod, virt->proc_paths);
    REMOVE_PROC_ENTRY("ftable", proc_dir_virtmod, virt->proc_ftable);

    REMOVE_PROC_ENTRY("policy_v4", proc_dir_policy, proc_file_policy);
    REMOVE_PROC_ENTRY("policy" , proc_dir_virtmod, proc_dir_policy);

    REMOVE_PROC_ENTRY("nodes", virt->proc_remote, virt->proc_remote_nodes);
    REMOVE_PROC_ENTRY("links", virt->proc_remote, virt->proc_remote_links);
    REMOVE_PROC_ENTRY("vroutes", virt->proc_remote, virt->proc_remote_vroutes);
    REMOVE_PROC_ENTRY("reorder", virt->proc_remote, virt->proc_reorder_stats);
    REMOVE_PROC_ENTRY("remote", proc_dir_virtmod, virt->proc_remote);

    // slave files
    REMOVE_PROC_ENTRY("slave_list", proc_dir_slaves, proc_file_slave_list);
    REMOVE_PROC_ENTRY("slaves", proc_dir_virtmod, proc_dir_slaves);

    // stats files
    REMOVE_PROC_ENTRY("log_timing", proc_dir_stats_timing, proc_file_log_timing);
    REMOVE_PROC_ENTRY("timing_stats", proc_dir_stats_timing, proc_file_get_timing);
    REMOVE_PROC_ENTRY("timing", proc_dir_stats, proc_dir_stats_timing);
    
    REMOVE_PROC_ENTRY("link_stats", proc_dir_stats, proc_file_link_stats);
    REMOVE_PROC_ENTRY("module_stats", proc_dir_stats, proc_file_module_stats);
    REMOVE_PROC_ENTRY("stats", proc_dir_virtmod, proc_dir_stats);

    // module's root directory
    REMOVE_PROC_ENTRY(MODULE_PROC_NAME, NULL, proc_dir_virtmod);

    return 0;
}



static int proc_read_slave_list(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    struct device_node *head;

    list_for_each_entry(head, get_slave_list_head(), lif.list) {
        int dev_status = 0;
        if(head->flags & DEVICE_NO_TX)
            dev_status = 1;

        len += sprintf(page + len, "%16s: %d 0x%08x 0x%02x:%02x:%02x:%02x:%02x:%02x 0x%02x:%02x:%02x:%02x:%02x:%02x %d %9ld %9ld %u\n", 
                        head->dev->name, 
                        dev_status, 
                        (unsigned int)head->lif.ip4,
                        head->dev->dev_addr[0], 
                        head->dev->dev_addr[1], 
                        head->dev->dev_addr[2],
                        head->dev->dev_addr[3], 
                        head->dev->dev_addr[4], 
                        head->dev->dev_addr[5],
                        head->next_hop_addr[0], 
                        head->next_hop_addr[1], 
                        head->next_hop_addr[2],
                        head->next_hop_addr[3], 
                        head->next_hop_addr[4], 
                        head->next_hop_addr[5],
                        head->lif.prio,
                        head->lif.flow_count,
                        head->lif.bandwidth_hint,
                        head->lif.active_paths);
    }

    if( len <= count + off )
        *eof = 1;
    *start = page + off;

    len -= off;

    if( len > count )
        len = count;
    if( len < 0 )
        len = 0;

    return len;
}



static int proc_read_module_stats(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    struct net_device *master = (struct net_device *)data;
    struct virt_priv *priv = netdev_priv(master);
    
    len += sprintf(page + len, "-----------------------\n");
    len += sprintf(page + len, "       | Received                                | Transmitted\n");
    len += sprintf(page + len, "ifname | bytes packets errors dropped compressed | bytes packets errors dropped compressed\n");
    len += sprintf(page + len, "-----------------------\n");

    len += sprintf(page + len, "%6s | %5lu %7lu %6lu %7lu %10lu | "
                         "%5lu %7lu %6lu %7lu %10lu\n",
                    master->name,
                    priv->stats.rx_bytes,
                    priv->stats.rx_packets,
                    priv->stats.rx_errors,
                    priv->stats.rx_dropped,
                    priv->stats.rx_compressed,
                    priv->stats.tx_bytes,
                    priv->stats.tx_packets,
                    priv->stats.tx_errors,
                    priv->stats.tx_dropped,
                    priv->stats.tx_compressed);

    if( len <= count + off )
        *eof = 1;
    *start = page + off;

    len -= off;

    if( len > count )
        len = count;
    if( len < 0 )
        len = 0;

    return len;
}

static int proc_read_link_stats(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    struct device_node *head;

    len += sprintf(page + len, "-----------------------\n");
    len += sprintf(page + len, "       | Received                                | Transmitted\n");
    len += sprintf(page + len, "ifname | bytes packets errors dropped compressed | bytes packets errors dropped compressed\n");
    len += sprintf(page + len, "-----------------------\n");

    list_for_each_entry(head, get_slave_list_head(), lif.list) {
        len += sprintf(page + len, "%6s | %5lu %7lu %6lu %7lu %10lu | "
                             "%5lu %7lu %6lu %7lu %10lu\n",
                        head->dev->name,
                        head->stats.rx_bytes,
                        head->stats.rx_packets,
                        head->stats.rx_errors,
                        head->stats.rx_dropped,
                        head->stats.rx_compressed,
                        head->stats.tx_bytes,
                        head->stats.tx_packets,
                        head->stats.tx_errors,
                        head->stats.tx_dropped,
                        head->stats.tx_compressed);
    }

    if( len <= count + off )
        *eof = 1;
    *start = page + off;

    len -= off;

    if( len > count )
        len = count;
    if( len < 0 )
        len = 0;

    return len;
}

static int proc_read_get_timing(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    int index = 0;
    int loop_max = TIMING_NUM_ELEMENTS;
    s64 *array = NULL;

    len += sprintf(page + len, "-----------------------\n");
    len += sprintf(page + len, "| Transmit                         | Recieve\n");
    len += sprintf(page + len, "| setup lookup mangle done packets | setup lookup mangle done packets\n");
    len += sprintf(page + len, "-----------------------\n");

    if( use_timing() ) {
        array = get_timing_array();
        while( index < loop_max ) {
            if( (index != TIMING_TX_START) && (index != TIMING_RX_START) ) 
                len += sprintf(page + len, "%lld ", array[index]);
            index++;
        }
        len += sprintf(page + len, "\n");
    } else
        len += sprintf(page + len, "0 0 0 0 0 0 0 0 0 0\n");

    return len;
}


static int proc_read_log_timing(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    len += sprintf(page + len, "%d\n", use_timing());
    return len;
}


static int proc_write_log_timing(struct file *flip, const char *buff, unsigned long len, void *data)
{
    char *value_buf;
    int value  = 0;
    int size   = sizeof(int);

    if( len > size )
        return -EINVAL;
    value_buf = (char *)kmalloc(size, GFP_KERNEL);
    //value_buf = (char *)valloc(size);
    if( !value_buf )
        return -ENOMEM;

    if( copy_from_user(value_buf, buff, size) ) {
        kfree(value_buf);
        //vfree(value_buf);
        return -EFAULT;
    }

    sscanf(value_buf, "%d", &value);
    set_timing(value);

    kfree(value_buf);
    //vfree(value_buf);
    return len;
}

static int ct_policy_show(struct seq_file *s, void *p)
{
    struct virt_priv *virt = s->private;
    struct policy_entry *entry;

    seq_printf(s, "Egress Policy Table\n");
    seq_printf(s, "source   netmask  dest     netmask  prot spt  dpt  action   link selection   refcnt rxpkts txpkts rxbytes  txbytes \n");
    
    rcu_read_lock();

    list_for_each_entry_rcu(entry, &virt->policy_list_flow_egress.list, list) {
        const char *link_sel_alg = entry->alg ? entry->alg->name : "NULL";
        const struct policy_stats *stats = &entry->stats;

        seq_printf(s, "%08x %08x %08x %08x %04hx %04hx %04hx %08x %-16s %6d %6lu %6lu %8lu %8lu\n",
                entry->flow.src_addr, entry->flow.src_netmask,
                entry->flow.dst_addr, entry->flow.dst_netmask,
                entry->flow.proto,
                entry->flow.src_port, entry->flow.dst_port,
                entry->action, link_sel_alg, atomic_read(&entry->refcnt),
                stats->rx_packets, stats->tx_packets,
                stats->rx_bytes, stats->tx_bytes);
    }

    seq_printf(s, "Ingress Policy Table\n");
    seq_printf(s, "source   netmask  dest     netmask  prot spt  dpt  action   link selection   refcnt rxpkts txpkts rxbytes  txbytes \n");
    
    list_for_each_entry_rcu(entry, &virt->policy_list_flow_ingress.list, list) {
        const char *link_sel_alg = entry->alg ? entry->alg->name : "NULL";
        const struct policy_stats *stats = &entry->stats;

        seq_printf(s, "%08x %08x %08x %08x %04hx %04hx %04hx %08x %-16s %6d %6lu %6lu %8lu %8lu\n",
                entry->flow.src_addr, entry->flow.src_netmask,
                entry->flow.dst_addr, entry->flow.dst_netmask,
                entry->flow.proto,
                entry->flow.src_port, entry->flow.dst_port,
                entry->action, link_sel_alg, atomic_read(&entry->refcnt),
                stats->rx_packets, stats->tx_packets,
                stats->rx_bytes, stats->tx_bytes);
    }

    rcu_read_unlock();

    return 0;
}

static int ct_policy_open(struct inode *inode, struct file *file)
{
    struct virt_priv *virt = PROC_I(inode)->pde->data;
    int result;

    result = single_open(file, ct_policy_show, virt);
    if(result < 0)
        return result;

    return 0;
}

static const struct file_operations ct_policy_fops = {
    .owner   = THIS_MODULE,
    .open    = ct_policy_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

/*
 * setup the proc directory and files for the policy API
 */
static int setup_policy_proc(struct virt_priv *virt)
{
    int ret = 0;

    proc_dir_policy = proc_mkdir("policy", proc_dir_virtmod);
    if( proc_dir_policy == NULL ) {
        ret = -ENOMEM;
        goto error_dir_policy;
    }

    proc_file_policy = create_proc_entry("policy_v4", 644, proc_dir_policy);
    if( proc_file_policy == NULL ) {
        ret = -ENOMEM;
        goto error_file_policy;
    }

    proc_file_policy->proc_fops = &ct_policy_fops;
    proc_file_policy->data = virt;

    return ret;

error_file_policy:
    REMOVE_PROC_ENTRY("policy", proc_dir_virtmod, proc_dir_policy);
error_dir_policy:
    return ret;
}

/*
 * Print the contents of the flow table.
 */
static int ct_ftable_show(struct seq_file *s, void *p)
{
    struct virt_priv *virt = s->private;

    dump_flow_table(s, virt);

    return 0;
}

static int ct_ftable_open(struct inode *inode, struct file *file)
{
    struct virt_priv *virt = PROC_I(inode)->pde->data;
    int result;

    result = single_open(file, ct_ftable_show, virt);
    if(result < 0)
        return result;

    return 0;
}

static const struct file_operations ct_ftable_fops = {
    .owner   = THIS_MODULE,
    .open    = ct_ftable_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

/*
 * Set up a proc file for reading the flow cache.
 */
static int setup_ftable(struct virt_priv *virt) {
    virt->proc_ftable = create_proc_entry("ftable", 644, proc_dir_virtmod);
    if(!virt->proc_ftable) {
        return -ENOMEM;
    }

    virt->proc_ftable->proc_fops = &ct_ftable_fops;
    virt->proc_ftable->data = virt;

    return 0;
}

static int ct_paths_open(struct inode *inode, struct file *file)
{
    struct virt_priv *virt = PROC_I(inode)->pde->data;
    int result;

    result = single_open(file, dump_path_list, virt);
    if(result < 0)
        return result;

    return 0;
}

static const struct file_operations ct_paths_fops = {
    .owner   = THIS_MODULE,
    .open    = ct_paths_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

/*
 * Set up a proc file for reading the path list.
 */
static int setup_paths(struct virt_priv *virt) {
    virt->proc_paths = create_proc_entry("paths", 644, proc_dir_virtmod);
    if(!virt->proc_paths) {
        return -ENOMEM;
    }

    virt->proc_paths->proc_fops = &ct_paths_fops;
    virt->proc_paths->data = virt;

    return 0;
}

static int ct_remote_nodes_open(struct inode *inode, struct file *file)
{
    struct virt_priv *virt = PROC_I(inode)->pde->data;
    int result;

    result = single_open(file, dump_remote_node_list, virt);
    if(result < 0)
        return result;

    return 0;
}

static const struct file_operations ct_remote_nodes_fops = {
    .owner   = THIS_MODULE,
    .open    = ct_remote_nodes_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

static int ct_remote_links_open(struct inode *inode, struct file *file)
{
    struct virt_priv *virt = PROC_I(inode)->pde->data;
    int result;

    result = single_open(file, dump_remote_link_list, virt);
    if(result < 0)
        return result;

    return 0;
}

static const struct file_operations ct_remote_links_fops = {
    .owner   = THIS_MODULE,
    .open    = ct_remote_links_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

static int ct_reorder_stats_open(struct inode *inode, struct file *file)
{
    struct virt_priv *virt = PROC_I(inode)->pde->data;
    int result;

    result = single_open(file, dump_reorder_stats, virt);
    if(result < 0)
        return result;

    return 0;
}

static const struct file_operations ct_reorder_stats_fops = {
    .owner   = THIS_MODULE,
    .open    = ct_reorder_stats_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

/*
 * Set up proc subdirectory for management of remote nodes and links.
 */
static int setup_remote_proc(struct virt_priv *virt)
{
    int ret = 0;

    virt->proc_remote = proc_mkdir("remote", proc_dir_virtmod);
    if(!virt->proc_remote) {
        ret = -ENOMEM;
        goto error_dir_remote;
    }

    virt->proc_remote_nodes = create_proc_entry("nodes", 644, virt->proc_remote);
    if(!virt->proc_remote_nodes) {
        ret = -ENOMEM;
        goto error_file_remote_nodes;
    }

    virt->proc_remote_nodes->proc_fops = &ct_remote_nodes_fops;
    virt->proc_remote_nodes->data = virt;

    virt->proc_remote_links = create_proc_entry("links", 644, virt->proc_remote);
    if(!virt->proc_remote_links) {
        ret = -ENOMEM;
        goto error_file_remote_links;
    }
    
    virt->proc_remote_links->proc_fops = &ct_remote_links_fops;
    virt->proc_remote_links->data = virt;

    virt->proc_remote_vroutes = create_proc_entry("vroutes", 644, virt->proc_remote);
    if(!virt->proc_remote_vroutes) {
        ret = -ENOMEM;
        goto error_file_vroutes;
    }

    virt->proc_remote_vroutes->data       = virt;
    virt->proc_remote_vroutes->read_proc  = proc_read_vroutes;
    virt->proc_remote_vroutes->write_proc = 0;

    virt->proc_reorder_stats = create_proc_entry("reorder", 644, virt->proc_remote);
    if(!virt->proc_reorder_stats) {
        ret = -ENOMEM;
        goto error_file_reorder_stats;
    }
    
    virt->proc_reorder_stats->proc_fops = &ct_reorder_stats_fops;
    virt->proc_reorder_stats->data = virt;

    return ret;

error_file_reorder_stats:
    REMOVE_PROC_ENTRY("vroutes", virt->proc_remote, virt->proc_remote_vroutes);
error_file_vroutes:
    REMOVE_PROC_ENTRY("links", virt->proc_remote, virt->proc_remote_nodes);
error_file_remote_links:
    REMOVE_PROC_ENTRY("nodes", virt->proc_remote, virt->proc_remote_links);
error_file_remote_nodes:
    REMOVE_PROC_ENTRY("remote", proc_dir_virtmod, virt->proc_remote);
error_dir_remote:
    return ret;
}

static int proc_read_vroutes(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    struct virt_priv *virt = (struct virt_priv *)data;
    struct vroute *vroute;

    int written = 0;
    int space = count;
    int len;

    len = snprintf(page, space, "destination\tnetmask\tgateway\n");
    if(unlikely(len > space)) {
        written += space;
        goto done;
    }

    written += len;
    space   -= len;

    list_for_each_entry(vroute, &virt->vroute_table, vroute_list) {
        int len = snprintf(page + written, space,
                "%x\t%x\t%x\n", vroute->dest, vroute->netmask, vroute->node_ip);

        if(unlikely(len > space)) {
            written += space;
            goto done;
        }
        
        written += len;
        space   -= len;
    }

done:
    *eof = 1;
    return written;
}

static int ct_mem_stats_open(struct inode *inode, struct file *file)
{
    struct virt_priv *virt = PROC_I(inode)->pde->data;
    int result;

    result = single_open(file, dump_mem_stats, virt);
    if(result < 0)
        return result;

    return 0;
}

static const struct file_operations ct_mem_stats_fops = {
    .owner   = THIS_MODULE,
    .open    = ct_mem_stats_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

/*
 * Set up a proc file for reading the memory stats.
 */
static int setup_mem_stats(struct virt_priv *virt) {
    virt->proc_mem_stats = create_proc_entry("mem_stats", 444, proc_dir_virtmod);
    if(!virt->proc_mem_stats) {
        return -ENOMEM;
    }

    virt->proc_mem_stats->proc_fops = &ct_mem_stats_fops;
    virt->proc_mem_stats->data = virt;

    return 0;
}

