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

#ifndef _VIRT_DEBUG_H__
#define _VIRT_DEBUG_H__


//#define DBG
#define ERR

#ifdef DBG
//#define VIRT_DBG(fmt, args...) printk(KERN_DEBUG "virt: %s:%s:%d " fmt, __FILE__, __func__, __LINE__, ##args)
#define VIRT_DBG(fmt, args...) printk(KERN_ALERT "virt: %s: " fmt, __func__, ##args)
#else
#define VIRT_DBG(fmt, args...)
#endif

#ifdef ERR
#define VIRT_ERR(fmt, args...) printk(KERN_ERR "virt: " fmt, ##args)
#else
#define VIRT_ERR(fmt, args...) 
#endif

#ifdef INFO
#define VIRT_INFO(fmt, args...) printk(KERN_INFO "virt: " fmt, ##args)
#else
#define VIRT_INFO(fmt, args...) 
#endif


#define PFX "virt: "

// take from drivers/net/e1000/e1000.h
#define DPRINTK(nlevel, klevel, fmt, args...)               \
do {                                    \
    if (NETIF_MSG_##nlevel & adapter->msg_enable)           \
        printk(KERN_##klevel PFX "%s: %s: " fmt,        \
               adapter->netdev->name, __func__, ##args);    \
} while (0)


#endif //_VIRT_DEBUG_H__
