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
#include <linux/time.h>

#include "virtStats.h"
#include "virtDebug.h"



/* ------------------------ globals --------------------------- */
int __use_timing = 0;
s64 __timing_array[TIMING_NUM_ELEMENTS];
//int __timing_rx_packets = 0;
//int __timing_tx_packets = 0;


/* ----------------------- prototypes -------------------------- */



/* ------------------------ functions ------------------------- */


int set_timing(int value)
{
    if( (__use_timing == 0) && (value == 1) ) {
        //__timing_rx_packets = 0;
        //__timing_tx_packets = 0;
        memset(__timing_array, 0, sizeof(__timing_array));
    }

    if( (value == 1) || (value == 0) ) {
        __use_timing = value;
    }

    return 0;
}

int use_timing(void)
{
    return __use_timing;
}


s64 *get_timing_array(void)
{
    /*VIRT_DBG("lookup: %lld mangle: %lld done: %lld packets: %lld lookup: %lld mangle: %lld done: %lld packets: %lld\n", 
        __timing_array[TIMING_TX_LOOKUP],
        __timing_array[TIMING_TX_MANGLE],
        __timing_array[TIMING_TX_END],
        __timing_array[TIMING_TX_PACKETS],
        __timing_array[TIMING_RX_LOOKUP],
        __timing_array[TIMING_RX_MANGLE],
        __timing_array[TIMING_RX_END],
        __timing_array[TIMING_RX_PACKETS]);*/
    return __timing_array;
}

// TODO: print values to proc file
int log_timing(int type)
{
    s64 ns_time, ns_diff;
    struct timeval current_time;

    //static inline s64 timeval_to_ns(const struct timeval *tv)
    //extern void do_gettimeofday(struct timeval *tv);

    do_gettimeofday(&current_time);
    ns_time = timeval_to_ns(&current_time);
    if( (type != TIMING_TX_START) && (type != TIMING_RX_START) ) {

        if( type <= ((TIMING_NUM_ELEMENTS - 1)/2) ) 
            ns_diff = ns_time - __timing_array[TIMING_TX_START];
        else 
            ns_diff = ns_time - __timing_array[TIMING_RX_START];

        __timing_array[type] += ns_diff;
    } else {
        __timing_array[type] = ns_time;

        if( type == TIMING_TX_START )
            __timing_array[TIMING_TX_PACKETS] += 1;
        else if( type == TIMING_RX_START )
            __timing_array[TIMING_RX_PACKETS] += 1;
    }

    return 0;
}

