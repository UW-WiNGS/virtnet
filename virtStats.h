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

#ifndef _VIRT_STATS_H__
#define _VIRT_STATS_H__

enum time_step {
    TIMING_TX_START=0,
    TIMING_TX_SETUP,
    TIMING_TX_PARSE,
    TIMING_TX_LOOKUP,
    TIMING_TX_MANGLE,
    TIMING_TX_END,
    TIMING_TX_PACKETS,
    TIMING_RX_START,
    TIMING_RX_SETUP,
    TIMING_RX_PARSE,
    TIMING_RX_LOOKUP,
    TIMING_RX_MANGLE,
    TIMING_RX_END,
    TIMING_RX_PACKETS,
    TIMING_NUM_ELEMENTS,
};


struct link_stats
{
    // stats from net_device_stats structure
    unsigned long rx_packets;
    unsigned long tx_packets;
    unsigned long rx_bytes;
    unsigned long tx_bytes;
    unsigned long rx_errors;
    unsigned long tx_errors;
    unsigned long rx_dropped;
    unsigned long tx_dropped;
    unsigned long rx_compressed;
    unsigned long tx_compressed;
    unsigned long collisions;
    unsigned long multicast;

    // custom link metric stats
    unsigned long rx_reorder;
    unsigned long tx_reorder;
    unsigned long rx_losses;
    unsigned long tx_losses;
    unsigned long rx_latency;
    unsigned long tx_latency;
    unsigned long rx_bandwidth;
    unsigned long tx_bandwidth;

    // current state variables
    unsigned long link_seq_no;

    // custom link monitoring stats
    unsigned long link_failures;
    unsigned long down_time;
};


// TODO: int log_timing(int type, pkt);
int use_timing(void);
int set_timing(int value);
int log_timing(int type);
s64 *get_timing_array(void);

// TODO: driver's get_stats function should be here and copy values master's priv->stats structure


#endif //_VIRT_STATS_H__
