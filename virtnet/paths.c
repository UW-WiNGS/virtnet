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

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "ioctl.h"

const char *PATHS_FILE = "/proc/virtmod/paths";

int paths_help(const char *device, int argc, char *argv[])
{
    printf("Access the path list.\n");
    printf("Commands supported: list, xor\n");
    return 0;
}

int paths_list(const char *device, int argc, char *argv[])
{
    FILE *file = fopen(PATHS_FILE, "r");
    if(!file) {
        printf("Could not open %s.\n", PATHS_FILE);
        return 1;
    }

    /* Skip the header line. */
    char buffer[256];
    fgets(buffer, sizeof(buffer), file);

    printf("                                                                                                                               coding         \n");
    printf("local_address   remote_address  lport rport state available  cwnd       min_cwnd   max_cwnd   srtt       rttvar     base_rtt   sa/hi/lo refcnt\n");

    while(!feof(file)) {
        unsigned local_addr;
        unsigned remote_addr;
        unsigned short local_port;
        unsigned short remote_port;
        unsigned state;
        unsigned available;
        unsigned cwnd;
        unsigned min_cwnd;
        unsigned max_cwnd;
        unsigned long srtt;
        unsigned long rttvar;
        unsigned long base_rtt;
        char coding[8];
        unsigned refcnt;
        const int num_columns = 14;

        int rtn = fscanf(file, "%x %x %hu %hu %u %u %u %u %u %lu %lu %lu %8c %u",
                &local_addr, &remote_addr, &local_port, &remote_port, 
                &state, &available,
                &cwnd, &min_cwnd, &max_cwnd, &srtt, &rttvar,
                &base_rtt, coding, &refcnt);
        if(rtn == num_columns) {
            char local_addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &local_addr, local_addr_str, sizeof(local_addr_str));
            
            char remote_addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &remote_addr, remote_addr_str, sizeof(remote_addr_str));

            const char *state_str;
            switch(state) {
                case 0:
                    state_str = "DEAD";
                    break;
                case 1:
                    state_str = "ACTIV";
                    break;
                case 2:
                    state_str = "ACT/W";
                    break;
                case 3:
                    state_str = "STALL";
                    break;
                default:
                    state_str = "UNKNO";
            }

            //      xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx xxxxx xxxxx xxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxx xx/xx/xx xxxxxx
            printf("%-15s %-15s %-5hu %-5hu %-5s %-10u %-10u %-10u %-10u %-10lu %-10lu %-10lu %8.8s %-6u\n",
                    local_addr_str,
                    remote_addr_str,
                    local_port,
                    remote_port,
                    state_str,
                    available,
                    cwnd,
                    min_cwnd,
                    max_cwnd,
                    srtt,
                    rttvar,
                    base_rtt,
                    coding,
                    refcnt);
        } else if(rtn >= 0) {
            printf("Error parsing %s.\n", PATHS_FILE);
            fclose(file);
            return 1;
        } else {
            break;
        }
    }

    return 0;
}

int paths_xor(const char *device, int argc, char *argv[])
{
    if(argc < 8) {
        printf("Usage: %s <local address> <remote address> <local port> <remote port> <same path> <same prio> <lower prio>\n", argv[0]);
        return 1;
    }

    struct virt_conf_message msg;
    msg.op = VIRT_CONF_SET_XOR_RATE2;

    struct virt_conf_xor_rate2 *xor = &msg.msg.xor_rate2;
    inet_pton(AF_INET, argv[1], &xor->local_addr);
    inet_pton(AF_INET, argv[2], &xor->remote_addr);
    xor->local_port = htons(atoi(argv[3]));
    xor->remote_port = htons(atoi(argv[4]));
    xor->same_path = atoi(argv[5]);
    xor->same_prio = atoi(argv[6]);
    xor->lower_prio = atoi(argv[7]);

    if(xor->same_path < 0 || xor->same_path > MAX_XOR_CODING_RATE) {
        printf("Valid range for coding rate is between 0 and %d\n", MAX_XOR_CODING_RATE);
        return 1;
    }

    if(xor->same_prio < 0 || xor->same_prio > MAX_XOR_CODING_RATE) {
        printf("Valid range for coding rate is between 0 and %d\n", MAX_XOR_CODING_RATE);
        return 1;
    }

    if(xor->lower_prio < 0 || xor->lower_prio > MAX_XOR_CODING_RATE) {
        printf("Valid range for coding rate is between 0 and %d\n", MAX_XOR_CODING_RATE);
        return 1;
    }

    if(virt_conf_ioctl(device, &msg) != 0) {
        printf("ioctl call failed\n");
        return 1;
    }

    return 0;
}

