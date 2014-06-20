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
#include <linux/if.h>
#include <sys/ioctl.h>

#include "ioctl.h"

const char *SLAVES_FILE = "/proc/virtmod/slaves/slave_list";

int slaves_help(const char *device, int argc, char *argv[])
{
    printf("Access the slave list.\n");
    printf("Commands supported: <list | add | remove | setgw>\n");
    printf("\n");
    printf("setgw sets the gateway IP address for an interface,\n");
    printf("which is necessary for Ethernet and WiFi devices\n");
    return 0;
}

int slaves_list(const char *device, int argc, char *argv[])
{
    FILE *file = fopen(SLAVES_FILE, "r");
    if(!file) {
        printf("Could not open %s.\n", SLAVES_FILE);
        return 1;
    }

    char dev[16];
    unsigned state;
    unsigned addr;
    char mac_addr[18];
    char next_hop[18];
    unsigned prio;
    unsigned flows;
    unsigned bandwidth;
    unsigned paths;
    const int num_columns = 9;

    //      xxxxxxxxxxxxxxx xxx.xxx.xxx.xxx xx.xx.xx.xx.xx.xx xx.xx.xx.xx.xx.xx xxx xxxxxx xxxxxxxxx
    printf("device          address         macaddr           nexthop           pri flows  predbw   \n");

    while(!feof(file)) {
        int rtn = fscanf(file, " %[a-zA-Z0-9]: %u 0x%x 0x%17s 0x%17s %u %u %u %u",
                dev, &state, &addr, mac_addr, next_hop, &prio, 
                &flows, &bandwidth, &paths);
        if(rtn == num_columns) {
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, addr_str, sizeof(addr_str));

            printf("%-15s %-15s %-17s %-17s %-3u %-6u %-9u\n",
                    dev, addr_str, mac_addr, next_hop,
                    prio, flows, bandwidth);
        } else if(rtn >= 0) {
            printf("Error parsing %s.\n", SLAVES_FILE);
            fclose(file);
            return 1;
        } else {
            break;
        }
    }

    fclose(file);

    return 0;
}

int slaves_add(const char *device, int argc, char *argv[])
{
    if(argc < 2) {
        printf("Usage: %s <device>\n", argv[0]);
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        perror("socket");
        return 1;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    strncpy(ifr.ifr_slave, argv[1], sizeof(ifr.ifr_slave));

    if(ioctl(sockfd, SIOCVIRTENSLAVE, &ifr) < 0) {
        perror("SIOCVIRTENSLAVE");
        close(sockfd);
        return 1;
    }

    close(sockfd);
    return 0;
}

int slaves_remove(const char *device, int argc, char *argv[])
{
    if(argc < 2) {
        printf("Usage: %s <device>\n", argv[0]);
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        perror("socket");
        return 1;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    strncpy(ifr.ifr_slave, argv[1], sizeof(ifr.ifr_slave));

    if(ioctl(sockfd, SIOCVIRTRELEASE, &ifr) < 0) {
        perror("SIOCVIRTRELEASE");
        close(sockfd);
        return 1;
    }

    close(sockfd);
    return 0;
}

int slaves_setgw(const char *device, int argc, char *argv[])
{
    if(argc < 3) {
        printf("Usage: %s <device> <gateway address>\n", argv[0]);
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        perror("socket");
        return 1;
    }

    struct gwaddr_req gwa_req;
    memset(&gwa_req, 0, sizeof(gwa_req));
    strncpy(gwa_req.ifname, argv[1], sizeof(gwa_req.ifname));
    gwa_req.family = AF_INET;
    inet_pton(AF_INET, argv[2], &gwa_req.gwaddr_ip4);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    ifr.ifr_data = &gwa_req;

    if(ioctl(sockfd, SIOCVIRTSETGWADDR, &ifr) < 0) {
        perror("SIOCVIRTSETGWADDR");
        close(sockfd);
        return 1;
    }

    close(sockfd);
    return 0;
}

