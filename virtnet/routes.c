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

const char *ROUTES_FILE = "/proc/virtmod/remote/vroutes";

int routes_help(const char *device, int argc, char *argv[])
{
    printf("Access the virtual routing table.\n");
    printf("Commands supported: list, add, remove.\n");
    return 0;
}

int routes_list(const char *device, int argc, char *argv[])
{
    FILE *file = fopen(ROUTES_FILE, "r");
    if(!file) {
        printf("Could not open %s.\n", ROUTES_FILE);
        return 1;
    }

    /* Skip the header line. */
    char buffer[256];
    fgets(buffer, sizeof(buffer), file);

    //      xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx
    printf("destination     netmask         gateway        \n");

    while(!feof(file)) {
        unsigned destination;
        unsigned netmask;
        unsigned gateway;
        const int num_columns = 3;

        int rtn = fscanf(file, "%x %x %x", &destination, &netmask, &gateway);
        if(rtn == num_columns) {
            char destination_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &destination, destination_str, sizeof(destination_str));

            char netmask_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &netmask, netmask_str, sizeof(netmask_str));

            char gateway_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &gateway, gateway_str, sizeof(gateway_str));

            printf("%-15s %-15s %-15s\n", 
                    destination_str, netmask_str, gateway_str);
        } else if(rtn >= 0) {
            printf("Error parsing %s.\n", ROUTES_FILE);
            fclose(file);
            return 1;
        } else {
            break;
        }
    }

    fclose(file);

    return 0;
}

int routes_add(const char *device, int argc, char *argv[])
{
    if(argc < 4) {
        printf("Usage: %s <destination> <netmask> <gateway>\n", argv[0]);
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        perror("socket");
        return 1;
    }

    struct vroute_req vroute_req;
    memset(&vroute_req, 0, sizeof(vroute_req));
    inet_pton(AF_INET, argv[1], &vroute_req.dest);
    inet_pton(AF_INET, argv[2], &vroute_req.netmask);
    inet_pton(AF_INET, argv[3], &vroute_req.node_ip);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    ifr.ifr_data = &vroute_req;

    if(ioctl(sockfd, SIOCVIRTADDVROUTE, &ifr) < 0) {
        perror("SIOCVIRTADDVROUTE");
        close(sockfd);
        return 1;
    }

    close(sockfd);
    return 0;
}

int routes_remove(const char *device, int argc, char *argv[])
{
    if(argc < 4) {
        printf("Usage: %s <destination> <netmask> <gateway>\n", argv[0]);
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        perror("socket");
        return 1;
    }

    struct vroute_req vroute_req;
    memset(&vroute_req, 0, sizeof(vroute_req));
    inet_pton(AF_INET, argv[1], &vroute_req.dest);
    inet_pton(AF_INET, argv[2], &vroute_req.netmask);
    inet_pton(AF_INET, argv[3], &vroute_req.node_ip);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    ifr.ifr_data = &vroute_req;

    if(ioctl(sockfd, SIOCVIRTDELVROUTE, &ifr) < 0) {
        perror("SIOCVIRTDELVROUTE");
        close(sockfd);
        return 1;
    }

    close(sockfd);
    return 0;
}

