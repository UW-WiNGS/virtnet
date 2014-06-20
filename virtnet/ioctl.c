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

#include <string.h>
#include <netdb.h>
#include <linux/if.h>
#include <sys/ioctl.h>

#include "ioctl.h"

int virt_conf_ioctl(const char *device, struct virt_conf_message *msg)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0)
        return -1;

    struct ifreq ifr;
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    ifr.ifr_data = msg;

    int result = ioctl(sockfd, SIOCVIRTCONF, &ifr);
    close(sockfd);

    return result;
}

