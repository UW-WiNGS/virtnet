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

const char *FTABLE_FILE = "/proc/virtmod/ftable";

int ftable_help(const char *device, int argc, char *argv[])
{
    printf("Access the flow table.\n");
    printf("Commands supported: list\n");
    return 0;
}

int ftable_list(const char *device, int argc, char *argv[])
{
    FILE *file = fopen(FTABLE_FILE, "r");
    if(!file) {
        printf("Could not open %s.\n", FTABLE_FILE);
        return 1;
    }

    char buffer[256];
    fgets(buffer, sizeof(buffer), file);

    unsigned source;
    unsigned dest;
    unsigned prot;
    unsigned spt;
    unsigned dpt;
    unsigned action;
    char linksel[16];
    char txdev[16];
    char rxdev[16];
    unsigned rxpkts;
    unsigned txpkts;
    unsigned rxbytes;
    unsigned txbytes;
    unsigned lastpkt;
    unsigned refcnt;
    const int num_columns = 15;

    //      xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx xxxxx xxxxx xxxxx xxxxxxxxxxxxxxx xxxxxxxxxxxxxxx xxxxxxxxxxxxxxx xxxxxx xxxxxx xxxxxxxx xxxxxxxx
    printf("source          destination     proto sport dport linkselect      txdevice        rxdevice        rxpkts txpkts rxbytes  txbytes \n");

    while(!feof(file)) {
        int rtn = fscanf(file, "%x %x %x %x %x %x %15s %15s %15s %u %u %u %u %u %u",
                &source, &dest, &prot, &spt, &dpt, &action, linksel, txdev, rxdev,
                &rxpkts, &txpkts, &rxbytes, &txbytes, &lastpkt, &refcnt);
        if(rtn == num_columns) {
            char source_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &source, source_str, sizeof(source_str));

            char dest_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &dest, dest_str, sizeof(dest_str));

            char prot_str[8];
            switch(prot) {
                case IPPROTO_TCP:
                    strncpy(prot_str, "TCP", sizeof(prot_str));
                    break;
                case IPPROTO_UDP:
                    strncpy(prot_str, "UDP", sizeof(prot_str));
                    break;
                case IPPROTO_ICMP:
                    strncpy(prot_str, "ICMP", sizeof(prot_str));
                    break;
                default:
                    snprintf(prot_str, sizeof(prot_str), "%hu", ntohs(prot));
                    break;
            }

            spt = ntohs(spt);
            dpt = ntohs(dpt);

            printf("%-15s %-15s %-5s %-5hu %-5hu %-15s %-15s %-15s %-6u %-6u %-8u %-8u\n",
                    source_str, dest_str, prot_str, spt, dpt, linksel, 
                    txdev, rxdev, rxpkts, txpkts, rxbytes, txbytes);
        } else if(rtn >= 0) {
            printf("Error parsing %s.\n", FTABLE_FILE);
            fclose(file);
            return 1;
        } else {
            break;
        }
    }

    fclose(file);

    return 0;
}
