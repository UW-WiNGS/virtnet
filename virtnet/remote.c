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

const char *REMOTE_NODES_FILE = "/proc/virtmod/remote/nodes";
const char *REMOTE_LINKS_FILE = "/proc/virtmod/remote/links";

int remote_help(const char *device, int argc, char *argv[])
{
    printf("Access the remote node and link lists.\n");
    printf("Commands supported: <nodes | links> <list | add | remove>\n");
    return 0;
}

int remote_nodes_list(const char *device, int argc, char *argv[])
{
    FILE *file = fopen(REMOTE_NODES_FILE, "r");
    if(!file) {
        printf("Could not open %s.\n", REMOTE_NODES_FILE);
        return 1;
    }

    /* Skip the header line. */
    char buffer[256];
    fgets(buffer, sizeof(buffer), file);

    //      xxx.xxx.xxx.xxx xxxxx xxxxx xxxxxxx xxxxxxx xxxxxx
    printf("private_addr    links mxpri txqueue qlimit  refcnt\n");

    while(!feof(file)) {
        unsigned privaddr;
        int links;
        int mpri;
        int txqueue;
        int qlimit;
        int refcnt;
        const int num_columns = 6;

        int rtn = fscanf(file, "%x %d %d %d %d %d",
                &privaddr, &links, &mpri,
                &txqueue, &qlimit, &refcnt);
        if(rtn == num_columns) {
            char privaddr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &privaddr, privaddr_str, sizeof(privaddr_str));

            //      xxx.xxx.xxx.xxx xxxxx xxxxx xxxxxxx xxxxxxx xxxxxx
            printf("%-15s %-5d %-5d %-7d %-7d %-6d\n",
                    privaddr_str, links, mpri,
                    txqueue, qlimit, refcnt);
        } else if(rtn >= 0) {
            printf("Error parsing %s.\n", REMOTE_NODES_FILE);
            fclose(file);
            return 1;
        } else {
            break;
        }
    }

    return 0;
}

int remote_nodes_add(const char *device, int argc, char *argv[])
{
    if(argc < 2) {
        printf("Usage: %s <private address>\n", argv[0]);
        return 1;
    }

    struct virt_conf_message msg;
    msg.op = VIRT_CONF_ADD_REMOTE_NODE;

    struct virt_conf_remote_node *node = &msg.msg.remote_node;
    inet_pton(AF_INET, argv[1], &node->priv_ip);

    if(virt_conf_ioctl(device, &msg) != 0) {
        printf("ioctl call failed\n");
        return 1;
    }

    return 0;
}

int remote_nodes_remove(const char *device, int argc, char *argv[])
{
    if(argc < 2) {
        printf("Usage: %s <private address>\n", argv[0]);
        return 1;
    }

    struct virt_conf_message msg;
    msg.op = VIRT_CONF_DEL_REMOTE_NODE;

    struct virt_conf_remote_node *node = &msg.msg.remote_node;
    inet_pton(AF_INET, argv[1], &node->priv_ip);

    if(virt_conf_ioctl(device, &msg) != 0) {
        printf("ioctl call failed\n");
        return 1;
    }

    return 0;
}

int remote_nodes(const char *device, int argc, char *argv[])
{
    if(argc < 1) {
        remote_help(device, argc, argv);
        return 1;
    }

    if(strcmp(argv[1], "list") == 0) {
        return remote_nodes_list(device, argc - 1, argv + 1);
    } else if(strcmp(argv[1], "add") == 0) {
        return remote_nodes_add(device, argc - 1, argv + 1);
    } else if(strcmp(argv[1], "remove") == 0) {
        return remote_nodes_remove(device, argc - 1, argv + 1);
    } else {
        remote_help(device, argc, argv);
        return 1;
    }
}

int remote_links_list(const char *device, int argc, char *argv[])
{
    FILE *file = fopen(REMOTE_LINKS_FILE, "r");
    if(!file) {
        printf("Could not open %s.\n", REMOTE_LINKS_FILE);
        return 1;
    }

    /* Skip the header line. */
    char buffer[256];
    fgets(buffer, sizeof(buffer), file);

    //      xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx xxxxx xxxxx xxxxx xxxxxxx xxxxxxxxxx xxxxx xxxxxx
    printf("private_addr    public_addr     port  flags prio  flows   bandwidth  paths refcnt\n");

    while(!feof(file)) {
        unsigned privaddr;
        unsigned pubaddr;
        int port;
        int flags;
        int prio;
        int flows;
        long long bandwidth;
        int paths;
        int refcnt;
        const int num_columns = 9;

        int rtn = fscanf(file, "%x %x %x %x %d %d %lld %d %d",
                &privaddr, &pubaddr, &port,
                &flags, &prio, &flows,
                &bandwidth, &paths, &refcnt);
        if(rtn == num_columns) {
            char privaddr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &privaddr, privaddr_str, sizeof(privaddr_str));
            
            char pubaddr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &pubaddr, pubaddr_str, sizeof(pubaddr_str));

    //      xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx xxxxx xxxxx xxxxx xxxxxxx xxxxxxxxxx xxxxx xxxxxx
            printf("%-15s %-15s %-5u %05x %-5d %-7d %-10lld %-5d %-6d\n",
                    privaddr_str, pubaddr_str, ntohs(port),
                    flags, prio, flows,
                    bandwidth, paths, refcnt);
        } else if(rtn >= 0) {
            printf("Error parsing %s.\n", REMOTE_LINKS_FILE);
            fclose(file);
            return 1;
        } else {
            break;
        }
    }

    return 0;
}

int remote_links_add(const char *device, int argc, char *argv[])
{
    if(argc < 4) {
        printf("Usage: %s <private address> <public address> <port>\n", argv[0]);
        return 1;
    }

    struct virt_conf_message msg;
    msg.op = VIRT_CONF_ADD_REMOTE_LINK;

    struct virt_conf_remote_link *link = &msg.msg.remote_link;
    inet_pton(AF_INET, argv[1], &link->priv_ip);
    inet_pton(AF_INET, argv[2], &link->pub_ip);
    link->data_port = htons(atoi(argv[3]));

    if(virt_conf_ioctl(device, &msg) != 0) {
        printf("ioctl call failed\n");
        return 1;
    }

    return 0;
}

int remote_links_remove(const char *device, int argc, char *argv[])
{
    if(argc < 4) {
        printf("Usage: %s <private address> <public address> <port>\n", argv[0]);
        return 1;
    }

    struct virt_conf_message msg;
    msg.op = VIRT_CONF_DEL_REMOTE_LINK;

    struct virt_conf_remote_link *link = &msg.msg.remote_link;
    inet_pton(AF_INET, argv[1], &link->priv_ip);
    inet_pton(AF_INET, argv[2], &link->pub_ip);
    link->data_port = htons(atoi(argv[3]));

    if(virt_conf_ioctl(device, &msg) != 0) {
        printf("ioctl call failed\n");
        return 1;
    }

    return 0;
}

int remote_links(const char *device, int argc, char *argv[])
{
    if(argc < 1) {
        remote_help(device, argc, argv);
        return 1;
    }

    if(strcmp(argv[1], "list") == 0) {
        return remote_links_list(device, argc - 1, argv + 1);
    } else if(strcmp(argv[1], "add") == 0) {
        return remote_links_add(device, argc - 1, argv + 1);
    } else if(strcmp(argv[1], "remove") == 0) {
        return remote_links_remove(device, argc - 1, argv + 1);
    } else {
        remote_help(device, argc, argv);
        return 1;
    }
}


