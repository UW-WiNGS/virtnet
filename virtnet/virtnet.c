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
#include <stdlib.h>

#include "ftable.h"
#include "slaves.h"
#include "remote.h"
#include "paths.h"
#include "routes.h"

struct command {
    const char *name;
    int (*run)(const char *device, int argc, char *argv[]);
};

struct table {
    const char *name;
    int (*help)(const char *device, int argc, char *argv[]);
    const struct command *commands;
};

const struct command FTABLE_COMMANDS[] = {
    { "help", ftable_help },
    { "list", ftable_list },
    { NULL, NULL },
};

const struct command SLAVES_COMMANDS[] = {
    { "help", slaves_help },
    { "list", slaves_list },
    { "add", slaves_add },
    { "remove", slaves_remove },
    { "setgw", slaves_setgw },
    { NULL, NULL },
};

const struct command REMOTE_COMMANDS[] = {
    { "help", remote_help },
    { "nodes", remote_nodes },
    { "links", remote_links },
    { NULL, NULL },
};

const struct command PATHS_COMMANDS[] = {
    { "help", paths_help },
    { "list", paths_list },
    { "xor",  paths_xor },
    { NULL, NULL },
};

const struct command ROUTES_COMMANDS[] = {
    { "help", routes_help },
    { "list", routes_list },
    { "add", routes_add },
    { "remove", routes_remove },
    { NULL, NULL },
};

const struct table TABLES[] = {
    { "ftable", ftable_help, FTABLE_COMMANDS },
    { "slaves", slaves_help, SLAVES_COMMANDS },
    { "remote", remote_help, REMOTE_COMMANDS },
    { "paths",  paths_help,  PATHS_COMMANDS },
    { "routes",  routes_help,  ROUTES_COMMANDS },
    { NULL, NULL, NULL },
};

void print_usage(const char* cmd)
{
    printf("Usage: %s device TABLE { COMMAND | help }\n", cmd);
    printf("where  TABLE := { ftable | slaves | remote| paths }\n");
    printf("       COMMAND := { list }\n");
}

int main(int argc, char* argv[])
{
    if(argc < 3) {
        print_usage(argv[0]);
        exit(1);
    }

    const char *device = argv[1];

    const struct table *table = TABLES;
    while(table->name) {
        if(strcasecmp(table->name, argv[2]) == 0) {
            if(argc >= 4) {
                const struct command *command = table->commands;
                while(command->name) {
                    if(strcasecmp(command->name, argv[3]) == 0)
                        return command->run(device, argc - 3, &argv[3]);
                    command++;
                }

                printf("Command %s not valid for table %s.\n", argv[3], argv[2]);
                print_usage(argv[0]);
                return 1;
            } else {
                table->help(device, argc - 2, &argv[2]);
                return 1;
            }
        }

        table++;
    }

    printf("Table %s not valid.\n", argv[2]);
    print_usage(argv[0]);
    return 1;
}

