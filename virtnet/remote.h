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

#ifndef REMOTE_H
#define REMOTE_H

int remote_help(const char *device, int argc, char *argv[]);

int remote_nodes_list(const char *device, int argc, char *argv[]);
int remote_nodes_add(const char *device, int argc, char *argv[]);
int remote_nodes_remove(const char *device, int argc, char *argv[]);
int remote_nodes(const char *device, int argc, char *argv[]);

int remote_links_list(const char *device, int argc, char *argv[]);
int remote_links_add(const char *device, int argc, char *argv[]);
int remote_links_remove(const char *device, int argc, char *argv[]);
int remote_links(const char *device, int argc, char *argv[]);

#endif /* REMOTE_H */
