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

#ifndef _VIRT_POLICY_TYPES_H__
#define _VIRT_POLICY_TYPES_H__

#define MAX_ALG_NAME_LEN   16

// actions
#define POLICY_ACT_PASS    0x0001
#define POLICY_ACT_NAT     0x0002
#define POLICY_ACT_ENCAP   0x0003
#define POLICY_ACT_DECAP   0x0004
#define POLICY_ACT_DROP    0x0005
#define POLICY_ACT_LISP    0x0006
#define POLICY_ACT_MASK    0x000F

// operation policies
#define POLICY_OP_COMPRESS      0x0010
#define POLICY_OP_ENCRYPT       0x0020
#define POLICY_OP_DEJITTER      0x0040
#define POLICY_OP_ACCEL         0x0080
#define POLICY_OP_DUPLICATE     0x0100
#define POLICY_OP_LIMIT         0x0200
#define POLICY_OP_CODING        0x0400
#define POLICY_OP_MULTIPATH     0x0800
#define POLICY_OP_RETX          0x1000
#define POLICY_OP_MASK          0x1FF0

#define POLICY_TBL_INPUT   0x01
#define POLICY_TBL_OUTPUT  0x02
#define POLICY_TBL_MASK    0x03

#define POLICY_ROW_NONE    -1

#define POLICY_ACTION(x)   ((__u32)(x & 0x000F))
#define POLICY_OPS(x)      ((__u32)(x & 0x1FF0))

enum policy_command {
    POLICY_CMD_APPEND,
    POLICY_CMD_DELETE,
    POLICY_CMD_INSERT,
    POLICY_CMD_REPLACE,
    POLICY_CMD_FLUSH,  // flush a specific table
    POLICY_CMD_MAX,
};

enum policy_type {
    POLICY_TYPE_DEFAULT,
    POLICY_TYPE_FLOW,
    POLICY_TYPE_DEV,
    POLICY_TYPE_APP,
    POLICY_TYPE_MAX,
};

#endif //_VIRT_POLICY_TYPES_H__
