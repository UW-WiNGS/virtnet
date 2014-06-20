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

#include <linux/skbuff.h>
#include <linux/raid/xor.h>    /* Optimized XOR code */

#include "virtCoding.h"

/*
 * dest->len must be large enough to hold src->len or at least have enough
 * tailroom so that it can expand to hold src->len.
 */
int xor_sk_buff(struct sk_buff *dest, struct sk_buff *src, int offset)
{
    int bytes = src->len - offset;

#if 0
    void *dest_ptr = dest->data + offset;
    void *src_ptr = src->data + offset;
#endif

    unsigned char *dest_ptr = dest->data + offset;
    unsigned char *src_ptr = src->data + offset;
    int i;

    int diff = src->len - dest->len;
    if(diff > 0) {
        unsigned char *space;

        if(WARN_ON(skb_tailroom(dest) < diff))
            return 0;

        space = skb_put(dest, diff);
        memset(space, 0, diff);
    }

    for(i = 0; i < bytes; i++) {
        dest_ptr[i] ^= src_ptr[i];
    }

#if 0
    /* I would prefer to use this optimized XOR code, but I believe it assumes
     * that the data fit nicely into words. */
    xor_blocks(1, bytes, dest_ptr, &src_ptr);
#endif

    return bytes;
}

