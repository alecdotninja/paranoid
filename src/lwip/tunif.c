/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

/*
 * This file is a skeleton for developing Ethernet network interface
 * drivers for lwIP. Add code to the low_level functions and do a
 * search-and-replace for the word "tunif" to replace it with
 * something that better describes your network interface.
 */

#include <lwip/prot/etharp.h>
#include <lwip/igmp.h>
#include <fcntl.h>
#include "lwip/snmp.h"

struct tunif {
    struct eth_addr *ethaddr;
    int fd;
};

static void tunif_input(struct netif *netif) {
    struct tunif *tunif = netif->state;

    char buffer[BUFSIZ];
    ssize_t length;

    if((length = read(tunif->fd, buffer, sizeof(buffer))) > 0) {
        struct pbuf *packet = pbuf_alloc(PBUF_RAW, (u16_t)length, PBUF_POOL);

        if (packet != NULL) {
            size_t offset = 0;

            for (struct pbuf *part = packet; part != NULL; part = part->next) {
                memcpy(part->payload, buffer + offset, part->len);
                offset += part->len;
            }

            MIB2_STATS_NETIF_ADD(netif, ifinoctets, packet->tot_len);

            if (((u8_t *) packet->payload)[0] & 1) {
                /* broadcast or multicast packet*/
                MIB2_STATS_NETIF_INC(netif, ifinnucastpkts);
            } else {
                /* unicast packet*/
                MIB2_STATS_NETIF_INC(netif, ifinucastpkts);
            }

            LINK_STATS_INC(link.recv);

            if (netif->input(packet, netif) != ERR_OK) {
                LWIP_DEBUGF(NETIF_DEBUG, ("tunif_input: IP input error\n"));
            }

            pbuf_free(packet);
        }else{
            LINK_STATS_INC(link.memerr);
            LINK_STATS_INC(link.drop);
            MIB2_STATS_NETIF_INC(netif, ifindiscards);
        }
    }
}

static err_t tunif_output(struct netif *netif, struct pbuf *packet, const ip_addr_t *ipaddr) {
    struct tunif *tunif = netif->state;

    for (struct pbuf *part = packet; part != NULL; part = part->next) {
        if (write(tunif->fd, part->payload, part->len) >= 0) {
            LINK_STATS_INC(link.xmit);
        }else{
            LINK_STATS_INC(link.drop);
        }
    }

    return ERR_OK;
}

err_t tunif_init(struct netif *netif) {
    struct tunif *tunif = netif->state;

    LWIP_ASSERT("netif != NULL", (netif != NULL));
    LWIP_ASSERT("tunif != NULL", (tunif != NULL));

    if(fcntl(tunif->fd, F_SETFL, O_NONBLOCK) < 0) {
        return ERR_CLSD;
    }

    MIB2_INIT_NETIF(netif, snmp_ifType_other, 0);

    netif->state = tunif;
    netif->name[0] = 't';
    netif->name[1] = 'n';
    netif->mtu = 1360;
    netif->flags = NETIF_FLAG_LINK_UP;
    netif->output = tunif_output;

    return ERR_OK;
}
