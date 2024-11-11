/*
 * Copyright (c) 2023 Institute of Parallel And Distributed Systems (IPADS), Shanghai Jiao Tong University (SJTU)
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "virtio.h"
#include "virtio-net.h"

struct ethr_hdr {
        uint8_t dmac[6];
        uint8_t smac[6];
        uint16_t ethr_type;
        uint16_t hwtype;
        uint16_t protype;
        uint8_t hwsize;
        uint8_t prosize;
        uint16_t opcode;
        uint8_t arp_smac[6];
        uint32_t sip;
        uint8_t arp_dmac[6];
        uint32_t dip;
} __attribute__((packed));

int hex_to_int(char ch)
{
        u32 i = 0;

        if (ch >= '0' && ch <= '9') {
                i = ch - '0';
        } else if (ch >= 'A' && ch <= 'F') {
                i = 10 + (ch - 'A');
        } else if (ch >= 'a' && ch <= 'f') {
                i = 10 + (ch - 'a');
        }

        return i;
}

void pack_mac(u8* dest, char* src)
{
        for (int i = 0, j = 0; i < 17; i += 3) {
                u32 i1 = hex_to_int(src[i]);
                u32 i2 = hex_to_int(src[i + 1]);
                dest[j++] = (i1 << 4) + i2;
        }
}

int atoi(const char* s)
{
        int n;

        n = 0;
        while ('0' <= *s && *s <= '9')
                n = n * 10 + *s++ - '0';
        return n;
}

uint32_t get_ip(char* ip, u32 len)
{
        u32 ipv4 = 0;
        char arr[4];
        int n1 = 0;

        u32 ip_vals[4];
        int n2 = 0;

        for (int i = 0; i < len; i++) {
                char ch = ip[i];
                if (ch == '.') {
                        arr[n1++] = '\0';
                        n1 = 0;
                        ip_vals[n2++] = atoi(arr);
                        // cprintf("Check ipval:%d , arr:%s",ip_vals[n2],arr);
                } else {
                        arr[n1++] = ch;
                }
        }

        arr[n1++] = '\0';
        n1 = 0;
        ip_vals[n2++] = atoi(arr);
        // cprintf("Final Check ipval:%d , arr:%s",ip_vals[n2],arr);

        //	ipv4 = (ip_vals[0]<<24) + (ip_vals[1]<<16) + (ip_vals[2]<<8) +
        // ip_vals[3];
        ipv4 = (ip_vals[3] << 24) + (ip_vals[2] << 16) + (ip_vals[1] << 8)
               + ip_vals[0];
        return ipv4;
}

uint16_t htons(uint16_t v)
{
        return (v >> 8) | (v << 8);
}
uint32_t htonl(uint32_t v)
{
        return htons(v >> 16) | (htons((uint16_t)v) << 16);
}

int create_eth_arp_frame(uint8_t* smac, char* ipAddr, struct ethr_hdr* eth)
{
        printf("Create ARP frame\n");
        char* dmac = "FF:FF:FF:FF:FF:FF";

        pack_mac(eth->dmac, dmac);
        memmove(eth->smac, smac, 6);

        // ether type = 0x0806 for ARP
        eth->ethr_type = htons(0x0806);

        /** ARP packet filling **/
        eth->hwtype = htons(1);
        eth->protype = htons(0x0800);

        eth->hwsize = 0x06;
        eth->prosize = 0x04;

        // arp request
        eth->opcode = htons(1);

        /** ARP packet internal data filling **/
        memmove(eth->arp_smac, smac, 6);
        pack_mac(eth->arp_dmac, dmac); // this can potentially be igored for the
                                       // request

        eth->sip = get_ip("192.168.1.1", strlen("192.168.1.1"));

        *(uint32_t*)(&eth->dip) = get_ip(ipAddr, strlen(ipAddr));

        return 0;
}

extern struct virtio_device* net_dev;
int arp_test(void* driver)
{
        struct virtio_device* device = net_dev;

        struct ethr_hdr* eth = calloc(1, sizeof *eth);
        create_eth_arp_frame(device->macaddr, "192.168.2.2", eth);
        for (int i = 0; i < sizeof(*eth); i++) {
                printf("%02x ", *((u8*)eth + i));
        }
        printf("\n");

        virtio_net_send(driver, (void*)eth, sizeof(*eth));
        return 0;
}