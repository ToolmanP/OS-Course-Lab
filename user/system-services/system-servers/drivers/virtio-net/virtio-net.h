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

#pragma once
#include <pthread.h>
#include "pci.h"
#include "virtio.h"

#define FRAME_SIZE (1600)

struct virtio_net_hdr {
#define VIRTIO_NET_HDR_F_NEEDS_CSUM 1
        u8 flags;
#define VIRTIO_NET_HDR_GSO_NONE  0
#define VIRTIO_NET_HDR_GSO_TCPV4 1
#define VIRTIO_NET_HDR_GSO_UDP   3
#define VIRTIO_NET_HDR_GSO_TCPV6 4
        u8 gso_type;
        u16 hdr_len;
        u16 gso_size;
        u16 csum_start;
        u16 csum_offset;
        u16 num_buffers;
};

extern pthread_t virtio_server_thread_tid;
extern cap_t virtio_server_thread_cap;
extern struct virtio_device *net_dev;

void *virtio_ipc_server_routine(void *arg);
void virtio_net_send(struct virtio_device *dev, u8 *packet, u32 length);
void virtio_net_recv(struct virtio_device *dev, u8 *packet, u32 *length);
