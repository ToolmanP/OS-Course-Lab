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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <chcore/type.h>
#include <chcore/syscall.h>
#include <chcore/memory.h>
#include <chcore/bug.h>
#include <chcore/container/list.h>
#include <chcore/pthread.h>

#include "virtio.h"
#include "virtio-net.h"
#include "pci.h"

/*
 * Allocates a virtio device.
 */
struct virtio_device *alloc_virt_dev(struct pci_device *dev)
{
        struct virtio_device *vdev;
        cap_t cfg_pmo_cap;

        vdev = malloc(sizeof(struct virtio_device));
        BUG_ON(vdev == NULL);
        vdev->base = dev->membase;
        vdev->size = dev->reg_size[4];
        vdev->irq = dev->irq_line;
        vdev->iobase = dev->iobase;
        vdev->pci = dev;
        vdev->remap_base = chcore_alloc_vaddr(vdev->size);
        vdev->cfg = (struct virtio_pci_common_cfg *)vdev->remap_base;
        memcpy(vdev->macaddr, dev->mac, sizeof vdev->macaddr);

        printf("IO remap mem region %#08lx to %#08lx, size: %#04x\n",
               (u64)vdev->base,
               (u64)vdev->cfg,
               vdev->size);

        cfg_pmo_cap = usys_create_device_pmo(vdev->base, vdev->size);
        usys_map_pmo(SELF_CAP,
                     cfg_pmo_cap,
                     (u64)vdev->remap_base,
                     VM_READ | VM_WRITE);

        return vdev;
}

static void vp_reset(struct virtio_device *vdev)
{
        /* 0 status means a reset. */
        iowrite8(0, &vdev->cfg->device_status);
        /* After writing 0 to device_status, the driver MUST wait for a read of
         * device_status to return 0 before reinitializing the device.
         * This will flush out the status write, and flush in device writes,
         * including MSI-X interrupts, if any.
         */
        while (ioread8(&vdev->cfg->device_status))
                ;
}

static u64 vp_get_features(struct virtio_device *vdev)
{
        u64 features;

        iowrite32(0, &vdev->cfg->device_feature_select);
        features = ioread32(&vdev->cfg->device_feature);
        iowrite32(1, &vdev->cfg->device_feature_select);
        features |= ((u64)ioread32(&vdev->cfg->device_feature) << 32);

        return features;
}

static u8 vp_get_status(struct virtio_device *vdev)
{
        return ioread8(&vdev->cfg->device_status);
}

static void vp_set_status(struct virtio_device *vdev, u8 status)
{
        /* We should never be setting status to 0. */
        BUG_ON(status == 0);
        iowrite8(status, &vdev->cfg->device_status);
}

static void virtio_add_status(struct virtio_device *dev, unsigned int status)
{
        vp_set_status(dev, vp_get_status(dev) | status);
}

static inline void virtio_device_ready(struct virtio_device *dev)
{
        unsigned status = vp_get_status(dev);

        BUG_ON(status & VIRTIO_STATUS_DRIVER_OK);
        vp_set_status(dev, status | VIRTIO_STATUS_DRIVER_OK);
}

/*
 * Feature negotiation for a network device
 *
 * We are offloading checksuming to the device
 */
static void virtio_net_feature_negotiate(u32 *features)
{
        // do not use control queue
        DISABLE_FEATURE(*features, VIRTIO_NET_F_CTRL_VQ);

        DISABLE_FEATURE(*features, VIRTIO_NET_F_GUEST_TSO4);
        DISABLE_FEATURE(*features, VIRTIO_NET_F_GUEST_TSO6);
        DISABLE_FEATURE(*features, VIRTIO_NET_F_GUEST_UFO);
        DISABLE_FEATURE(*features, VIRTIO_NET_F_MRG_RXBUF);
        DISABLE_FEATURE(*features, VIRTIO_F_EVENT_IDX);

        // Only enable MAC if it is offered by the device
        if (*features & VIRTIO_NET_F_MAC) {
                printf("Enable VIRTIO_NET_F_MAC\n");
                ENABLE_FEATURE(*features, VIRTIO_NET_F_MAC);
        }

        if (*features & VIRTIO_NET_F_MQ) {
                printf("VIRTIO_NET_F_MQ enabled\n");
        }
}

int virtio_finalize_features(struct virtio_device *dev, u64 features)
{
        u8 status;

        printf("Final features: 0x%lx\n", features);
        if (!(features & (1ul << VIRTIO_F_VERSION_1))) {
                BUG("virtio: device uses modern interface "
                    "but does not have VIRTIO_F_VERSION_1\n");
        }

        iowrite32(0, &dev->cfg->driver_feature_select);
        iowrite32(features, &dev->cfg->driver_feature);
        iowrite32(1, &dev->cfg->driver_feature_select);
        iowrite32(features >> 32, &dev->cfg->driver_feature);

        virtio_add_status(dev, VIRTIO_STATUS_FEATURES_OK);
        status = vp_get_status(dev);
        if (!(status & VIRTIO_STATUS_FEATURES_OK)) {
                BUG("virtio: device refuses features\n");
        }

        return 0;
}

int setup_virtqueue(struct virtio_device *dev, u16 index)
{
        struct virt_queue *virtq;
        u16 num, off;
        void *queue;
        u64 vring_align = 64; // set to L1 cache line size
        struct chcore_dma_handle dma_handle;

        /* Select the queue we're interested in */
        iowrite16(index, &dev->cfg->queue_select);

        /* Check if queue is either not available or already active. */
        num = ioread16(&dev->cfg->queue_size);
        // size 0 implies the queue doesn't exist.
        if (!num || ioread16(&dev->cfg->queue_enable))
                BUG("Queue doesn't exist or is already enabled!\n");

        /* get offset of notification word for this vq */
        off = ioread16(&dev->cfg->queue_notify_off);
        printf("Queue: %d size: %d, notify_off:%d\n", index, num, off);

        /* Allocating DMA address for this queue */
        queue = chcore_alloc_dma_mem(vring_size(num, vring_align), &dma_handle);
        BUG_ON(!queue);
        printf("Allocate 0x%x bytes for virtqueue %d, [%p ~ %p]\n",
               vring_size(num, vring_align),
               index,
               queue,
               queue + vring_size(num, vring_align));

        // size 0 implies the queue doesn't exist.
        if (num == 0) {
                return -1;
        }

        virtq = &dev->queues[index];
        virtq->num = num;
        virtq->desc = queue;
        virtq->available =
                (struct virtq_avail *)((char *)queue
                                       + num * sizeof(struct virtq_desc));
        virtq->used = (void *)(((u64)&virtq->available->ring[num] + sizeof(u16)
                                + vring_align - 1)
                               & ~(vring_align - 1));
        virtq->desc_pa = dma_handle.paddr;
        virtq->available_pa =
                dma_handle.paddr + ((u64)virtq->available - (u64)virtq->desc);
        virtq->used_pa =
                dma_handle.paddr + ((u64)virtq->used - (u64)virtq->desc);

        virtq->queue_size = num;
        virtq->free = malloc(num);
        BUG_ON(virtq->free == NULL);
        memset(virtq->free, 1, num);
        virtq->last_used_idx = 0;
        /* We use polling mode instead of interrupt */
        virtq->available->flags |= VIRTQ_AVAIL_F_NO_INTERRUPT;
        /* Pre-allocate a packet buffer for transmis */
        virtq->packet_buffer = chcore_alloc_dma_mem(PAGE_SIZE, &dma_handle);
        virtq->packet_buffer_pa = dma_handle.paddr;
        printf("Get a packet buffer with vaddr: %p, paddr: %#lx\n",
               virtq->packet_buffer,
               virtq->packet_buffer_pa);

        /* activate the queue */
        iowrite16(num, &dev->cfg->queue_size);
        iowrite64_twopart(virtq->desc_pa,
                          &dev->cfg->queue_desc_lo,
                          &dev->cfg->queue_desc_hi);
        iowrite64_twopart(virtq->available_pa,
                          &dev->cfg->queue_avail_lo,
                          &dev->cfg->queue_avail_hi);
        iowrite64_twopart(virtq->used_pa,
                          &dev->cfg->queue_used_lo,
                          &dev->cfg->queue_used_hi);

        // // The multiplier is after the cap structure, which is 16 bytes long.
        // notify_off_multiplier =
        //         confread32(dev->pci,
        //                    cap_pointer
        //                            + offsetof(struct virtio_pci_notify_cap,
        //                                       notify_off_multiplier));
        // virtq->notify_addr = phys_to_virt(notify_base + off *
        // notify_off_multiplier);
        virtq->notify_addr = (vaddr_t)dev->remap_base + 0x3000 + index * 4;

        printf("descriptors: %p available: %p used: %p, notify_addr: %#08lx\n",
               virtq->desc,
               virtq->available,
               virtq->used,
               virtq->notify_addr);

        /* Activate */
        iowrite16(1, &dev->cfg->queue_enable);
        return 0;
}

void virtio_device_init(struct virtio_device *dev)
{
        u8 status;
        u64 features;

        status = ioread8(&dev->cfg->device_status);
        printf("device_status: 0x%x\n", status);

        /* First reset the device */
        vp_reset(dev);

        /* Acknowledge that we've seen the device. */
        virtio_add_status(dev, VIRTIO_STATUS_ACKNOWLEDGE);

        /* We have a driver! */
        virtio_add_status(dev, VIRTIO_STATUS_DRIVER);

        features = vp_get_features(dev);

        printf("Supported queue num: %d\n", ioread16(&dev->cfg->num_queues));
        printf("Before negotiate, device feature: 0x%lx\n", features);
        virtio_net_feature_negotiate((u32 *)&features);

        // finalize features
        printf("Before negotiate, device feature: 0x%lx\n", features);
        virtio_finalize_features(dev, features);

        /*  Just one queue pair, no control queue */
        for (int i = 0; i < 2; i++) {
                setup_virtqueue(dev, i);
        }

        virtio_device_ready(dev);

        printf("Device config done, status: %x\n",
               ioread8(&dev->cfg->device_status));
}

/* Find a free descriptor, mark it non-free, return its index. */
static int alloc_desc(struct virt_queue *vq)
{
        for (int i = 0; i < vq->num; i++) {
                if (vq->free[i]) {
                        vq->free[i] = 0;
                        return i;
                }
        }
        return -1;
}

/* Mark a descriptor as free. */
static void free_desc(int i, struct virt_queue *vq)
{
        if (i >= vq->num)
                BUG("free_desc 1");
        if (vq->free[i])
                BUG("free_desc 2");

        vq->desc[i].addr = 0;
        vq->desc[i].len = 0;
        vq->desc[i].len = 0;
        vq->desc[i].flags = 0;
        vq->desc[i].next = 0;
        vq->free[i] = 1;
}

/* Free a chain of descriptors. */
static void free_chain(int i, struct virt_queue *vq)
{
        while (1) {
                int flag = vq->desc[i].flags;
                int nxt = vq->desc[i].next;
                free_desc(i, vq);
                if (flag & VIRTQ_DESC_F_NEXT)
                        i = nxt;
                else
                        break;
        }
}

// allocate three descriptors (they need not be contiguous).
// disk transfers always use three descriptors.
static int alloc3_desc(int *idx, struct virt_queue *vq)
{
        for (int i = 0; i < 3; i++) {
                idx[i] = alloc_desc(vq);
                if (idx[i] < 0) {
                        for (int j = 0; j < i; j++)
                                free_desc(idx[j], vq);
                        return -1;
                }
        }
        return 0;
}

/*
 * Notify the device by writing to an offest within the ISR CAP Bar.
 *
 * From Virtio Spec 1.0 4.1.4.4 Notification structure layout
 */
void notify_queue(struct virtio_device *dev, u16 queue)
{
        struct virt_queue *vq = &dev->queues[queue];
        u32 *addr;

        /* write the queue index to the address within the bar to notify the
         * device. */
        addr = (u32 *)vq->notify_addr;
        *addr = queue;
}

void virtio_net_send(struct virtio_device *dev, u8 *packet, u32 length)
{
        struct virt_queue *tx_queue = &dev->queues[VIRTIO_NET_TX_QUEUE_INDEX];
        struct virtio_net_hdr *header;
        int idx[3];
        int desc_id;
        u8 *complete_status;

        while (1) {
                if (alloc3_desc(idx, tx_queue) == 0) {
                        break;
                }
        }

        header = (struct virtio_net_hdr *)tx_queue->packet_buffer;
        header->flags = 0;
        header->gso_type = VIRTIO_NET_HDR_GSO_NONE;
        header->csum_start = 0;
        header->csum_offset = 0;
        header->hdr_len = 0;

        // printf("allocate index: %d %d %d\n", idx[0], idx[1], idx[2]);
        tx_queue->desc[idx[0]].addr = tx_queue->packet_buffer_pa;
        tx_queue->desc[idx[0]].len = sizeof(struct virtio_net_hdr);
        tx_queue->desc[idx[0]].flags = VIRTQ_DESC_F_NEXT;
        tx_queue->desc[idx[0]].next = idx[1];

        memcpy(tx_queue->packet_buffer + sizeof(struct virtio_net_hdr),
               packet,
               length);
        tx_queue->desc[idx[1]].addr =
                tx_queue->packet_buffer_pa + sizeof(struct virtio_net_hdr);
        tx_queue->desc[idx[1]].len = length;
        tx_queue->desc[idx[1]].flags = VIRTQ_DESC_F_NEXT;
        tx_queue->desc[idx[1]].next = idx[2];

        complete_status = tx_queue->packet_buffer
                          + sizeof(struct virtio_net_hdr) + length;
        *complete_status = 0;
        tx_queue->desc[idx[2]].addr = tx_queue->packet_buffer_pa
                                      + sizeof(struct virtio_net_hdr) + length;
        tx_queue->desc[idx[2]].len = 1;
        tx_queue->desc[idx[2]].flags = VIRTQ_DESC_F_WRITE;
        tx_queue->desc[idx[2]].next = 0;

        mb();
        tx_queue->available->ring[tx_queue->available->idx % tx_queue->num] =
                idx[0];
        mb();
        // tell the device another avail ring entry is available.
        tx_queue->available->idx += 1;
        mb();

        notify_queue(dev, VIRTIO_NET_TX_QUEUE_INDEX);
        mb();

        while (tx_queue->last_used_idx == ioread16(&tx_queue->used->idx))
                ;
        mb();
        desc_id = tx_queue->used
                          ->ring[tx_queue->last_used_idx % tx_queue->queue_size]
                          .id;
        // printf("Send request completed. desc idx %d status: %d\n",
        //        desc_id,
        //        *complete_status);

        if (*complete_status != 0)
                BUG("Virtio net send quest status != 0");

        free_chain(desc_id, tx_queue);
        tx_queue->last_used_idx += 1;
        BUG_ON(tx_queue->last_used_idx != ioread16(&tx_queue->used->idx));
}

#define VIRTIO_RECV_DEPTH 20
u64 recv_buffer_paddr;
void *recv_buffer_vaddr;

static inline void rx_queue_push(struct virtio_device *dev, u64 paddr)
{
        struct virt_queue *rx_queue =
                &net_dev->queues[VIRTIO_NET_RX_QUEUE_INDEX];
        int idx = alloc_desc(rx_queue);

        rx_queue->desc[idx].addr = paddr;
        rx_queue->desc[idx].len = FRAME_SIZE;
        rx_queue->desc[idx].flags = VIRTQ_DESC_F_WRITE;
        rx_queue->desc[idx].next = 0;

        mb();
        rx_queue->available->ring[rx_queue->available->idx % rx_queue->num] =
                idx;
        mb();
        // tell the device another avail ring entry is available.
        rx_queue->available->idx += 1;
        mb();

        if (!(ioread16(&rx_queue->used->flags) & VIRTQ_USED_F_NO_NOTIFY))
                notify_queue(net_dev, VIRTIO_NET_RX_QUEUE_INDEX);
        mb();
}

void virtio_net_recv(struct virtio_device *dev, u8 *packet, u32 *length)
{
        struct virt_queue *rx_queue = &dev->queues[VIRTIO_NET_RX_QUEUE_INDEX];
        int desc_id;
        u32 recv_len;
        u8 *copy_src;

        while (rx_queue->last_used_idx == ioread16(&rx_queue->used->idx))
                ;

        mb();
        desc_id = rx_queue->used
                          ->ring[rx_queue->last_used_idx % rx_queue->queue_size]
                          .id;
        recv_len =
                rx_queue->used
                        ->ring[rx_queue->last_used_idx % rx_queue->queue_size]
                        .len;
        // printf("Packet received, desc idx: %d, len: %d\n", desc_id,
        // recv_len);

        copy_src = recv_buffer_vaddr
                   + (rx_queue->last_used_idx % VIRTIO_RECV_DEPTH) * FRAME_SIZE
                   + sizeof(struct virtio_net_hdr);
        memcpy(packet, copy_src, recv_len - sizeof(struct virtio_net_hdr));

        free_desc(desc_id, rx_queue);

        *length = recv_len;
        rx_queue_push(dev,
                      recv_buffer_paddr
                              + (rx_queue->last_used_idx % VIRTIO_RECV_DEPTH)
                                        * FRAME_SIZE);
        rx_queue->last_used_idx += 1;
}

void prepare_recv_buffer(struct virtio_device *dev)
{
        struct chcore_dma_handle dma_handle;
        int i;

        /* Allocate buffer to receive packets */
        recv_buffer_vaddr = chcore_alloc_dma_mem(FRAME_SIZE * VIRTIO_RECV_DEPTH,
                                                 &dma_handle);
        recv_buffer_paddr = dma_handle.paddr;

        for (i = 0; i < VIRTIO_RECV_DEPTH; ++i) {
                rx_queue_push(net_dev, recv_buffer_paddr + i * FRAME_SIZE);
        }
}

struct virtio_device *net_dev;
extern int arp_test(void *driver);
int main()
{
        struct pci_device pdev;

        usys_get_pci_device(0x02, (unsigned long)&pdev);
        net_dev = alloc_virt_dev(&pdev);

        virtio_device_init(net_dev);

        prepare_recv_buffer(net_dev);

        virtio_server_thread_cap =
                chcore_pthread_create(&virtio_server_thread_tid,
                                      NULL,
                                      virtio_ipc_server_routine,
                                      NULL);

        usys_exit(0);
}
