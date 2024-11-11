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
#include "pci.h"

#define DISABLE_FEATURE(v, feature) v &= ~(1 << feature)
#define ENABLE_FEATURE(v, feature)  v |= (1 << feature)
#define HAS_FEATURE(v, feature)     (v & (1 << feature))

// Virtio device IDs
enum VIRTIO_DEVICE {
        RESERVED = 0,
        NETWORK_CARD = 1,
        BLOCK_DEVICE = 2,
        CONSOLE = 3,
        ENTROPY_SOURCE = 4,
        MEMORY_BALLOONING_TRADITIONAL = 5,
        IO_MEMORY = 6,
        RPMSG = 7,
        SCSI_HOST = 8,
        NINEP_TRANSPORT = 9,
        MAC_80211_WLAN = 10,
        RPROC_SERIAL = 11,
        VIRTIO_CAIF = 12,
        MEMORY_BALLOON = 13,
        GPU_DEVICE = 14,
        CLOCK_DEVICE = 15,
        INPUT_DEVICE = 16
};

// Transitional vitio device ids
enum TRANSITIONAL_VIRTIO_DEVICE {
        T_NETWORK_CARD = 0X1000,
        T_BLOCK_DEVICE = 0X1001,
        T_MEMORY_BALLOONING_TRADITIONAL = 0X1002,
        T_CONSOLE = 0X1003,
        T_SCSI_HOST = 0X1004,
        T_ENTROPY_SOURCE = 0X1005,
        T_NINEP_TRANSPORT = 0X1006
};

// The PCI device ID of is VIRTIO_DEVICE_ID_BASE + virtio_device
#define VIRTIO_DEVICE_ID_BASE 0x1040
// A virtio device will always have this vendor id
#define VIRTIO_VENDOR_ID 0x1AF4

struct virtio_pci_cap {
        // Generic PCI field: PCI_CAP_ID_VNDR, 0
        u8 cap_vendor;
        // Generic PCI field: next ptr, 1
        u8 cap_next;
        // Generic PCI field: capability length, 2
        u8 cap_len;
/* Common configuration */
#define VIRTIO_PCI_CAP_COMMON_CFG 1
/* Notifications */
#define VIRTIO_PCI_CAP_NOTIFY_CFG 2
/* ISR Status */
#define VIRTIO_PCI_CAP_ISR_CFG 3
/* Device specific configuration */
#define VIRTIO_PCI_CAP_DEVICE_CFG 4
/* PCI configuration access */
#define VIRTIO_PCI_CAP_PCI_CFG 5
        // Identifies the structure, 3
        u8 cfg_type;
        // Where to find it, 4
        u8 bar;
        // Pad to full dword, 5
        u8 padding[3];
        // Offset within bar, 8
        u32 offset;
        // Length of the structure, in bytes, 12
        u32 length;
};

struct virtio_pci_notify_cap {
        struct virtio_pci_cap cap;
        u32 notify_off_multiplier; /* Multiplier for queue_notify_off. */
};

struct virtio_pci_common_cfg {
        /* About the whole device. */
        u32 device_feature_select; /* read-write , 0*/
        u32 device_feature; /* read-only for driver , 4*/
        u32 driver_feature_select; /* read-write , 8*/
        u32 driver_feature; /* read-write , 12*/
        u16 msix_config; /* read-write , 20*/
        u16 num_queues; /* read-only for driver , 22*/
        u8 device_status; /* read-write , 24*/
        u8 config_generation; /* read-only for driver , 25*/

        /* About a specific virtqueue. */
        u16 queue_select; /* read-write , 26*/
        u16 queue_size; /* read-write, power of 2, or 0. , 28*/
        u16 queue_msix_vector; /* read-write , 30*/
        u16 queue_enable; /* read-write , 32*/
        u16 queue_notify_off; /* read-only for driver , 34*/
        u32 queue_desc_lo; /* read-write */
        u32 queue_desc_hi; /* read-write */
        u32 queue_avail_lo; /* read-write */
        u32 queue_avail_hi; /* read-write */
        u32 queue_used_lo; /* read-write */
        u32 queue_used_hi; /* read-write */
};

struct virtq_desc {
        /* Address (guest-physical). */
        u64 addr;
        /* Length. */
        u32 len;
/* This marks a buffer as continuing via the next field. */
#define VIRTQ_DESC_F_NEXT 1
/* This marks a buffer as device write-only (otherwise device read-only). */
#define VIRTQ_DESC_F_WRITE 2
/* This means the buffer contains a list of buffer descriptors. */
#define VIRTQ_DESC_F_INDIRECT 4
        /* The flags as indicated above. */
        u16 flags;
        /* Next field if flags & NEXT */
        u16 next;
};

struct virtq_avail {
#define VIRTQ_AVAIL_F_NO_INTERRUPT 1
        u16 flags;
        u16 idx;
        u16 ring[/* queue size */];
};

/* u32 is used here for ids for padding reasons. */
struct virtq_used_elem {
        /* Index of start of used descriptor chain. */
        u32 id;
        /* Total length of the descriptor chain which was used (written to) */
        u32 len;
};

typedef struct virtq_used_elem __attribute__((aligned(4))) virtq_used_elem_t;

struct virtq_used {
#define VIRTQ_USED_F_NO_NOTIFY 1
        u16 flags;
        u16 idx;
        virtq_used_elem_t ring[/* Queue Size */];
};

/* Alignment requirements for vring elements.
 * When using pre-virtio 1.0 layout, these fall out naturally.
 */
#define VRING_AVAIL_ALIGN_SIZE 2
#define VRING_USED_ALIGN_SIZE  4
#define VRING_DESC_ALIGN_SIZE  16

typedef struct virtq_desc __attribute__((aligned(VRING_DESC_ALIGN_SIZE)))
vring_desc_t;
typedef struct virtq_avail __attribute__((aligned(VRING_AVAIL_ALIGN_SIZE)))
vring_avail_t;
typedef struct virtq_used __attribute__((aligned(VRING_USED_ALIGN_SIZE)))
vring_used_t;

// alignment and sizes come from virtio spec 1.0 2.4 Virtqueues
// http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-220004
struct virt_queue {
        u32 num;
        vring_desc_t *desc;
        vring_avail_t *available;
        vring_used_t *used;
        u64 desc_pa;
        u64 available_pa;
        u64 used_pa;

        u16 next_buffer;
        u16 queue_size;
        vaddr_t notify_addr;

        u8 *free;
        u16 last_used_idx;

        u8 *packet_buffer;
        u64 packet_buffer_pa;
};

static inline unsigned vring_size(unsigned int num, unsigned long align)
{
        return ((sizeof(struct virtq_desc) * num + sizeof(u16) * (3 + num)
                 + align - 1)
                & ~(align - 1))
               + sizeof(u16) * 3 + sizeof(struct virtq_used_elem) * num;
}

/*
 * A Virtio device.
 */
struct virtio_device {
        enum { VIRT_FREE, VIRT_USED } state;
        // memory mapped IO base
        u64 base;
        // size of memory mapped region
        u32 size;
        u8 irq;
        u32 iobase;
        struct pci_device *pci;
        /* MMIO vaddr after remap */
        u64 remap_base;
        struct virtio_pci_common_cfg *cfg;
        u8 macaddr[6];
#define VIRTIO_NET_RX_QUEUE_INDEX   0
#define VIRTIO_NET_TX_QUEUE_INDEX   1
#define VIRTIO_NET_CTRL_QUEUE_INDEX 2
        struct virt_queue queues[4];
};

#define NVIRTIO 10

// Array of virtio devices
extern struct virtio_device virtdevs[NVIRTIO];

/* The feature bitmap for virtio net */
#define VIRTIO_NET_F_CSUM          0 /* Host handles pkts w/ partial csum */
#define VIRTIO_NET_F_GUEST_CSUM    1 /* Guest handles pkts w/ partial csum */
#define VIRTIO_NET_F_MAC           5 /* Host has given MAC address. */
#define VIRTIO_NET_F_GSO           6 /* Host handles pkts w/ any GSO type */
#define VIRTIO_NET_F_GUEST_TSO4    7 /* Guest can handle TSOv4 in. */
#define VIRTIO_NET_F_GUEST_TSO6    8 /* Guest can handle TSOv6 in. */
#define VIRTIO_NET_F_GUEST_ECN     9 /* Guest can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_GUEST_UFO     10 /* Guest can handle UFO in. */
#define VIRTIO_NET_F_HOST_TSO4     11 /* Host can handle TSOv4 in. */
#define VIRTIO_NET_F_HOST_TSO6     12 /* Host can handle TSOv6 in. */
#define VIRTIO_NET_F_HOST_ECN      13 /* Host can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_HOST_UFO      14 /* Host can handle UFO in. */
#define VIRTIO_NET_F_MRG_RXBUF     15 /* Host can merge receive buffers. */
#define VIRTIO_NET_F_STATUS        16 /* virtio_net_config.status available */
#define VIRTIO_NET_F_CTRL_VQ       17 /* Control channel available */
#define VIRTIO_NET_F_CTRL_RX       18 /* Control channel RX mode support */
#define VIRTIO_NET_F_CTRL_VLAN     19 /* Control channel VLAN filtering */
#define VIRTIO_NET_F_CTRL_RX_EXTRA 20 /* Extra RX mode control support */
#define VIRTIO_NET_F_GUEST_ANNOUNCE \
        21 /* Guest can announce device on the network */
#define VIRTIO_NET_F_MQ                    \
        22 /* Device supports Receive Flow \
            * Steering */
#define VIRTIO_F_EVENT_IDX \
        29 /* Support for avail_event and used_event fields */
#define VIRTIO_F_VERSION_1 32

#define VIRTIO_STATUS_RESET              0
#define VIRTIO_STATUS_ACKNOWLEDGE        1
#define VIRTIO_STATUS_DRIVER             2
#define VIRTIO_STATUS_FAILED             128
#define VIRTIO_STATUS_FEATURES_OK        8
#define VIRTIO_STATUS_DRIVER_OK          4
#define VIRTIO_STATUS_DEVICE_NEEDS_RESET 64

#define VIRTIO_HOST_F_OFF  0x0000
#define VIRTIO_GUEST_F_OFF 0x0004
#define VIRTIO_QADDR_OFF   0x0008

#define VIRTIO_QSIZE_OFF   0x000C
#define VIRTIO_QSEL_OFF    0x000E
#define VIRTIO_QNOTFIY_OFF 0x0010

#define VIRTIO_DEV_STATUS_OFF   0x0012
#define VIRTIO_ISR_STATUS_OFF   0x0013
#define VIRTIO_DEV_SPECIFIC_OFF 0x0014
/* if msi is enabled, device specific headers shift by 4 */
#define VIRTIO_MSI_ADD_OFF   0x0004
#define VIRTIO_STATUS_DRV    0x02
#define VIRTIO_STATUS_ACK    0x01
#define VIRTIO_STATUS_DRV_OK 0x04
#define VIRTIO_STATUS_FAIL   0x80

#define mb()  asm volatile("mfence")
#define rmb() asm volatile("mfence")
#define wmb() asm volatile("mfence")

static inline u8 ioread8(u8 *addr)
{
        u8 ret;
        mb();
        ret = *addr;
        rmb();
        return ret;
}

static inline void iowrite8(u8 value, u8 *addr)
{
        mb();
        *addr = value;
        wmb();
}

static inline u16 ioread16(u16 *addr)
{
        u16 ret;
        mb();
        ret = *addr;
        rmb();
        return ret;
}

static inline void iowrite16(u16 value, u16 *addr)
{
        mb();
        *addr = value;
        wmb();
}

static inline u32 ioread32(u32 *addr)
{
        u32 ret;
        mb();
        ret = *addr;
        rmb();
        return ret;
}

static inline void iowrite32(u32 value, u32 *addr)
{
        mb();
        *addr = value;
        wmb();
}

static inline void iowrite64_twopart(u64 val, u32 *lo, u32 *hi)
{
        iowrite32((u32)val, lo);
        iowrite32(val >> 32, hi);
}
