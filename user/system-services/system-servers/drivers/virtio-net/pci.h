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
#include <chcore/type.h>

// Forward declaration
struct pci_device;

/*
 * The PCI specification specifies 8 bits for the bus identifier, 5 bits for
 * the device and 3 bits for selecting a particular function. This is the BDF
 * (Bus Device Function) address of a PCI device
 */
#define PCI_MAX_DEVICES 32

struct pci_bus {
        // A bridge is a type of PCI device which just forwards all transactions
        // if they are destined for any device behind it. The PCI host bridge is
        // the common interface for all other PCI devices/buses on a system
        struct pci_device *parent_bridge;
        u32 bus_num;
};

struct pci_device {
        enum { PCI_FREE, PCI_USED } state;
        // The bus this device is on
        struct pci_bus *bus;

        // The device number of the device on the bus
        u32 dev;
        // The function represented by this struct
        u32 func;

        u32 dev_id;
        u32 dev_class;

        u64 reg_base[6];
        u32 reg_size[6];
        // Virtio spec v1.0 only defines 5 types of capabilites.
        u8 cap[6]; // Maps cap type to offset within the pci config space.
        u8 cap_bar[6]; // Maps cap type to their BAR number
        u32 cap_off[6]; // Map cap type to offset within bar

        u8 irq_line;
        u8 irq_pin;
        u64 membase;
        u32 iobase;

        u8 mac[6];
};
