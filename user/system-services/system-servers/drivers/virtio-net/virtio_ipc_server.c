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

#include <chcore-internal/lwip_defs.h>
#include <chcore-internal/net_interface.h>
#include <chcore/ipc.h>
#include <chcore/bug.h>
#include <chcore/launcher.h>
#include <assert.h>

#include "virtio.h"
#include "virtio-net.h"

pthread_t virtio_server_thread_tid;
cap_t virtio_server_thread_cap;

DEFINE_SERVER_HANDLER(virtio_net_ipc_handler)
{
        int ret = 0;
        struct net_driver_request *ndr =
                (struct net_driver_request *)ipc_get_msg_data(ipc_msg);
        u32 len;

        switch (ndr->req) {
        case NET_DRIVER_WAIT_LINK_UP: {
                printf("NET_DRIVER_WAIT_LINK_UP\n");
                break;
        }
        case NET_DRIVER_RECEIVE_FRAME: {
                // printf("NET_DRIVER_RECEIVE_FRAME\n");
                virtio_net_recv(net_dev, (u8 *)ndr->data, &len);
                ndr->args[0] = len;
                break;
        }
        case NET_DRIVER_SEND_FRAME: {
                // printf("NET_DRIVER_SEND_FRAME\n");
                len = ndr->args[0];
                virtio_net_send(net_dev, (u8 *)ndr->data, len);
                break;
        }
        default:
                break;
        }

        ipc_return(ipc_msg, ret);
}

void *virtio_ipc_server_routine(void *arg)
{
        int ret;
        struct lwip_request *lr;
        ipc_msg_t *ipc_msg;
        // char *argv[1];

        // register ipc server for access from lwip
        ret = ipc_register_server(virtio_net_ipc_handler,
                                  DEFAULT_CLIENT_REGISTER_HANDLER);
        if (ret < 0) {
                WARN("Ethernet thread register IPC server failed");
                usys_exit(0);
        }

        // call lwip to add an ethernet interface
        ipc_msg =
                ipc_create_msg_with_cap(lwip_ipc_struct, sizeof(struct lwip_request), 1);
        lr = (struct lwip_request *)ipc_get_msg_data(ipc_msg);
        lr->req = LWIP_INTERFACE_ADD;
        // configure interface type and MAC address
        struct net_interface *intf = (struct net_interface *)lr->data;
        intf->type = NET_INTERFACE_ETHERNET;
        memcpy(intf->mac_address, net_dev->macaddr, 6);

        // give lwip the thread cap, so it can ipc call (poll) us
        ipc_set_msg_cap(ipc_msg, 0, virtio_server_thread_cap);
        // do the call
        ret = ipc_call(lwip_ipc_struct, ipc_msg);
        ipc_destroy_msg(ipc_msg);
        if (ret < 0) {
                WARN("Call LWIP.LWIP_INTERFACE_ADD failed");
        }

        // argv[0] = "wsk_proxy.bin";
        // chcore_new_process(1, argv);

        usys_exit(0);
        return NULL;
}