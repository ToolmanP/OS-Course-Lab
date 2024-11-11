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

#include "greth.h"

#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <pthread.h>
#include <ctype.h>

#include <chcore/defs.h>
#include <chcore/syscall.h>
#include <chcore/bug.h>
#include <chcore/ipc.h>
#include <chcore-internal/lwip_defs.h>
#include <chcore-internal/net_interface.h>
#include <chcore/pthread.h>

#define MAC_ADDRESS_SIZE 6
static u8 mac_address[MAC_ADDRESS_SIZE];

void *greth = NULL;

static pthread_t eth_thread_tid;
static cap_t eth_thread_cap;

DEFINE_SERVER_HANDLER(eth_ipc_handler)
{
	int ret = 0;
	struct net_driver_request *ndr =
		(struct net_driver_request *)ipc_get_msg_data(ipc_msg);
	switch (ndr->req) {
	case NET_DRIVER_WAIT_LINK_UP: {
		printf("NET_DRIVER_WAIT_LINK_UP\n");
		break;
	}
	case NET_DRIVER_RECEIVE_FRAME: {
		// printf("NET_DRIVER_RECEIVE_FRAME\n");
		int len;
		while ((len = eth_receive(greth, ndr->data, 1560)) <= 0)
			;
		ndr->args[0] = len;
		break;
	}
	case NET_DRIVER_SEND_FRAME: {
		// printf("NET_DRIVER_SEND_FRAME\n");
		unsigned len = ndr->args[0];
		if (eth_send(greth, ndr->data, len))
			ret = NET_DRIVER_RET_SEND_FAILED;
		debug("ret: %d\n", ret);
		break;
	}
	default:
		break;
	}
	ipc_return(ipc_msg, ret);
}

static void *eth_thread_func(void *arg)
{
	int ret;
	struct lwip_request *lr;
	ipc_msg_t *ipc_msg;

	/* register ipc server for access from lwip */
	ret = ipc_register_server(
		eth_ipc_handler,
		DEFAULT_CLIENT_REGISTER_HANDLER);
	if (ret < 0) {
		WARN("Ethernet thread register IPC server failed");
		return 0;
	}

	/* call lwip to add an ethernet interface */
	ipc_msg = ipc_create_msg_with_cap(lwip_ipc_struct, sizeof(struct lwip_request), 1);
	lr = (struct lwip_request *)ipc_get_msg_data(ipc_msg);
	lr->req = LWIP_INTERFACE_ADD;

	/* configure interface type and MAC address */
	struct net_interface *intf = (struct net_interface *)lr->data;
	intf->type = NET_INTERFACE_ETHERNET;
	memcpy(intf->mac_address, mac_address, MAC_ADDRESS_SIZE);

	/* give lwip the thread cap, so it can ipc call (poll) us */
	ipc_set_msg_cap(ipc_msg, 0, eth_thread_cap);

	/* do the call */ 
	ret = ipc_call(lwip_ipc_struct, ipc_msg);
	ipc_destroy_msg(ipc_msg);
	if (ret < 0) {
		WARN("Call LWIP.LWIP_INTERFACE_ADD failed");
		return 0;
	}

	while (1) {
		usys_yield();
	}
}

int main(int argc, char **argv)
{
	pthread_t handler_thread_pid;

	greth = greth_initialize(mac_address);

	if (!greth){
		printf("greth initialize failed\n");
		return 0;
	}

	printf("greth %lx\n", (unsigned long)greth);

	pthread_create(&handler_thread_pid, NULL, handle_greth_irq, greth);

	eth_thread_cap = chcore_pthread_create(
		&eth_thread_tid, NULL, eth_thread_func, NULL);
	printf("Ethernet thread created, cap: %d\n", eth_thread_cap);

	usys_exit(0);
	return 0;
}