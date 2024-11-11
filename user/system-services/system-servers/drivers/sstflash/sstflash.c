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

#include <malloc.h>
#include <stdio.h>
#include <sys/mman.h>
#include <chcore/ipc.h>
#include <chcore/syscall.h>
#include <chcore/memory.h>
#include <chcore-internal/flash_defs.h>
#include "sstflash.h"

// #define DEBUG
#define PREFIX "[flash]"

#define info(fmt, ...) printf(PREFIX " " fmt, ##__VA_ARGS__)
#define error(fmt, ...) printf(PREFIX " " fmt, ##__VA_ARGS__)
#ifdef DEBUG
#define debug(fmt, ...) printf(PREFIX " " fmt, ##__VA_ARGS__)
#else
#define debug(fmt, ...)
#endif

#define soft_barrier asm volatile("": : :"memory")

#define BLOCK_OFFSET 256

struct flash_info *flash_info;

void static inline disable_l2cache(void)
{
	usys_cache_config(0);
}

void static inline enable_l2cache(void)
{
	usys_cache_config(1);
}

static void init_flash_info(struct flash_info *flash_info)
{
	flash_info->flash_bit = 32;
	flash_info->flash_mcode = 0xbf;
	flash_info->flash_startaddr = FLASH_BASE;
	flash_info->cpu_id = 4;
}

static int init_io_mapping(void)
{
	int io_pmo_cap = usys_create_device_pmo(
		FLASH_START, ROUND_UP(FLASH_END - FLASH_START, PAGE_SIZE));
	int ret = usys_map_pmo(
		SELF_CAP, io_pmo_cap, FLASH_BASE, VM_READ | VM_WRITE);
	return ret;
}

#ifdef DEBUG
static int flash_show_info(void)
{
	if (flash_info->flash_mcode == 0x89) {
		printf("\n     Intel-style\n");
	}
	else if (flash_info->flash_mcode == 0xbf) {
		printf("\n     SST-style\n");
	}
	else if (flash_info->flash_mcode == 0x01) {
		printf("\n     AMD-style\n");
	}
	else if (flash_info->flash_mcode == 0x1f) {
		printf("\n     ATMEL-style\n");
	}
	else if (flash_info->flash_mcode == 0xf5) {
		printf("\n     USER-style\n");
	}
	else {
		printf("\n     unknow flash \n");
		return -1;
	}
	
	printf(" Manufacturer ID : 0x%x \n", flash_info->flash_mcode);
	printf(" Device ID       : 0x%x \n", flash_info->flash_dcode);	
	printf(" prom            : %d bit\n", flash_info->flash_bit);
	printf(" flash           : %d * %d-bit \n",
		flash_info->flash_bit/flash_info->flash_rbit,
		flash_info->flash_rbit);
	printf(" flash size      : %d * %d Kbyte\n",
		flash_info->flash_bit/flash_info->flash_rbit,
		flash_info->flash_rsize);
	printf(" blocks          : %d \n", flash_info->flash_rblocks);
	if ((flash_info->flash_mcode == 0x01) ||
		(flash_info->flash_mcode == 0x1f)) {
		if ((flash_info->flash_dcode == 0x2256) ||
			(flash_info->flash_dcode == 0x2253) ||
			(flash_info->flash_dcode == 0x225f)||
			(flash_info->flash_dcode == 0xc8)) {
			printf(" block size      :(0 - 7) %d * 8 Kbyte\n",
				flash_info->flash_bit/flash_info->flash_rbit);
			printf(" block size      :(8 -70) %d * %d Kbyte\n\n",
				flash_info->flash_bit/flash_info->flash_rbit,
				flash_info->flash_bsize/1024);
		}
		else if ((flash_info->flash_dcode&0xffff) == 0x037e) {
			if ((flash_info->flash_dcode&0xff0000) == 0x0) {
				printf(" block size       :(0)    32  Kbyte\n");
				printf(" block size       :(1-2)  16  Kbyte\n");
				printf(" block size       :(3)    192 Kbyte\n");
				printf(" block size       :(4-18) 256 Kbyte\n");
			}
			else {
				printf(" block size       :(0-14) 256 Kbyte\n");
				printf(" block size       :(15)   192 Kbyte\n");
				printf(" block size       :(16-17)16  Kbyte\n");
				printf(" block size       :(18)   32  Kbyte\n");
			}
		}
		else {
			printf(" block size       :(0 -62) %d * %d Kbyte\n",
				flash_info->flash_bit/flash_info->flash_rbit,
				flash_info->flash_bsize/1024);
			printf(" block size       :(63 -70) %d * 8 Kbyte\n\n",
				flash_info->flash_bit/flash_info->flash_rbit);
		}
	}
	else {
		printf(" block size      : %d * %d Kbyte\n\n",
			flash_info->flash_bit/flash_info->flash_rbit,
			flash_info->flash_bsize/1024);
	}
	return 0;
}
#endif

int sst_flash_detect(void)
{
	unsigned int mid = 0;
	debug("sst flash detect\n");

	disable_l2cache();
	
	if (flash_info->flash_bit == 32) {
		unsigned int *flashaddr = 
			(unsigned int *)flash_info->flash_startaddr;
		flashaddr[0x5555] = 0xaaaaaaaa;
		soft_barrier;
		flashaddr[0x2aaa] = 0x55555555;
		soft_barrier;
		flashaddr[0x5555] = 0x90909090;
		soft_barrier;
		mid = flashaddr[0];
		debug("flash mid = 0x%x\n", mid);

		if (mid == 0xbfbfbfbf) {
			flash_info->flash_dcode = flashaddr[1] & 0xff;
		}
		else if (mid == 0xbf00bf) {
			flash_info->flash_dcode = flashaddr[1] & 0xffff;
		}
		else {
			flash_info->flash_mcode = 0;
			error("sst flash not found!\n");
			return -1;
		}

		flashaddr[0x5555] = 0xaaaaaaaa;
		soft_barrier;
		flashaddr[0x2aaa] = 0x55555555;
		soft_barrier;
		flashaddr[0x5555] = 0xf0f0f0f0;
		soft_barrier;
	}
	else if (flash_info->flash_bit == 16) {
		unsigned short *flashaddr = 
			(unsigned short *)flash_info->flash_startaddr;
		flashaddr[0x5555] = 0xaaaa;
		soft_barrier;
		flashaddr[0x2aaa] = 0x5555;
		soft_barrier;
		flashaddr[0x5555] = 0x9090;
		soft_barrier;
		mid = flashaddr[0];

		if (mid == 0xbfbf) {
			flash_info->flash_dcode = flashaddr[1] & 0xff;
		}
		else if (mid==0xbf) {
			flash_info->flash_dcode = flashaddr[1] & 0xffff;	
		}
		else {
			flash_info->flash_mcode = 0;
			error("sst flash not found!\n");
			return -1;
		}

		flashaddr[0x5555] = 0xaaaa;
		soft_barrier;
		flashaddr[0x2aaa] = 0x5555;
		soft_barrier;
		flashaddr[0x5555] = 0xf0f0;
		soft_barrier;
	}
	else if (flash_info->flash_bit == 8) {
		unsigned char *flashaddr = 
			(unsigned char *)flash_info->flash_startaddr;
		flashaddr[0x5555] = 0xaa;
		soft_barrier;
		flashaddr[0x2aaa] = 0x55;
		soft_barrier;
		flashaddr[0x5555] = 0x90;
		soft_barrier;

		if (flashaddr[0] != 0xbf) {
			flash_info->flash_mcode = 0;
			error("sst flash not found!\n");
			return -1;
		}
		
		flash_info->flash_dcode = flashaddr[1] & 0xff;
		flashaddr[0x5555] = 0xaa;
		soft_barrier;
		flashaddr[0x2aaa] = 0x55;
		soft_barrier;
		flashaddr[0x5555] = 0xf0;
		soft_barrier;
	}	

	if (flash_info->flash_dcode == 0xd4) {
		flash_info->flash_rsize = 512/8;
	}
	else if (flash_info->flash_dcode == 0xd5) {
		flash_info->flash_rsize = 1024/8;
	}
	else if(flash_info->flash_dcode==0xd6) {
		flash_info->flash_rsize = 2*1024/8;
	}
	else if (flash_info->flash_dcode == 0xd7) {
		flash_info->flash_rsize = 4*1024/8;
	}
	else if (flash_info->flash_dcode == 0x80) {
		flash_info->flash_rsize = 4*1024/8;
	}
	else if (flash_info->flash_dcode == 0x81) {
		flash_info->flash_rsize = 8*1024/8;
	}
	else if (flash_info->flash_dcode == 0x89) {
		flash_info->flash_rsize = 2*1024/8;
	}
	else if (flash_info->flash_dcode == 0x236d) {
		flash_info->flash_rsize = 4*16*1024/8;
	}
	else if (flash_info->flash_dcode == 0x235d) {
		flash_info->flash_rsize = 2*16*1024/8;
	}
	else {
		flash_info->flash_mcode = 0;
		error("unknown sst flash\n");
		return -1;
	}

	if ((flash_info->flash_dcode == 0x80) || 
		(flash_info->flash_dcode == 0x81) || 
		(flash_info->flash_dcode == 0x89)) {
		////x8 or x16  or x8/x16
		flash_info->flash_rbit = 16;
		flash_info->flash_rblocks = flash_info->flash_rsize /2;
		////block size
		flash_info->flash_bsize = 0x800; //2k
	}
	else if ((flash_info->flash_dcode == 0x236d) || 
		(flash_info->flash_dcode == 0x235d)) {
		////x8 or x16  or x8/x16
		flash_info->flash_rbit = 16;
		// flash_info->flash_rblocks = flash_info->flash_rsize /32;
		flash_info->flash_rblocks = flash_info->flash_rsize / 8;
		////block size
		// flash_info->flash_bsize = 0x8000; //32k
		flash_info->flash_bsize = 0x800; //2k
	}
	else {
		////x8 or x16  or x8/x16
		flash_info->flash_rbit = 8;
		flash_info->flash_rblocks = flash_info->flash_rsize /4;
		////block size
		flash_info->flash_bsize = 0x1000; //4k	
	}

	enable_l2cache();
#ifdef DEBUG
	flash_show_info();
#endif
	return 0;
}

int sst_flash_erase(struct flash_request *req)
{	
	int delay = 0;
	unsigned start_block, end_block;
	unsigned toggle1 = 0, toggle2 = 0;

	start_block = req->erase.block + BLOCK_OFFSET;
	end_block = start_block + req->erase.count;
#ifdef DEBUG
	unsigned blocksize = (flash_info->flash_bit / flash_info->flash_rbit) *
		flash_info->flash_bsize * 2;
#endif
	if (end_block > flash_info->flash_rblocks) {
		end_block = flash_info->flash_rblocks;
	}
	if (end_block < start_block) {
		error("erase failed: invalid parameters\n");
		return -1;
	}
	else if (end_block == start_block) {
		return 0;
	}

	disable_l2cache();

	if (flash_info->flash_bit == 32) {
		unsigned *flashaddr = (unsigned *)flash_info->flash_startaddr;
		for (int i = start_block; i < end_block; i++) {
#ifdef DEBUG
			unsigned regaddr = flash_info->flash_startaddr +
				blocksize * i;
			debug("erase block %3u : 0x%.8x - 0x%.8x\n",
				i, regaddr, regaddr + blocksize);
#endif
			flashaddr[0x5555] = 0xaaaaaaaa;
			soft_barrier;
			flashaddr[0x2aaa] = 0x55555555;
			soft_barrier;
			flashaddr[0x5555] = 0x80808080;
			soft_barrier;
			flashaddr[0x5555] = 0xaaaaaaaa;
			soft_barrier;
			flashaddr[0x2aaa] = 0x55555555;
			soft_barrier;
			flashaddr[flash_info->flash_bsize * i] = 0x50505050;
			soft_barrier;

			while (1) {
				toggle1 = flashaddr[flash_info->flash_bsize * i];
				soft_barrier;
				toggle2 = flashaddr[flash_info->flash_bsize * i];
				if ((0x40404040 & toggle1) == (0x40404040 & toggle2)) {
					break;
				}
				else {
					for(delay = 0; delay < 100000; delay++);
				}
			}
		}
		flashaddr[0x5555] = 0xaaaaaaaa;
		soft_barrier;
		flashaddr[0x2aaa] = 0x55555555;
		soft_barrier;
		flashaddr[0x5555] = 0xf0f0f0f0;
		soft_barrier;
	}
	else if (flash_info->flash_bit == 16) {
		unsigned short *flashaddr = 
			(unsigned short *)flash_info->flash_startaddr;		
		for(int i = start_block; i < end_block; i++) {
#ifdef DEBUG
			unsigned regaddr = flash_info->flash_startaddr +
				blocksize * i;
			debug("erase block %3u : 0x%.8x - 0x%.8x\n",
				i, regaddr, regaddr + blocksize);
#endif
			flashaddr[0x5555] = 0xaaaa;
			soft_barrier;
			flashaddr[0x2aaa] = 0x5555;
			soft_barrier;
			flashaddr[0x5555] = 0x8080;
			soft_barrier;
			flashaddr[0x5555] = 0xaaaa;
			soft_barrier;
			flashaddr[0x2aaa] = 0x5555;
			soft_barrier;
			flashaddr[flash_info->flash_bsize * i] = 0x3030;
			soft_barrier;

			for (int j = 0; j < 100; j++) {
				toggle1 = flashaddr[flash_info->flash_bsize * i];
				soft_barrier;
				toggle2 = flashaddr[flash_info->flash_bsize * i];
				soft_barrier;
				if ((0x4040 & toggle1) == (0x4040 & toggle2)) {
					break;
				}
				else {
					for (delay = 0; delay < 10000; delay++);
				}
			}
		}
		flashaddr[0x5555] = 0xaaaa;
		soft_barrier;
		flashaddr[0x2aaa] = 0x5555;
		soft_barrier;
		flashaddr[0x5555] = 0xf0f0;
		soft_barrier;
	}
	else if (flash_info->flash_bit == 8) {
		unsigned char *flashaddr = 
			(unsigned char *)flash_info->flash_startaddr;
		for (int i = start_block; i < end_block; i++) {
#ifdef DEBUG
			unsigned regaddr = flash_info->flash_startaddr +
				blocksize * i;
			debug("erase block %3u : 0x%.8x - 0x%.8x\n",
				i, regaddr, regaddr + blocksize);
#endif
			flashaddr[0x5555] = 0xaa;
			soft_barrier;
			flashaddr[0x2aaa] = 0x55;
			soft_barrier;
			flashaddr[0x5555] = 0x80;
			soft_barrier;
			flashaddr[0x5555] = 0xaa;
			soft_barrier;
			flashaddr[0x2aaa] = 0x55;
			soft_barrier;
			flashaddr[flash_info->flash_bsize * i] = 0x30;
			soft_barrier;

			for (int j = 0; j < 100; j++) {
				toggle1 = flashaddr[flash_info->flash_bsize * i];
				soft_barrier;
				toggle2 = flashaddr[flash_info->flash_bsize * i];
				soft_barrier;
				if ((0x4040 & toggle1) == (0x4040 & toggle2)) {
					break;
				}
				else {
					for (delay = 0; delay < 10000; delay++);
				}
			}
		}
		flashaddr[0x5555] = 0xaa;
		soft_barrier;
		flashaddr[0x2aaa] = 0x55;
		soft_barrier;
		flashaddr[0x5555] = 0xf0;
		soft_barrier;	
	}

	enable_l2cache();
	return 0;
}

int sst_flash_read(ipc_msg_t *ipc_msg)
{
	unsigned block, offset, length, blocksize;
	struct flash_request *req;

	req = (struct flash_request *)ipc_get_msg_data(ipc_msg);
	block = req->read.block + BLOCK_OFFSET;
	offset = req->read.offset;
	length = req->read.length;
	blocksize = (flash_info->flash_bit / flash_info->flash_rbit) *
			flash_info->flash_bsize * 2;
	debug("read: block = %u, offset = %u, length = %u\n",
		block, offset, length);
	if (offset + length > blocksize) {
		length = blocksize - offset;
	}

	if (flash_info->flash_bit == 32) {
		unsigned *flashaddr = (unsigned *)flash_info->flash_startaddr;
		volatile unsigned *bufptr = (volatile unsigned *)
			((void *)req + sizeof(struct flash_request));
		volatile unsigned *addrptr = (volatile unsigned *)
			((void *)flashaddr + block * blocksize + offset);

		for (int i = 0; i < length; i += 4, addrptr++, bufptr++) {
			*bufptr = *addrptr;
		}
	}
	else if (flash_info->flash_bit == 16) {
		unsigned short *flashaddr = 
			(unsigned short *)flash_info->flash_startaddr;
		volatile unsigned short *bufptr = (volatile unsigned short *)
			((void *)req + sizeof(struct flash_request));
		volatile unsigned short *addrptr = (volatile unsigned short *)
			((void *)flashaddr + block * blocksize + offset);

		for (int i = 0; i < length; i += 2, addrptr++, bufptr++) {
			*bufptr = *addrptr;
		}
	}
	else if (flash_info->flash_bit == 8) {
		unsigned char *flashaddr = 
			(unsigned char *)flash_info->flash_startaddr;
		volatile unsigned char *bufptr = (volatile unsigned char *)
			((void *)req + sizeof(struct flash_request));
		volatile unsigned char *addrptr = (volatile unsigned char *)
			((void *)flashaddr + block * blocksize + offset);

		for (int i = 0; i < length; i++, addrptr++, bufptr++) {
			*bufptr = *addrptr;
		}
	}

	debug("read finished\n");
	return 0;
}

int sst_flash_write(ipc_msg_t *ipc_msg)
{
	int delay = 0;
	unsigned block, offset, length, blocksize;
	struct flash_request *req;

	req = (struct flash_request *)ipc_get_msg_data(ipc_msg);
	block = req->write.block + BLOCK_OFFSET;
	offset = req->write.offset;
	length = req->write.length;
	blocksize = (flash_info->flash_bit / flash_info->flash_rbit) *
			flash_info->flash_bsize * 2;
	debug("write: block = %u, offset = %u, length = %u\n",
		block, offset, length);
	if (offset + length > blocksize) {
		length = blocksize - offset;
	}

	disable_l2cache();

	if (flash_info->flash_bit == 32) {
		unsigned *flashaddr = (unsigned *)flash_info->flash_startaddr;
		volatile unsigned *bufptr = (volatile unsigned *)
			((void *)req + sizeof(struct flash_request));
		volatile unsigned *addrptr = (volatile unsigned *)
			((void *)flashaddr + block * blocksize + offset);

		for (int i = 0; i < length; i += 4) {
			flashaddr[0x5555] = 0xaaaaaaaa;
			soft_barrier;
			flashaddr[0x2aaa] = 0x55555555;
			soft_barrier;
			flashaddr[0x5555] = 0xa0a0a0a0;
			soft_barrier;
			*addrptr = *bufptr;
			while (*addrptr != *bufptr) {
				for (delay = 0; delay < 100000; delay++);
			}	
			++addrptr;
			++bufptr;
		}
		flashaddr[0x5555] = 0xaaaaaaaa;
		soft_barrier;
		flashaddr[0x2aaa] = 0x55555555;
		soft_barrier;
		flashaddr[0x5555] = 0xf0f0f0f0;
		soft_barrier;
	}
	else if (flash_info->flash_bit == 16) {
		unsigned short *flashaddr = 
			(unsigned short *)flash_info->flash_startaddr;
		volatile unsigned short *bufptr = (volatile unsigned short *)
			((void *)req + sizeof(struct flash_request));
		volatile unsigned short *addrptr = (volatile unsigned short *)
			((void *)flashaddr + block * blocksize + offset);

		for (int i = 0; i < length; i += 2) {
			flashaddr[0x5555] = 0xaaaa;
			soft_barrier;
			flashaddr[0x2aaa] = 0x5555;
			soft_barrier;
			flashaddr[0x5555] = 0xa0a0;
			soft_barrier;
			
			*addrptr = *bufptr;
			delay = 0;
			while(*addrptr != *bufptr) {
				delay++;
				if (delay > 400) {
					error("write failed!\n");
					return -1;
				}
			}
			++addrptr;
			++bufptr;
		}
		flashaddr[0x5555] = 0xaaaa;
		soft_barrier;
		flashaddr[0x2aaa] = 0x5555;
		soft_barrier;
		flashaddr[0x5555] = 0xf0f0;
		soft_barrier;
	}
	else if (flash_info->flash_bit == 8) {
		unsigned char *flashaddr = 
			(unsigned char *)flash_info->flash_startaddr;
		volatile unsigned char *bufptr = (volatile unsigned char *)
			((void *)req + sizeof(struct flash_request));
		volatile unsigned char *addrptr = (volatile unsigned char *)
			((void *)flashaddr + block * blocksize + offset);

		for (int i = 0; i < length; i++) {
			flashaddr[0x5555] = 0xaa;
			soft_barrier;
			flashaddr[0x2aaa] = 0x55;
			soft_barrier;
			flashaddr[0x5555] = 0xa0;
			soft_barrier;
			
			*addrptr = *bufptr;
			delay = 0;
			while (*addrptr != *bufptr) {
				delay++;
				if (delay > 400) {
					error("write failed!\n");
					return -1;
				}	
			}
			++addrptr;
			++bufptr;
		}
		flashaddr[0x5555] = 0xaa;
		soft_barrier;
		flashaddr[0x2aaa] = 0x55;
		soft_barrier;
		flashaddr[0x5555] = 0xf0;
		soft_barrier;
	}

	enable_l2cache();
	debug("write finished\n");
	return 0;
}

DEFINE_SERVER_HANDLER(sst_flash_dispatch)
{
	struct flash_request *req;
	int ret = 0;
	req = (struct flash_request *)ipc_get_msg_data(ipc_msg);

	switch (req->req)
	{
	case FLASH_REQ_DETECT:
		ret = sst_flash_detect();
		break;
	case FLASH_REQ_READ:
		ret = sst_flash_read(ipc_msg);
		break;
	case FLASH_REQ_WRITE:
		ret = sst_flash_write(ipc_msg);
		break;
	case FLASH_REQ_ERASE:
		ret = sst_flash_erase(req);
		break;
	default:
		error("request %d not supported\n", req->req);
		ret = -1;
		break;
	}
	ipc_return(ipc_msg, ret);
}

int main()
{
	int ret = 0;
	flash_info = calloc(1, sizeof(*flash_info));
	init_flash_info(flash_info);
	ret = init_io_mapping();
	if (ret < 0) {
		error("map pmo failed\n");
		free(flash_info);
		return -1;
	}

	ret = sst_flash_detect();
	if (ret < 0) {
		error("flash detect failed\n");
		free(flash_info);
		return -1;
	}

	ret = ipc_register_server(sst_flash_dispatch,
		DEFAULT_CLIENT_REGISTER_HANDLER);
	if (ret < 0) {
		error("failed to register flash dispatch server\n");
		free(flash_info);
		return -1;
	}
	info("flash dispatch server registered\n");

	while (1) {
		usys_yield();
	}
	return 0;
}