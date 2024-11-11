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

struct flash_info {
	int flash_bit;
	int flash_mcode;
	int flash_dcode;
	int flash_rbit;
	int flash_rsize;
	int flash_rblocks;
	int flash_bsize;
	int flash_opt;
	int flash_eblocks;
	int flash_waddr;
	int flash_wlen;
	int flash_startaddr;
	int cpu_id;
	int edac_en;
	int parament[10];
};

#define FLASH_START	0x0
#define FLASH_END	0x10000000
#define FLASH_BASE	0x10000000