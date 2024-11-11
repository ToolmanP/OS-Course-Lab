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

/* Gaisler.com GRETH 10/100/1000 Ethernet MAC driver
 *
 * Driver use polling mode (no Interrupt)
 *
 * (C) Copyright 2007
 * Daniel Hellstrom, Gaisler Research, daniel@gaisler.com
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

/* #define DEBUG */
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/param.h>

#include <errno.h>
#include <malloc.h>
#include <chcore/syscall.h>
#include <chcore/memory.h>
#include <sys/mman.h>

#include "greth.h"

/* Default to 3s timeout on autonegotiation */
#ifndef GRETH_PHY_TIMEOUT_MS
#define GRETH_PHY_TIMEOUT_MS 3000
#endif

/* ByPass Cache when reading regs */
#define GRETH_REGLOAD(addr)		(*(unsigned int volatile *)((unsigned int)addr))
/* Write-through cache ==> no bypassing needed on writes */
#define GRETH_REGSAVE(addr,data) (*(volatile unsigned int *)(addr) = (data))
#define GRETH_REGORIN(addr,data) GRETH_REGSAVE(addr,GRETH_REGLOAD(addr)|data)
#define GRETH_REGANDIN(addr,data) GRETH_REGSAVE(addr,GRETH_REGLOAD(addr)&data)

#define GRETH_RXBD_CNT 16
#define GRETH_TXBD_CNT 8

#define GRETH_RXBUF_SIZE 1540
#define GRETH_BUF_ALIGN 4
#define GRETH_RXBUF_EFF_SIZE \
	( (GRETH_RXBUF_SIZE&~(GRETH_BUF_ALIGN-1))+GRETH_BUF_ALIGN )

typedef struct {
	greth_regs *regs;
	int irq;

	/* Hardware info */
	unsigned char phyaddr;
	int gbit_mac;

	/* Current operating Mode */
	int m_link;			/* 1: link is up */
	int gb;			/* GigaBit */
	int fd;			/* Full Duplex */
	int sp;			/* 10/100Mbps speed (1=100,0=10) */
	int auto_neg;		/* Auto negotiate done */

	unsigned char hwaddr[6];	/* MAC Address */

	unsigned int tx_next, tx_last, tx_free;

	/* Descriptors */
	greth_bd *rxbd_base, *rxbd_max;
	greth_bd *txbd_base, *txbd_max;

	greth_bd *rxbd_curr;

	/* rx buffers in rx descriptors */
	void *rxbuf_base;	/* (GRETH_RXBUF_SIZE+ALIGNBYTES) * GRETH_RXBD_CNT */

	/* tx buffers in tx descriptors */
	void *txbuf_base;


	struct {
		/* rx status */
		unsigned int rx_packets,
		    rx_crc_errors, rx_frame_errors, rx_length_errors, rx_errors;

		/* tx stats */
		unsigned int tx_packets,
		    tx_latecol_errors,
		    tx_underrun_errors, tx_limit_errors, tx_errors;
	} stats;
} greth_priv;

#define PKTSIZE			1518
#define ETHER_HDR_SIZE	14
static struct {
	unsigned char data[PKTSIZE];
	int length;
} eth_rcv_bufs[GRETH_RXBD_CNT];

static unsigned int eth_rcv_current, eth_rcv_last;

#define APB_BASE 0x80000000
#define USER_APB_BASE 0x70000000

#define GRETH_BASE 0x70000e00
#define GRETH_IRQ 5

/* Read MII register 'addr' from core 'regs' */
static int read_mii(int phyaddr, int regaddr, volatile greth_regs * regs)
{
	while (GRETH_REGLOAD(&regs->mdio) & GRETH_MII_BUSY) {
	}

	GRETH_REGSAVE(&regs->mdio, ((phyaddr & 0x1F) << 11) | ((regaddr & 0x1F) << 6) | 2);

	while (GRETH_REGLOAD(&regs->mdio) & GRETH_MII_BUSY) {
	}

	if (!(GRETH_REGLOAD(&regs->mdio) & GRETH_MII_NVALID)) {
		return (GRETH_REGLOAD(&regs->mdio) >> 16) & 0xFFFF;
	} else {
		return -1;
	}
}

static void write_mii(int phyaddr, int regaddr, int data, volatile greth_regs * regs)
{
	while (GRETH_REGLOAD(&regs->mdio) & GRETH_MII_BUSY) {
	}

	GRETH_REGSAVE(&regs->mdio,
		      ((data & 0xFFFF) << 16) | ((phyaddr & 0x1F) << 11) |
		      ((regaddr & 0x1F) << 6) | 1);

	while (GRETH_REGLOAD(&regs->mdio) & GRETH_MII_BUSY) {
	}

}

/* 
 * init/start hardware and allocate descriptor buffers for rx side
 */
int greth_init(greth_priv* greth)
{
	int i;
	greth_regs *regs = greth->regs;
	unsigned long rxbd_phy, txbd_phy, rxbuf_phy, txbuf_phy;
	cap_t rxbuf_cap, txbuf_cap;

	debug("greth_init\n");

	if (!greth->rxbd_base) {

		/* allocate descriptors */
		greth->rxbd_base = (greth_bd *)
		    memalign(0x1000, GRETH_RXBD_CNT * sizeof(greth_bd));
		greth->txbd_base = (greth_bd *)
		    memalign(0x1000, GRETH_TXBD_CNT * sizeof(greth_bd));

		memset(greth->rxbd_base, 0, GRETH_RXBD_CNT * sizeof(greth_bd));
		memset(greth->txbd_base, 0, GRETH_TXBD_CNT * sizeof(greth_bd));

		/* allocate buffers to all descriptors  */
		rxbuf_cap = usys_create_pmo(GRETH_RXBUF_EFF_SIZE * GRETH_RXBD_CNT, PMO_DATA);
		greth->rxbuf_base = chcore_auto_map_pmo(rxbuf_cap, GRETH_RXBUF_EFF_SIZE * GRETH_RXBD_CNT, PROT_READ | PROT_WRITE);
		if (!greth->rxbuf_base)
			return -EINVAL;

		txbuf_cap = usys_create_pmo(GRETH_TXBUF_SIZE * GRETH_TXBD_CNT, PMO_DATA);
		greth->txbuf_base = chcore_auto_map_pmo(txbuf_cap, GRETH_TXBUF_SIZE * GRETH_TXBD_CNT, PROT_READ | PROT_WRITE);
		if (!greth->txbuf_base) 
			return -EINVAL;
	}

	if(usys_get_phys_addr(greth->rxbd_base, &rxbd_phy))
		return -EINVAL;

	if(usys_get_phys_addr(greth->txbd_base, &txbd_phy))
		return -EINVAL;

	if(usys_get_phys_addr(greth->rxbuf_base, &rxbuf_phy))
		return -EINVAL;

	if(usys_get_phys_addr(greth->txbuf_base, &txbuf_phy))
		return -EINVAL;

	/* initate rx decriptors */
	for (i = 0; i < GRETH_RXBD_CNT; i++) {
		greth->rxbd_base[i].addr = rxbuf_phy + (GRETH_RXBUF_EFF_SIZE *i);
		debug("greth->rxbd_base[i].addr: %x\n",greth->rxbd_base[i].addr);

		/* enable desciptor & set wrap bit if last descriptor */
		if (i >= (GRETH_RXBD_CNT - 1)) {
			greth->rxbd_base[i].stat = GRETH_BD_EN | GRETH_BD_IE | GRETH_BD_WR;
		} else {
			greth->rxbd_base[i].stat = GRETH_BD_EN | GRETH_BD_IE;
		}
	}

	/* initiate indexes */
	greth->rxbd_curr = greth->rxbd_base;
	greth->rxbd_max = greth->rxbd_base + (GRETH_RXBD_CNT - 1);
	greth->txbd_max = greth->txbd_base + (GRETH_TXBD_CNT - 1);

	greth->tx_free = GRETH_TXBD_CNT;
	greth->tx_next = 0;
	greth->tx_last = 0;

	/* initate tx decriptors */
	for (i = 0; i < GRETH_TXBD_CNT; i++) {
		greth->txbd_base[i].addr = txbuf_phy + (GRETH_TXBUF_SIZE * i);
		debug("greth->txbd_base[i].addr: %x\n",greth->txbd_base[i].addr);
		/* enable desciptor & set wrap bit if last descriptor */
		if (i >= (GRETH_TXBD_CNT - 1)) {
			greth->txbd_base[i].stat = GRETH_BD_WR;
		} else {
			greth->txbd_base[i].stat = 0;
		}
	}

	/* Set pointer to tx/rx descriptor areas */
	GRETH_REGSAVE(&regs->rx_desc_p, rxbd_phy);
	GRETH_REGSAVE(&regs->tx_desc_p, txbd_phy);

	/* Enable Transmitter, GRETH will now scan descriptors for packets
	 * to transmitt */
	debug("greth_init: enabling receiver\n");
	GRETH_REGORIN(&regs->control, GRETH_RXI | GRETH_TXI);
	GRETH_REGORIN(&regs->control, GRETH_RXEN);
	return 0;
}

/* Initiate PHY to a relevant speed
 * return:
 *  - 0 = success
 *  - 1 = timeout/fail
 */
int greth_init_phy(greth_priv * dev)
{
	greth_regs *regs = dev->regs;
	int tmp, tmp1, tmp2;
	unsigned int start, timeout;
	int phyaddr = GRETH_PHY_ADR_DEFAULT;

	/* Save PHY Address */
	dev->phyaddr = phyaddr;
	debug("GRETH PHY ADDRESS: %d\n", phyaddr);

	/* X msecs to ticks */
	timeout = GRETH_PHY_TIMEOUT_MS * 1000;

	/* Get system current value
	 * Total timeout is 3s
	 */
	start = clock();

	/* get phy control register default values */
	while ((tmp = read_mii(phyaddr, 0, regs)) & 0x8000) {
		if (clock() - start > timeout) {
			debug("greth_init_phy: PHY read 1 failed\n");
			return 1;	/* Fail */
		}
	}

	/* reset PHY and wait for completion */
	write_mii(phyaddr, 0, 0x8000 | tmp, regs);

	while (((tmp = read_mii(phyaddr, 0, regs))) & 0x8000) {
		if (clock()-start  > timeout) {
			debug("greth_init_phy: PHY read 2 failed\n");
			return 1;	/* Fail */
		}
	}

	/* Check if PHY is autoneg capable and then determine operating
	 * mode, otherwise force it to 10 Mbit halfduplex
	 */
	dev->gb = 0;
	dev->fd = 0;
	dev->sp = 0;
	dev->auto_neg = 0;
	if (!((tmp >> 12) & 1)) {
		write_mii(phyaddr, 0, 0, regs);
	} else {
		/* wait for auto negotiation to complete and then check operating mode */
		dev->auto_neg = 1;
		while (!(((tmp = read_mii(phyaddr, 1, regs)) >> 5) & 1)) {
			if (clock()-start  > timeout) {
				printf("Auto negotiation timed out. "
				       "Selecting default config\n");
				tmp = read_mii(phyaddr, 0, regs);
				dev->gb = ((tmp >> 6) & 1)
				    && !((tmp >> 13) & 1);
				dev->sp = !((tmp >> 6) & 1)
				    && ((tmp >> 13) & 1);
				dev->fd = (tmp >> 8) & 1;
				goto auto_neg_done;
			}
		}
		if ((tmp >> 8) & 1) {
			tmp1 = read_mii(phyaddr, 9, regs);
			tmp2 = read_mii(phyaddr, 10, regs);
			if ((tmp1 & GRETH_MII_EXTADV_1000FD) &&
			    (tmp2 & GRETH_MII_EXTPRT_1000FD)) {
				dev->gb = 1;
				dev->fd = 1;
			}
			if ((tmp1 & GRETH_MII_EXTADV_1000HD) &&
			    (tmp2 & GRETH_MII_EXTPRT_1000HD)) {
				dev->gb = 1;
				dev->fd = 0;
			}
		}
		if ((dev->gb == 0) || ((dev->gb == 1) && (dev->gbit_mac == 0))) {
			tmp1 = read_mii(phyaddr, 4, regs);
			tmp2 = read_mii(phyaddr, 5, regs);
			if ((tmp1 & GRETH_MII_100TXFD) &&
			    (tmp2 & GRETH_MII_100TXFD)) {
				dev->sp = 1;
				dev->fd = 1;
			}
			if ((tmp1 & GRETH_MII_100TXHD) &&
			    (tmp2 & GRETH_MII_100TXHD)) {
				dev->sp = 1;
				dev->fd = 0;
			}
			if ((tmp1 & GRETH_MII_10FD) && (tmp2 & GRETH_MII_10FD)) {
				dev->fd = 1;
			}
			if ((dev->gb == 1) && (dev->gbit_mac == 0)) {
				dev->gb = 0;
				dev->fd = 0;
				write_mii(phyaddr, 0, dev->sp << 13, regs);
			}
		}

	}
      auto_neg_done:
	debug("%s GRETH Ethermac at [0x%x] irq %d. Running \
		%d Mbps %s duplex\n", dev->gbit_mac ? "10/100/1000" : "10/100", (unsigned int)(regs), (unsigned int)(dev->irq), dev->gb ? 1000 : (dev->sp ? 100 : 10), dev->fd ? "full" : "half");
	/* Read out PHY info if extended registers are available */
	if (tmp & 1) {
		tmp1 = read_mii(phyaddr, 2, regs);
		tmp2 = read_mii(phyaddr, 3, regs);
		tmp1 = (tmp1 << 6) | ((tmp2 >> 10) & 0x3F);
		tmp = tmp2 & 0xF;

		tmp2 = (tmp2 >> 4) & 0x3F;
		debug("PHY: Vendor %x   Device %x    Revision %d\n", tmp1,
		       tmp2, tmp);
	} else {
		printf("PHY info not available\n");
	}

	/* set speed and duplex bits in control register */
	GRETH_REGORIN(&regs->control,
		      (dev->gb << 8) | (dev->sp << 7) | (dev->fd << 4));

	return 0;
}

void greth_halt(greth_priv *greth)
{
	greth_regs *regs;
	int i;

	debug("greth_halt\n");

	if (!greth)
		return;

	regs = greth->regs;
	if (!regs)
		return;

	/* disable receiver/transmitter by clearing the enable bits */
	GRETH_REGANDIN(&regs->control, ~(GRETH_RXEN | GRETH_TXEN));

	/* reset rx/tx descriptors */
	if (greth->rxbd_base) {
		for (i = 0; i < GRETH_RXBD_CNT; i++) {
			greth->rxbd_base[i].stat =
			    (i >= (GRETH_RXBD_CNT - 1)) ? GRETH_BD_WR : 0;
		}
	}

	if (greth->txbd_base) {
		for (i = 0; i < GRETH_TXBD_CNT; i++) {
			greth->txbd_base[i].stat =
			    (i >= (GRETH_TXBD_CNT - 1)) ? GRETH_BD_WR : 0;
		}
	}
}

static void greth_clean_tx(greth_priv* greth){
	greth_bd *bdp;
	unsigned int status;

	while (1) {
		bdp = greth->txbd_base + greth->tx_last;
		GRETH_REGSAVE(&greth->regs->status, GRETH_INT_TE | GRETH_INT_TX);

		status = GRETH_REGLOAD(&bdp->stat);

		if (unlikely(status & GRETH_BD_EN)){
			debug("break from status: %u\n", status);
			break;
		}

		if (greth->tx_free == GRETH_TXBD_CNT)
			break;

		/* Check status for errors */
		if (unlikely(status & GRETH_TXBD_STATUS)) {
			greth->stats.tx_errors++;
			if (status & GRETH_TXBD_ERR_AL)
				greth->stats.tx_limit_errors++;
			if (status & GRETH_TXBD_ERR_UE)
				greth->stats.tx_underrun_errors++;
			if (status & GRETH_TXBD_ERR_LC)
				greth->stats.tx_latecol_errors++;
		}
		greth->stats.tx_packets++;
		greth->tx_last = NEXT_TX(greth->tx_last);
		greth->tx_free++;
	}
}

int greth_send(greth_priv* greth, void *eth_data, int data_length)
{
	greth_regs *regs = greth->regs;
	greth_bd *txbd;
	void *txbuf;
	unsigned int status;

	/* get tx buffer to use */
	txbuf = greth->txbuf_base + greth->tx_next * GRETH_TXBUF_SIZE;

	/* copy data info buffer */
	memcpy((char *)txbuf, (char *)eth_data, data_length);

	/* get descriptor to use */
	txbd = greth->txbd_base + greth->tx_next;

	/* setup descriptor to wrap around to it self */
	txbd->stat = GRETH_BD_EN | GRETH_BD_IE | data_length;

	if (greth->tx_next == (GRETH_TXBD_CNT - 1)) {
		txbd->stat |= GRETH_BD_WR;
	}

	debug("txbuf addr: %x\n", (unsigned) txbuf);
	debug("txbd addr: %x\n", (unsigned) txbd);
	debug("txbd stat addr: %x\n", (unsigned)(txbd->stat));
	debug("txbd addr addr: %x\n", (unsigned)(txbd->addr));

	greth->tx_next = NEXT_TX(greth->tx_next);
	greth->tx_free--;

	/* initate send by enabling transmitter */
	GRETH_REGORIN(&regs->control, GRETH_TXEN);

	if (unlikely(greth->tx_free <= 0)) {
		while ((status = GRETH_REGLOAD(&txbd->stat)) & GRETH_BD_EN)
			;
		greth_clean_tx(greth);
	}

	/* return succefully */
	return 0;
}

int eth_send(void* greth, void *packet, int length)
{
    if (length > GRETH_TXBUF_SIZE) {
        return -1;
    }

	return greth_send((greth_priv *)greth, packet, length);
}

static void eth_save_packet(void *packet, int length)
{
	char *p = packet;
	int i;

	if ((eth_rcv_last + 1) % GRETH_RXBD_CNT == eth_rcv_current)
		return;

	if (PKTSIZE < length)
		return;

	for (i = 0; i < length; i++)
		eth_rcv_bufs[eth_rcv_last].data[i] = p[i];

	eth_rcv_bufs[eth_rcv_last].length = length;
	eth_rcv_last = (eth_rcv_last + 1) % GRETH_RXBD_CNT;
}

int greth_recv(greth_priv* greth)
{
	greth_regs *regs = greth->regs;
	greth_bd *rxbd;
	unsigned int status, len = 0, bad;
	char *d;
	int enable = 0;
	int i;

	/* Receive all packet in buffer area, but clear as many error packets as there are
	 * available.
	 */
	while (1) {
		/* current receive descriptor */
		rxbd = greth->rxbd_curr;

		/* get status of next received packet */
		status = GRETH_REGLOAD(&rxbd->stat);

		bad = 0;

		/* stop if no more packets received */
		if (status & GRETH_BD_EN) {
			goto done;
		}

		debug("greth_recv: packet 0x%x, 0x%x, len: %d\n",
		       (unsigned int)rxbd, status, status & GRETH_BD_LEN);

		/* Check status for errors.
		 */
		if (status & GRETH_RXBD_ERR_FT) {
			greth->stats.rx_length_errors++;
			bad = 1;
		}
		if (status & (GRETH_RXBD_ERR_AE | GRETH_RXBD_ERR_OE)) {
			greth->stats.rx_frame_errors++;
			bad = 1;
		}
		if (status & GRETH_RXBD_ERR_CRC) {
			greth->stats.rx_crc_errors++;
			bad = 1;
		}
		if (bad) {
			greth->stats.rx_errors++;
			printf
			    ("greth_recv: Bad packet (%d, %d, %d, 0x%08x, %d)\n",
			     greth->stats.rx_length_errors,
			     greth->stats.rx_frame_errors,
			     greth->stats.rx_crc_errors, status,
			     greth->stats.rx_packets);
			/* print all rx descriptors */
			for (i = 0; i < GRETH_RXBD_CNT; i++) {
				printf("[%d]: Stat=0x%x, Addr=0x%x\n", i,
				       GRETH_REGLOAD(&greth->rxbd_base[i].stat),
				       GRETH_REGLOAD(&greth->rxbd_base[i].addr));
			}
		} else {
			/* Process the incoming packet. */
			len = status & GRETH_BD_LEN;
			d = (char *)((unsigned long)greth->rxbuf_base + (GRETH_RXBUF_EFF_SIZE * ((unsigned long)greth->rxbd_curr - (unsigned long)greth->rxbd_base) / sizeof(greth_bd)));

			debug
			    ("greth_recv: new packet, length: %d. data: %x %x %x %x %x %x %x %x\n",
			     len, d[0], d[1], d[2], d[3], d[4], d[5], d[6],
			     d[7]);

			/* flush all data cache to make sure we're not reading old packet data */
			// sparc_dcache_flush_all();

			/* pass packet on to network subsystem */
			if (len >= ETHER_HDR_SIZE)
				eth_save_packet((void *)d, len);

			/* bump stats counters */
			greth->stats.rx_packets++;
		}

		/* reenable descriptor to receive more packet with this descriptor, wrap around if needed */
		rxbd->stat =
		    GRETH_BD_EN | GRETH_BD_IE | 
		    (((unsigned int)greth->rxbd_curr >=
		      (unsigned int)greth->rxbd_max) ? GRETH_BD_WR : 0);

		enable = 1;

		/* increase index */
		greth->rxbd_curr =
		    ((unsigned int)greth->rxbd_curr >=
		     (unsigned int)greth->rxbd_max) ? greth->
		    rxbd_base : (greth->rxbd_curr + 1);
	}

	if (enable) {
		GRETH_REGORIN(&regs->control, GRETH_RXEN);
	}
	done:
	/* return positive length of packet or 0 if non received */
	return len;
}

int eth_receive(void* greth, void *packet, int length)
{
	char *p = packet;
	int i;

	if (eth_rcv_current == eth_rcv_last) {
			return -1;
	}

	length = MIN(eth_rcv_bufs[eth_rcv_current].length, length);

	for (i = 0; i < length; i++)
		p[i] = eth_rcv_bufs[eth_rcv_current].data[i];

	eth_rcv_current = (eth_rcv_current + 1) % GRETH_RXBD_CNT;
	return length;
}

void handle_greth_irq_internal(greth_priv* greth)
{
	u32 status, ctrl;

	/* Get the interrupt events that caused us to be here. */
	status = GRETH_REGLOAD(&greth->regs->status);

	/* Must see if interrupts are enabled also, INT_TX|INT_RX flags may be
	 * set regardless of whether IRQ is enabled or not. Especially
	 * important when shared IRQ.
	 */
	ctrl = GRETH_REGLOAD(&greth->regs->control);

	/* Handle rx and tx interrupts through poll */
	if (((status & (GRETH_INT_RE | GRETH_INT_RX)) && (ctrl & GRETH_RXI)) ||
	    ((status & (GRETH_INT_TE | GRETH_INT_TX)) && (ctrl & GRETH_TXI))) {

		/* Disable interrupts and schedule poll() */
		// GRETH_REGANDIN(grethy->regs->control, ~(GRETH_RXI|GRETH_TXI));
		greth_clean_tx(greth);
		greth_recv(greth);
	}
}

void *handle_greth_irq(void* arg)
{
	greth_priv* greth = (greth_priv*) arg;
	cap_t irq_cap;

	irq_cap = usys_irq_register(GRETH_IRQ);
	if (irq_cap < 0){
		printf("register irq num failed");
	}

	while (1) {
		usys_irq_wait(irq_cap, true);
		handle_greth_irq_internal(greth);
	}
}

void greth_set_hwaddr(greth_priv * greth, unsigned char *mac)
{
	/* save new MAC address */
	greth->hwaddr[0] = mac[0];
	greth->hwaddr[1] = mac[1];
	greth->hwaddr[2] = mac[2];
	greth->hwaddr[3] = mac[3];
	greth->hwaddr[4] = mac[4];
	greth->hwaddr[5] = mac[5];
	greth->regs->esa_msb = (mac[0] << 8) | mac[1];
	greth->regs->esa_lsb =
	    (mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) | mac[5];

	debug("GRETH: New MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int init_io_mapping(void)
{
	int ret = 0;
	cap_t io_pmo_cap;

	io_pmo_cap = usys_create_device_pmo(
		APB_BASE, PAGE_SIZE);
	ret = usys_map_pmo(
		SELF_CAP, io_pmo_cap, USER_APB_BASE, VM_READ | VM_WRITE);
	return ret;
}

void *greth_initialize(unsigned char* mac_addr)
{
	int i;
	char *addr_str, *end;
	
	if (init_io_mapping()){
		printf("io mapping failed\n");
		return NULL;
	}

	greth_priv *greth = (greth_priv *)malloc(sizeof(greth_priv));

	if (!greth) {
		printf("greth malloc failed, no memory!\n");
		return NULL;
	}

	debug("Scanning for GRETH\n");

	memset(greth, 0, sizeof(greth_priv));

	greth->regs = (greth_regs *) GRETH_BASE;
	greth->irq = GRETH_IRQ;
	greth->m_link = 0;

	/* Reset Core */
	GRETH_REGSAVE(&greth->regs->control, GRETH_RESET);

	/* Wait for core to finish reset cycle */
	while (GRETH_REGLOAD(&greth->regs->control) & GRETH_RESET) ;

	/* Get the phy address which assumed to have been set
	   correctly with the reset value in hardware */
	greth->phyaddr = (GRETH_REGLOAD(&greth->regs->mdio) >> 11) & 0x1F;

	/* Check if mac is gigabit capable */
	greth->gbit_mac = (GRETH_REGLOAD(&greth->regs->control) >> 27) & 1;

	GRETH_REGORIN(&greth->regs->control, GRETH_DDD);

	/* initiate PHY, select speed/duplex depending on connected PHY */
	if (greth_init_phy(greth)) {
		/* Failed to init PHY (timedout) */
		debug("GRETH[%p]: Failed to init PHY\n", greth->regs);
		return NULL;
	}

	addr_str = HWADDR;
	/* Get MAC address */	
	if (addr_str != NULL) {
		for (i = 0; i < 6; i++) {
			mac_addr[i] =
			    addr_str ? strtoul(addr_str, &end, 16) : 0;
			if (addr_str) {
				addr_str = (*end) ? end + 1 : end;
			}
			printf("addr: %d\n", mac_addr[i]);
		}
	} else {
		/* No ethaddr set */
		return NULL;
	}

	/* set and remember MAC address */
	greth_set_hwaddr(greth, mac_addr);

	greth->m_link = 1;

	if (greth_init(greth))
		printf("greth init failed\n");

	debug("GRETH[%p]: Initialized successfully\n", greth->regs);
	return (void *)greth;
}
