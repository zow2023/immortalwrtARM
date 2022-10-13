/* Copyright Statement:
 *
 * This software/firmware and related documentation ("MediaTek Software") are
 * protected under relevant copyright laws. The information contained herein is
 * confidential and proprietary to MediaTek Inc. and/or its licensors. Without
 * the prior written permission of MediaTek inc. and/or its licensors, any
 * reproduction, modification, use or disclosure of MediaTek Software, and
 * information contained herein, in whole or in part, shall be strictly
 * prohibited.
 *
 * Copyright  (C) 2019-2020  MediaTek Inc. All rights reserved.
 *
 * BY OPENING THIS FILE, RECEIVER HEREBY UNEQUIVOCALLY ACKNOWLEDGES AND AGREES
 * THAT THE SOFTWARE/FIRMWARE AND ITS DOCUMENTATIONS ("MEDIATEK SOFTWARE")
 * RECEIVED FROM MEDIATEK AND/OR ITS REPRESENTATIVES ARE PROVIDED TO RECEIVER
 * ON AN "AS-IS" BASIS ONLY. MEDIATEK EXPRESSLY DISCLAIMS ANY AND ALL
 * WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE OR
 * NONINFRINGEMENT. NEITHER DOES MEDIATEK PROVIDE ANY WARRANTY WHATSOEVER WITH
 * RESPECT TO THE SOFTWARE OF ANY THIRD PARTY WHICH MAY BE USED BY,
 * INCORPORATED IN, OR SUPPLIED WITH THE MEDIATEK SOFTWARE, AND RECEIVER AGREES
 * TO LOOK ONLY TO SUCH THIRD PARTY FOR ANY WARRANTY CLAIM RELATING THERETO.
 * RECEIVER EXPRESSLY ACKNOWLEDGES THAT IT IS RECEIVER'S SOLE RESPONSIBILITY TO
 * OBTAIN FROM ANY THIRD PARTY ALL PROPER LICENSES CONTAINED IN MEDIATEK
 * SOFTWARE. MEDIATEK SHALL ALSO NOT BE RESPONSIBLE FOR ANY MEDIATEK SOFTWARE
 * RELEASES MADE TO RECEIVER'S SPECIFICATION OR TO CONFORM TO A PARTICULAR
 * STANDARD OR OPEN FORUM. RECEIVER'S SOLE AND EXCLUSIVE REMEDY AND MEDIATEK'S
 * ENTIRE AND CUMULATIVE LIABILITY WITH RESPECT TO THE MEDIATEK SOFTWARE
 * RELEASED HEREUNDER WILL BE, AT MEDIATEK'S OPTION, TO REVISE OR REPLACE THE
 * MEDIATEK SOFTWARE AT ISSUE, OR REFUND ANY SOFTWARE LICENSE FEES OR SERVICE
 * CHARGE PAID BY RECEIVER TO MEDIATEK FOR SUCH MEDIATEK SOFTWARE AT ISSUE.
 *
 * The following software/firmware and/or related documentation ("MediaTek
 * Software") have been modified by MediaTek Inc. All revisions are subject to
 * any receiver's applicable license agreements with MediaTek Inc.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/list.h>
#include <linux/if_ether.h>
#include <linux/etherdevice.h>
#include <net/netlink.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/kobject.h>
#include <linux/version.h>
#include <linux/jhash.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_LICENSE("Dual BSD/GPL");

#define MTFWD_VERSION "1.0"

//#define CFG_SESSION_BASED_FWD 1
#define LOOP_DETECT_IN_DAEMON 0

#define NETLINK_EXT 25
#define MAX_ENTRY_CNT 256
#define MAX_MSGSIZE 1024
#define MAC_ADDR_LEN	6

/*Macro definition*/
#define HASH_TABLE_SIZE 256
#define MAC_ADDR_HASH(addr) (addr[0]^addr[1]^addr[2]^addr[3]^addr[4]^addr[5])
#define MAC_ADDR_HASH_INDEX(addr) (MAC_ADDR_HASH(addr) & (HASH_TABLE_SIZE - 1))
#define MAX(a, b) ((a > b) ? (a) : (b))
#define MIN(a, b) ((a < b) ? (a) : (b))

#define DBG_LVL_OFF	0
#define DBG_LVL_ERROR	1
#define DBG_LVL_WARN	2
#define DBG_LVL_TRACE	3
#define DBG_LVL_INFO	4
#define DBG_LVL_LOUD	5


unsigned long dbg_level = DBG_LVL_ERROR;

#define DBGPRINT_RAW(Level, Fmt)    \
do{                                   \
	unsigned long __gLevel = (Level) & 0xff;\
	if (__gLevel <= dbg_level)      \
	{                               \
		printk Fmt;               \
	}                               \
}while(0)

#define DBGPRINT(Level, Fmt)    DBGPRINT_RAW(Level, Fmt)

enum link_status {
	LINK_UNKNOWN = 0,
	LINK_UP,
	LINK_DOWN,
};

enum nl_msg_id {
	FWD_CMD_ADD_LINK = 1,
	FWD_CMD_DEL_LINK,

	FWD_CMD_ADD_TX_SRC = 3,
	FWD_CMD_DEL_TX_SRC,

	FWD_CMD_ADD_PATH_INFO,
	FWD_CMD_DEL_PATH_INFO,

	FWD_CMD_ADD_SESSION_ENTRY,
	FWD_CMD_DEL_SESSION_ENTRY,

	FWD_CMD_MAX
};

/*Data structure definition.*/
struct wifi_link{
	char name[IFNAMSIZ];
	char blk_mc;		/*mc pkt 0:not block, 1: block*/
};

struct mac_addr {
	unsigned char mac[MAC_ADDR_LEN];
};

struct fwd_path {
	char s_if[IFNAMSIZ];
	char s_lk_stat;	/*0:unknown, 1:linkup, 2:link down*/
	char d_if[IFNAMSIZ];
	char d_lk_stat;	/*0:unknown, 1:linkup, 2:link down*/
};

struct session_key {
	unsigned int s_ip;
	unsigned int d_ip;
	union {
		unsigned short ports[2];
		unsigned int port;
	};
	unsigned char proto;
};

struct session_ctrl {
	struct session_key key;
	char d_if[IFNAMSIZ];
};

struct link_entry {
	struct list_head list;
	struct rcu_head rcu;
	struct net_device *dev;
	char blk_mc;		/*mc pkt 0:not block, 1: block*/
};

struct tx_src_entry {
	struct list_head list;
	struct rcu_head rcu;
	unsigned char mac[MAC_ADDR_LEN];
};

struct path_info_entry {
	struct list_head list;
	struct rcu_head rcu;
	struct net_device *s_dev;
	struct net_device *d_dev;
	char s_lk_stat;	/*0:unknown, 1:linkup, 2:link down*/
	char d_lk_stat;	/*0:unknown, 1:linkup, 2:link down*/
};

struct session_based_entry {
	struct list_head list;
	struct rcu_head rcu;
	struct session_key key;
	struct net_device *d;
	unsigned long long stat;
};

/*Global variable*/
int link_tbl_cnt = 0;
spinlock_t link_tbl_lock;
struct list_head link_tbl[HASH_TABLE_SIZE];

int tx_src_tbl_cnt = 0;
spinlock_t tx_src_tbl_lock;
struct list_head tx_src_tbl[HASH_TABLE_SIZE];

int session_tbl_cnt = 0;
spinlock_t session_tbl_lock;
struct list_head session_tbl[HASH_TABLE_SIZE];

int path_active_cnt = 0;
spinlock_t path_tbl_lock;
struct list_head path_tbl;

struct sock *nl_sk;

char is_hk_ops_api = 0;

void check_if_register_nf_hook_ops(void);
void hex_dump(char *str, unsigned char *buf, unsigned int len)
{
	unsigned char *pt;
	int x;
	unsigned char tmp[512] = {0};

	if (dbg_level < DBG_LVL_TRACE)
		return ;

	if(len > 200)
		return ;

	pt = buf;
	memset(tmp, 0, 512);
	sprintf(tmp, "%s: %p, len = %d\n", str,  buf, len);
	for (x = 0; x < len; x++) {
		if (x % 16 == 0)
			sprintf(tmp+strlen(tmp), "0x%04x : ", x);
		sprintf(tmp+strlen(tmp), "%02x ", ((unsigned char)pt[x]));
		if (x%16 == 15)
			sprintf(tmp+strlen(tmp), "\n");

	}
	DBGPRINT(DBG_LVL_INFO, ("%s \n", tmp));
}

struct net_device *mt_dev_get_by_name(const char *name)
{
	struct net_device *dev;

	dev = dev_get_by_name(&init_net, name);

	if (dev)
		dev_put(dev);

	return dev;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
unsigned int fwd_hook_pre_routing(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
#else
unsigned int fwd_hook_pre_routing(unsigned int hooknum,
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
#endif
{
	const struct net_device *indev = NULL;
	struct ethhdr *hdr = eth_hdr(skb);
	struct link_entry *lk_pos;
	struct tx_src_entry *tx_src_pos;
	int hash_idx;
	char is_from_bh;


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
	indev = state->in;
#else
	indev = in;
#endif
	if (link_tbl_cnt < 1)
		return NF_ACCEPT;

	DBGPRINT(DBG_LVL_INFO, ("pre, recv on %s, DA:%pM, SA:%pM; type:%x\n",
		indev->name, hdr->h_dest, hdr->h_source, ntohs(hdr->h_proto)));

	if (likely(skb->protocol != htons(0x893A))) {
		/*loop pkt check, including bc/mc pkt*/
		if (unlikely(hdr->h_dest[0]&1)) {
#if LOOP_DETECT_IN_DAEMON
			hash_idx = MAC_ADDR_HASH_INDEX(indev->dev_addr);
			rcu_read_lock();
			list_for_each_entry_rcu(lk_pos, &link_tbl[hash_idx], list) {
				if (lk_pos->dev == indev && lk_pos->blk_mc) {
					rcu_read_unlock();
					return NF_DROP;
				}
			}
			rcu_read_unlock();
#else

			is_from_bh = 0;
			hash_idx = MAC_ADDR_HASH_INDEX(indev->dev_addr);
			rcu_read_lock();
			list_for_each_entry_rcu(lk_pos,	&link_tbl[hash_idx], list) {
				if (lk_pos->dev == indev) {
					is_from_bh = 1;
					break;
				}
			}
			rcu_read_unlock();

			if (is_from_bh) {
				hash_idx = MAC_ADDR_HASH_INDEX(hdr->h_source);
				rcu_read_lock();
				list_for_each_entry_rcu(tx_src_pos, &tx_src_tbl[hash_idx], list) {
					if (!memcmp(tx_src_pos->mac, hdr->h_source, ETH_ALEN)) {
						/*mc pkt was sent out by this device, loop detected.*/
						rcu_read_unlock();
						return NF_DROP;
					}
				}
				rcu_read_unlock();
			}
#endif
		}
	}

#if 0
	hash_idx = MAC_ADDR_HASH_INDEX(hdr->h_source);
	rcu_read_lock();
	list_for_each_entry_rcu(tx_src_pos, &tx_src_tbl[hash_idx], list) {
		if (!memcmp(tx_src_pos->mac, hdr->h_source, ETH_ALEN)) {
			DBGPRINT(DBG_LVL_WARN, (">>>>>>>pre, recv own address as source on %s, DA:%pM, SA:%pM; type:%x, drop it.\n",
				indev->name, hdr->h_dest, hdr->h_source, ntohs(hdr->h_proto)));
			hex_dump("pkt", (unsigned char *)hdr, 48);
			rcu_read_unlock();
			return NF_DROP;
		}
	}
	rcu_read_unlock();
#endif
	return NF_ACCEPT;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
unsigned int fwd_hook_forwarding(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
#else
unsigned int fwd_hook_forwarding(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#endif
{
	const struct net_device *indev = NULL;
	const struct net_device *outdev = NULL;
	struct path_info_entry *pos, *p_src, *p_dst;
	struct ethhdr *hdr = eth_hdr(skb);
	char src_is_apcli, dest_is_apcli;

#ifdef CFG_SESSION_BASED_FWD
	struct session_based_entry *s_pos;
	struct iphdr *iph;
	struct tcphdr *th = NULL;
	struct udphdr *uh = NULL;
	struct session_key;
	unsigned int port = 0;
	int hash_idx;
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
	indev = state->in;
	outdev = state->out;
#else
	indev = in;
	outdev = out;
#endif

	if (link_tbl_cnt <= 1)
		return NF_ACCEPT;

	DBGPRINT(DBG_LVL_INFO, (">>>>>>>fwd, from %s to %s, DA:%pM, SA:%pM, type:%x\n",
		indev->name, outdev->name, hdr->h_dest, hdr->h_source, ntohs(hdr->h_proto)));
	/*hex_dump("pkt", (unsigned char *)hdr, 48);*/

	if (unlikely(skb->protocol != htons(0x893A))) {
#ifdef CFG_SESSION_BASED_FWD
		/*session based forwarding first.*/
		if (skb->protocol == ETH_P_IP) {
			iph = ip_hdr(skb);
			if (iph->protocol == IPPROTO_TCP) {
				th = tcp_hdr(skb);
				port = th->source & th->dest<<16;
			} else if (iph->protocol == IPPROTO_UDP) {
				uh = udp_hdr(skb);
				port = uh->source & uh->dest<<16;
			}
			if (th || uh) {
				hash_idx = jhash_3words(iph->saddr, iph->daddr,
					port, 15) & (HASH_TABLE_SIZE - 1);
				DBGPRINT(DBG_LVL_ERROR, ("%d, %d, port %x, hash %d\n",
					iph->saddr, iph->daddr, port, hash_idx));
				rcu_read_lock();
				list_for_each_entry_rcu(s_pos, &session_tbl[hash_idx], list) {
					if (s_pos->key.s_ip == iph->saddr &&
						s_pos->key.d_ip == iph->daddr &&
						s_pos->key.port == port &&
						s_pos->key.proto == iph->protocol) {
						skb->dev = s_pos->d;
						rcu_read_unlock();
						return NF_ACCEPT;
					}
				}
				rcu_read_unlock();
			}
		}
#endif
		p_src = NULL;
		p_dst = NULL;
		rcu_read_lock();
		list_for_each_entry_rcu(pos, &path_tbl, list) {
			if (pos->s_dev == indev)
				p_src = pos;
			else if (pos->d_dev == outdev)
				p_dst = pos;

			if (p_src && p_dst && p_src->d_dev != p_dst->d_dev) {
				/*drop redundant bc/mc pkt in dbdc mode.*/
				if (unlikely(hdr->h_dest[0]&1)) {
					rcu_read_unlock();
					return NF_DROP;
				}

				if (p_src->d_lk_stat == LINK_UP)
					skb->dev = p_src->d_dev;
				rcu_read_unlock();
				return NF_ACCEPT;
			}
		}
		rcu_read_unlock();

		/*if mc/bc was received in an apcli and be forwarded to another apcli interface, drop it*/
		if (unlikely(hdr->h_dest[0]&1)) {
			rcu_read_lock();
			src_is_apcli = 0;
			dest_is_apcli = 0;
			list_for_each_entry_rcu(pos, &path_tbl, list) {
				if (!memcmp(pos->d_dev->dev_addr, indev->dev_addr, MAC_ADDR_LEN))
					src_is_apcli = 1;
				else if (!memcmp(pos->d_dev->dev_addr, outdev->dev_addr, MAC_ADDR_LEN))
					dest_is_apcli = 1;

				if (src_is_apcli && dest_is_apcli) {
					rcu_read_unlock();
					return NF_DROP;
				}
			}
			rcu_read_unlock();
		}
	}
	return NF_ACCEPT;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
unsigned int fwd_hook_post_routing(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
#else
unsigned int fwd_hook_post_routing(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#endif
{
	struct ethhdr *hdr = eth_hdr(skb);
	const struct net_device *outdev = NULL;
#if LOOP_DETECT_IN_DAEMON
	struct link_entry *pos;
	int hash_idx;
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
	outdev = state->out;
#else
	outdev = out;
#endif

#if LOOP_DETECT_IN_DAEMON
	if ((hdr->h_dest[0]&1) && (skb->protocol != htons(0x893A))) {
		hash_idx = MAC_ADDR_HASH_INDEX(outdev->dev_addr);
		rcu_read_lock();
		list_for_each_entry_rcu(pos, &link_tbl[hash_idx], list) {
			if (pos->dev == outdev && pos->blk_mc) {
				rcu_read_unlock();
				DBGPRINT(DBG_LVL_TRACE, ("post, DA:%pM, SA:%pM; type:%x.\n",
					hdr->h_dest, hdr->h_source, ntohs(hdr->h_proto)));
				return NF_DROP;
			}
		}
		rcu_read_unlock();
	}
#endif

	DBGPRINT(DBG_LVL_INFO, (">>>>>>>post, send pkt on %s, DA:%pM, SA:%pM; type:%x\n",
		outdev->name, hdr->h_dest, hdr->h_source, ntohs(hdr->h_proto)));
	/*hex_dump("pkt", (unsigned char *)hdr, 48);*/

	return NF_ACCEPT;
}


int add_tx_src_entry(struct mac_addr *m)
{
	struct tx_src_entry *pos;
	int hash_idx;

	if (m == NULL) {
		DBGPRINT(DBG_LVL_ERROR, ("no mac address available.\n"));
		return -1;
	}
	hash_idx = MAC_ADDR_HASH_INDEX(m->mac);

	spin_lock(&tx_src_tbl_lock);
	list_for_each_entry(pos, &tx_src_tbl[hash_idx], list) {
		if (!memcmp(pos->mac, m->mac, MAC_ADDR_LEN)) {
			DBGPRINT(DBG_LVL_ERROR, ("Mac: %pM was aleady existed.\n", m->mac));
			break;
		}
	}

	if (&pos->list == &tx_src_tbl[hash_idx] && tx_src_tbl_cnt <= MAX_ENTRY_CNT) {
		/*add a new entry to table.*/
		pos = kmalloc(sizeof(struct tx_src_entry), GFP_ATOMIC);
		if (pos == NULL) {
			spin_unlock(&tx_src_tbl_lock);
			DBGPRINT(DBG_LVL_ERROR, ("add tx src, memory allocate failed.\n"));
			return -1;
		}

		memset(pos, 0, sizeof(struct tx_src_entry));
		memcpy(pos->mac, m->mac, MAC_ADDR_LEN);

		list_add_tail_rcu(&pos->list, &tx_src_tbl[hash_idx]);
		tx_src_tbl_cnt++;
		DBGPRINT(DBG_LVL_ERROR, ("add tx_src: %pM\n", m->mac));
	} else if( tx_src_tbl_cnt > MAX_ENTRY_CNT)
		DBGPRINT(DBG_LVL_ERROR, ("tx_src_tbl_cnt(%d) > MAX_ENTRY_CNT(%d)\n",
			tx_src_tbl_cnt, MAX_ENTRY_CNT));

	spin_unlock(&tx_src_tbl_lock);
	return 0;
}

void free_src_entry(struct rcu_head *head)
{
	struct tx_src_entry *t =
		container_of(head, struct tx_src_entry, rcu);
	kfree(t);
}

int del_tx_src_entry(struct mac_addr *m)
{
	struct tx_src_entry *pos, *n;
	int hash_idx;

	if (m == NULL) {
		DBGPRINT(DBG_LVL_ERROR, ("no mac address available.\n"));
		return -1;
	}
	hash_idx = MAC_ADDR_HASH_INDEX(m->mac);

	spin_lock(&tx_src_tbl_lock);
	list_for_each_entry_safe(pos, n, &tx_src_tbl[hash_idx], list) {
		if (!memcmp(pos->mac, m->mac, MAC_ADDR_LEN)) {
			DBGPRINT(DBG_LVL_ERROR, ("del tx_src:%pM\n", m->mac));
			list_del_rcu(&pos->list);
			tx_src_tbl_cnt--;
			call_rcu(&pos->rcu, free_src_entry);
		}
	}
	spin_unlock(&tx_src_tbl_lock);
	return 0;
}

int add_link_entry(struct wifi_link *lk)
{
	struct net_device *dev;
	struct link_entry *pos;
	int hash_idx;

	dev = mt_dev_get_by_name(lk->name);
	if (dev == NULL) {
		DBGPRINT(DBG_LVL_ERROR, ("no net device found for %s\n", lk->name));
		return -1;
	}

	hash_idx = MAC_ADDR_HASH_INDEX(dev->dev_addr);

	spin_lock(&link_tbl_lock);
	list_for_each_entry(pos, &link_tbl[hash_idx], list) {
		if (pos->dev == dev) {
			pos->blk_mc = lk->blk_mc;
			DBGPRINT(DBG_LVL_ERROR, ("update link %s, blk_mc:%d\n", lk->name, lk->blk_mc));
			break;
		}
	}

	if (&pos->list == &link_tbl[hash_idx] && link_tbl_cnt <= MAX_ENTRY_CNT) {
		/*add a new entry to table.*/
		pos = kmalloc(sizeof(struct link_entry), GFP_ATOMIC);
		if (pos == NULL) {
			spin_unlock(&link_tbl_lock);
			return -1;
		}

		memset(pos, 0, sizeof(struct link_entry));
		pos->dev = dev;
		pos->blk_mc = lk->blk_mc;

		list_add_tail_rcu(&pos->list, &link_tbl[hash_idx]);
		link_tbl_cnt++;

		DBGPRINT(DBG_LVL_ERROR, ("add link %s, blk_mc:%d, link_tbl_cnt=%d\n", lk->name, lk->blk_mc, link_tbl_cnt));
	}
	spin_unlock(&link_tbl_lock);

	check_if_register_nf_hook_ops();

	return 0;
}

void free_lk_entry(struct rcu_head *head)
{
	struct link_entry *blk =
		container_of(head, struct link_entry, rcu);
	kfree(blk);
}

int del_link_entry(struct wifi_link *lk)
{
	struct link_entry *pos, *n;
	struct net_device *dev;
	int hash_idx;

	dev = mt_dev_get_by_name(lk->name);
	if (dev == NULL) {
		DBGPRINT(DBG_LVL_ERROR, ("no net device found for %s\n", lk->name));
		return -1;
	}

	hash_idx = MAC_ADDR_HASH_INDEX(dev->dev_addr);

	spin_lock(&link_tbl_lock);
	list_for_each_entry_safe(pos, n, &link_tbl[hash_idx], list) {
		if (dev == pos->dev) {
			list_del_rcu(&pos->list);
			link_tbl_cnt--;
			call_rcu(&pos->rcu, free_lk_entry);
			DBGPRINT(DBG_LVL_ERROR, ("del link %s\n", lk->name));
		}
	}
	spin_unlock(&link_tbl_lock);

	check_if_register_nf_hook_ops();

	return 0;
}

int add_session_tbl_entry(struct session_ctrl *s)
{
	struct session_based_entry *pos;
	struct net_device *dst_dev;
	int hash_idx;

	dst_dev = mt_dev_get_by_name(s->d_if);
	if (dst_dev == NULL) {
		DBGPRINT(DBG_LVL_ERROR, ("no net device found for %s\n", s->d_if));
		return -1;
	}
	hash_idx = jhash_3words(s->key.s_ip, s->key.d_ip,
			s->key.port, 15) &
			(HASH_TABLE_SIZE - 1);

	DBGPRINT(DBG_LVL_ERROR, ("hash_idx add = %d\n", hash_idx));

	rcu_read_lock();
	list_for_each_entry_rcu(pos, &session_tbl[hash_idx], list) {
		if (pos->key.s_ip == s->key.s_ip && pos->key.d_ip == s->key.d_ip &&
			pos->key.port == s->key.port && pos->key.proto == s->key.proto) {
			pos->d = dst_dev;
			break;
		}
	}
	rcu_read_unlock();

	if (&pos->list == &session_tbl[hash_idx] && session_tbl_cnt <= MAX_ENTRY_CNT) {
		/*add a new entry to table.*/
		pos = kmalloc(sizeof(struct session_based_entry), GFP_ATOMIC);
		if (pos == NULL)
			return -1;

		memset(pos, 0, sizeof(struct session_based_entry));
		pos->key.s_ip = s->key.s_ip;
		pos->key.d_ip = s->key.d_ip;
		pos->key.port = s->key.port;
		pos->key.proto = s->key.proto;
		pos->d = dst_dev;
		pos->stat = 0;

		spin_lock(&session_tbl_lock);
		list_add_tail_rcu(&pos->list, &session_tbl[hash_idx]);
		spin_unlock(&session_tbl_lock);
		session_tbl_cnt++;

	}
	return 0;
}

void free_session_entry(struct rcu_head *head)
{
	struct session_based_entry *e =
		container_of(head, struct session_based_entry, rcu);
	kfree(e);
}

int del_session_tbl_entry(struct session_ctrl *s)
{
	struct session_based_entry *pos, *n;
	int hash_idx;

	hash_idx = jhash_3words(s->key.s_ip, s->key.d_ip,
			s->key.port, 15) &
			(HASH_TABLE_SIZE - 1);
	DBGPRINT(DBG_LVL_ERROR, ("hash_idx del = %d\n", hash_idx));

	spin_lock(&session_tbl_lock);
	list_for_each_entry_safe(pos, n, &session_tbl[hash_idx], list) {
		if (pos->key.s_ip == s->key.s_ip && pos->key.d_ip == s->key.d_ip &&
			pos->key.port == s->key.port && pos->key.proto == s->key.proto) {
			list_del_rcu(&pos->list);
			session_tbl_cnt--;
			call_rcu(&pos->rcu, free_session_entry);
			break;
		}
	}

	spin_unlock(&session_tbl_lock);
	return 0;
}

void free_path_entry(struct rcu_head *head)
{
	struct path_info_entry *p =
		container_of(head, struct path_info_entry, rcu);
	kfree(p);
}

int add_path_entry(struct fwd_path *p)
{
	struct net_device *s, *d;
	struct path_info_entry *pos;

	s = mt_dev_get_by_name(p->s_if);
	d = mt_dev_get_by_name(p->d_if);

	if (s == NULL || d == NULL) {
		DBGPRINT(DBG_LVL_ERROR, ("no net device found for %s or %s\n", p->s_if, p->d_if));
		return -1;
	}

	spin_lock(&path_tbl_lock);

	list_for_each_entry(pos, &path_tbl, list) {
		if (pos->s_dev == s && pos->d_dev == d) {
			pos->s_lk_stat = p->s_lk_stat;

			if (pos->d_lk_stat != p->d_lk_stat)
				pos->d_lk_stat = p->d_lk_stat;

			DBGPRINT(DBG_LVL_ERROR, ("update: %s(%s)->%s(%s), active path:%d\n",
				p->s_if, p->s_lk_stat==LINK_UP? "UP" : "DN",
				p->d_if, p->d_lk_stat==LINK_UP? "UP" : "DN", path_active_cnt));
			break;
		}
	}

	if (&pos->list == &path_tbl) {
		/*add a new entry to table.*/
		pos = kmalloc(sizeof(struct path_info_entry), GFP_ATOMIC);
		if (pos == NULL) {
			spin_unlock(&path_tbl_lock);
			return -1;
		}

		memset(pos, 0, sizeof(struct path_info_entry));
		pos->s_dev = s;
		pos->d_dev = d;
		pos->s_lk_stat = p->s_lk_stat;
		pos->d_lk_stat = p->d_lk_stat;
		list_add_tail_rcu(&pos->list, &path_tbl);

		if (p->d_lk_stat == LINK_UP)
			path_active_cnt++;

		DBGPRINT(DBG_LVL_ERROR, ("add new: %s(%s)->%s(%s), active path:%d\n",
			p->s_if, p->s_lk_stat==LINK_UP? "UP" : "DN",
			p->d_if, p->d_lk_stat==LINK_UP? "UP" : "DN", path_active_cnt));
	}
	spin_unlock(&path_tbl_lock);

	check_if_register_nf_hook_ops();

	return 0;
}

int del_path_entry(struct fwd_path *p)
{
	struct path_info_entry *pos, *n;
	struct net_device *s, *d;

	s = mt_dev_get_by_name(p->s_if);
	d = mt_dev_get_by_name(p->d_if);
	if (s == NULL || d == NULL) {
		DBGPRINT(DBG_LVL_ERROR, ("no net device found for %s or %s\n", p->s_if, p->d_if));
		return -1;
	}

	spin_lock(&path_tbl_lock);
	list_for_each_entry_safe(pos, n, &path_tbl, list) {
		if (pos->s_dev == s && pos->d_dev == d) {
			list_del_rcu(&pos->list);
			call_rcu(&pos->rcu, free_path_entry);
			path_active_cnt = MAX((path_active_cnt-1), 0);
			DBGPRINT(DBG_LVL_ERROR, ("del path: %s(%s)->%s(%s), active path:%d\n",
				p->s_if, p->s_lk_stat==LINK_UP? "UP" : "DN",
				p->d_if, p->d_lk_stat==LINK_UP? "UP" : "DN", path_active_cnt));
		}
	}
	spin_unlock(&path_tbl_lock);
	check_if_register_nf_hook_ops();

	return 0;
}

void recv_nlmsg(struct sk_buff *skb)
{
	int pid;
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	char *msg = NULL;

	if (nlh->nlmsg_len < NLMSG_HDRLEN || skb->len < nlh->nlmsg_len)
		return;

	msg = (char *)NLMSG_DATA(nlh);

	DBGPRINT(DBG_LVL_TRACE, ("receive msg: %02x", msg[0]));

	pid = nlh->nlmsg_pid;

	switch (msg[0]) {
	case FWD_CMD_ADD_LINK:
		add_link_entry((struct wifi_link *)&msg[1]);
		break;
	case FWD_CMD_DEL_LINK:
		del_link_entry((struct wifi_link *)&msg[1]);
		break;
	case FWD_CMD_ADD_TX_SRC:
		add_tx_src_entry((struct mac_addr *)&msg[1]);
		break;
	case FWD_CMD_DEL_TX_SRC:
		del_tx_src_entry((struct mac_addr *)&msg[1]);
		break;
	case FWD_CMD_ADD_PATH_INFO:
		add_path_entry((struct fwd_path *)&msg[1]);
		break;
	case FWD_CMD_DEL_PATH_INFO:
		del_path_entry((struct fwd_path *)&msg[1]);
		break;
	case FWD_CMD_ADD_SESSION_ENTRY:
		add_session_tbl_entry((struct session_ctrl *)&msg[1]);
		break;
	case FWD_CMD_DEL_SESSION_ENTRY:
		del_session_tbl_entry((struct session_ctrl *)&msg[1]);
		break;
	default:
		break;
	}
}

struct netlink_kernel_cfg nl_kernel_cfg = {
	.groups = 0,
	.flags = 0,
	.input = recv_nlmsg,
	.cb_mutex = NULL,
	.bind = NULL,
};

static struct nf_hook_ops hk_ops[] = {
	{
		.hook		= fwd_hook_pre_routing,
		.pf		= NFPROTO_BRIDGE,
		.hooknum	= NF_BR_PRE_ROUTING,
		.priority	= NF_BR_PRI_BRNF,
	},
	{
		.hook		= fwd_hook_forwarding,
		.pf		= NFPROTO_BRIDGE,
		.hooknum	= NF_BR_FORWARD,
		.priority	= NF_BR_PRI_BRNF,
	},
	{
		.hook		= fwd_hook_post_routing,
		.pf		= NFPROTO_BRIDGE,
		.hooknum	= NF_BR_POST_ROUTING,
		.priority	= NF_BR_PRI_BRNF,
	}
};

void check_if_register_nf_hook_ops(void)
{
	if ((link_tbl_cnt < 1 || path_active_cnt < 1) && is_hk_ops_api) {
		DBGPRINT(DBG_LVL_ERROR, ("nf_unregister_hooks()\n"));
		nf_unregister_net_hooks(&init_net, &hk_ops[0], ARRAY_SIZE(hk_ops));
		is_hk_ops_api = 0;
	} else if ((link_tbl_cnt >= 1 || path_active_cnt >= 1) && !is_hk_ops_api) {
		/*register hook function to bridge.*/
		int ret = nf_register_net_hooks(&init_net, &hk_ops[0], ARRAY_SIZE(hk_ops));
		if (ret < 0) {
			DBGPRINT(DBG_LVL_ERROR, ("register nf hook fail, ret = %d\n", ret));
			return ;
		}
		DBGPRINT(DBG_LVL_ERROR, ("nf_register_hooks()\n"));
		is_hk_ops_api = 1;
	}
}

static ssize_t fwd_show_setting(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	unsigned int i, n;
	struct link_entry *lk_pos;
	struct path_info_entry *p_pos;
	struct tx_src_entry *tx_pos;

	n = 0;
	sprintf(buf, "[mtfwd] client link table:\n");
	rcu_read_lock();
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		list_for_each_entry_rcu(lk_pos, &link_tbl[i], list) {
			sprintf(buf+strlen(buf), "\t%d: %s\n", n++, lk_pos->dev->name);
		}
	}
	rcu_read_unlock();

	n = 0;
	sprintf(buf+strlen(buf), "[mtfwd] fwd path table, active count:%d\n", path_active_cnt);
	rcu_read_lock();
	list_for_each_entry_rcu(p_pos, &path_tbl, list) {
		sprintf(buf+strlen(buf), "\t%d: %s(%s) --> %s(%s)\n", n++,
			p_pos->s_dev->name, p_pos->s_lk_stat==LINK_UP? "UP" : "DN",
			p_pos->d_dev->name, p_pos->d_lk_stat==LINK_UP? "UP" : "DN");
	}
	rcu_read_unlock();

	n = 0;
	sprintf(buf+strlen(buf), "[mtfwd] tx src table:\n");
	rcu_read_lock();
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		list_for_each_entry_rcu(tx_pos, &tx_src_tbl[i], list) {
			sprintf(buf+strlen(buf), "\t %d: %pM\n", n++, tx_pos->mac);
		}
	}
	rcu_read_unlock();

	return strlen(buf);
}

static ssize_t fwd_set_dbg_level(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int dbglvl = simple_strtol(buf, 0, 10);;
	if (DBG_LVL_OFF <= dbglvl && dbglvl <= DBG_LVL_LOUD) {
		dbg_level = dbglvl;
		DBGPRINT(DBG_LVL_OFF, ("fwd dbg level set to %d\n", dbglvl));
	} else
		DBGPRINT(DBG_LVL_OFF, ("value is invalid, it should be 0~5\n"));

	return count;
}

static struct kobj_attribute fwd_sysfs_show_setting =
		__ATTR(show_setting, S_IRUGO, fwd_show_setting, NULL);

static struct kobj_attribute fwd_sysfs_set_dbg_level =
		__ATTR(debug_level, S_IWUSR, NULL, fwd_set_dbg_level);

static struct attribute *fwd_sysfs[] = {
	&fwd_sysfs_show_setting.attr,
	&fwd_sysfs_set_dbg_level.attr,
	NULL,
};
static struct attribute_group fwd_attr_group = {
	.attrs = fwd_sysfs,
};
struct kobject *fwd_kobj;

static int __init mtfwd_init(void)
{
	int ret, i;

	DBGPRINT(DBG_LVL_OFF, ("-->mtfwd_init(ver:%s)", MTFWD_VERSION));

	link_tbl_cnt = 0;
	tx_src_tbl_cnt = 0;
	session_tbl_cnt = 0;
	path_active_cnt = 0;

	/*init hash table.*/
	spin_lock_init(&link_tbl_lock);
	for (i = 0; i < HASH_TABLE_SIZE; i++)
		INIT_LIST_HEAD(&link_tbl[i]);

	spin_lock_init(&tx_src_tbl_lock);
	for (i = 0; i < HASH_TABLE_SIZE; i++)
		INIT_LIST_HEAD(&tx_src_tbl[i]);

	spin_lock_init(&session_tbl_lock);
	for (i = 0; i < HASH_TABLE_SIZE; i++)
		INIT_LIST_HEAD(&session_tbl[i]);

	spin_lock_init(&path_tbl_lock);
	INIT_LIST_HEAD(&path_tbl);

	/*register hook function to bridge.*/
	ret = nf_register_net_hooks(&init_net, &hk_ops[0], ARRAY_SIZE(hk_ops));
	if (ret < 0) {
		DBGPRINT(DBG_LVL_ERROR, ("register nf hook fail, ret = %d\n", ret));
		goto error1;
	}
	is_hk_ops_api = 1;

	/*register netlink interface.*/
	nl_sk = netlink_kernel_create(&init_net, NETLINK_EXT, &nl_kernel_cfg);
	if (!nl_sk) {
		DBGPRINT(DBG_LVL_ERROR, ("create netlink socket error.\n"));
		ret = -EFAULT;
		goto error2;
	}

	fwd_kobj = kobject_create_and_add("mtfwd", NULL);
	if (!fwd_kobj) {
		ret = -EFAULT;
		goto error3;
	}

	ret = sysfs_create_group(fwd_kobj, &fwd_attr_group);
	if (ret)
		goto error4;

	DBGPRINT(DBG_LVL_OFF, ("<--"));

	return ret;
error4:
	kobject_put(fwd_kobj);
error3:
	sock_release(nl_sk->sk_socket);
error2:
	nf_unregister_net_hooks(&init_net, &hk_ops[0], ARRAY_SIZE(hk_ops));
error1:
	return ret;
}

static void __exit mtfwd_exit(void)
{
	int i;
	struct tx_src_entry *pos_tx_src, *tx_src;
	struct session_based_entry *pos_session, *session;
	struct path_info_entry *pos_path, *p;
	struct link_entry *pos_link, *link;

	DBGPRINT(DBG_LVL_OFF, ("-->mtfwd_exit()"));

	sysfs_remove_group(fwd_kobj, &fwd_attr_group);
	kobject_put(fwd_kobj);

	if (nl_sk != NULL)
		sock_release(nl_sk->sk_socket);

	if (is_hk_ops_api) {
		nf_unregister_net_hooks(&init_net, &hk_ops[0], ARRAY_SIZE(hk_ops));
		is_hk_ops_api = 0;
	}

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		list_for_each_entry_safe(pos_link, link, &link_tbl[i], list) {
			list_del_rcu(&pos_link->list);
			link_tbl_cnt--;
			kfree(pos_link);
		}
	}

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		list_for_each_entry_safe(pos_tx_src, tx_src, &tx_src_tbl[i], list) {
			list_del_rcu(&pos_tx_src->list);
			tx_src_tbl_cnt--;
			kfree(pos_tx_src);
		}
	}
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		list_for_each_entry_safe(pos_session, session, &session_tbl[i], list) {
			list_del_rcu(&pos_session->list);
			session_tbl_cnt--;
			kfree(pos_session);
		}
	}

	list_for_each_entry_safe(pos_path, p, &path_tbl, list) {
		list_del_rcu(&pos_path->list);
		path_active_cnt = MAX((path_active_cnt-1), 0);
		kfree(pos_path);
	}
	DBGPRINT(DBG_LVL_OFF, ("<--mtfwd_exit()"));

	return;
}

module_init(mtfwd_init);
module_exit(mtfwd_exit);
