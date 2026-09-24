/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_DEVICE_H
#define _WG_DEVICE_H

#include "junk.h"
#include "noise.h"
#include "allowedips.h"
#include "peerlookup.h"
#include "cookie.h"
#include "magic_header.h"
#include "header_protection.h"

#include <linux/types.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/ptr_ring.h>

#define WG_NDM_NAME_SIZE	(sizeof("Wireguard32767") + 1)

struct wg_device;

struct multicore_worker {
	void *ptr;
	struct work_struct work;
};

struct crypt_queue {
	struct ptr_ring ring;
	struct multicore_worker __percpu *worker;
	int last_cpu;
};

struct prev_queue {
	struct sk_buff *head, *tail, *peeked;
	struct { struct sk_buff *next, *prev; } empty; // Match first 2 members of struct sk_buff.
	atomic_t count;
};

struct asc_config {
	bool advanced_security;
	u16 junk_packet_count;
	u16 junk_packet_min_size;
	u16 junk_packet_max_size;
};

static inline u16 wg_range16_lo(u32 range)
{
	return (u16)range;
}

static inline u16 wg_range16_hi(u32 range)
{
	return (u16)(range >> 16);
}

static inline bool wg_range16_valid(u32 range)
{
	return wg_range16_lo(range) <= wg_range16_hi(range);
}

static inline u16 wg_range16_pick(u32 range)
{
	u16 lo = wg_range16_lo(range);
	u16 hi = wg_range16_hi(range);

	return lo + get_random_u32() % ((u32)hi - lo + 1);
}

static inline u16 wg_range16_pick_or(u32 range, u16 value)
{
	return range ? wg_range16_pick(range) : value;
}

struct wg_device {
	struct net_device *dev;
	struct crypt_queue encrypt_queue, decrypt_queue, handshake_queue;
	struct sock __rcu *sock4, *sock6;
	struct net __rcu *creating_net;
	struct noise_static_identity static_identity;
	struct workqueue_struct *packet_crypt_wq,*handshake_receive_wq, *handshake_send_wq;
	struct cookie_checker cookie_checker;
	struct pubkey_hashtable *peer_hashtable;
	struct index_hashtable *index_hashtable;
	struct allowedips peer_allowedips;
	struct mutex device_update_lock, socket_update_lock;
	struct list_head device_list, peer_list;
	struct asc_config advanced_security_config;
	struct header_protection header_protection;
	u32 content_padding_addition;
	u32 rekey_after_time;
	u32 rekey_timeout;
	u32 reject_after_time;
	u32 keepalive_timeout;
	u32 max_handshake_attempts;
	atomic_t handshake_queue_len;
	unsigned int num_peers, device_update_gen;
	u32 fwmark;
	u16 incoming_port;
	bool have_creating_net_ref;
	bool random_trailers;
	bool disable_cookies;
	bool debug;
	char ndm_dev_name[WG_NDM_NAME_SIZE];

	struct jp_spec ispecs[5];
	struct magic_header headers[4];
	u16 junk_size[4];
};

int wg_device_init(void);
void wg_device_uninit(void);
int wg_device_handle_post_config(struct net_device *dev, struct asc_config *asc);

#endif /* _WG_DEVICE_H */
