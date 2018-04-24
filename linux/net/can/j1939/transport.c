// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2010-2011 EIA Electronics
 *
 * Authors:
 * Kurt Van Dijck <kurt.van.dijck@eia.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 */

#include <linux/skbuff.h>
#include <linux/hrtimer.h>
#include <linux/version.h>
#include <linux/if_arp.h>
#include <linux/wait.h>
#include <linux/seq_file.h>
#include <linux/can/skb.h>
#include "j1939-priv.h"

#define J1939_REGULAR 0
#define J1939_EXTENDED 1

#define J1939_ETP_PGN_CTL 0xc800
#define J1939_ETP_PGN_DAT 0xc700
#define J1939_TP_PGN_CTL 0xec00
#define J1939_TP_PGN_DAT 0xeb00

#define J1939_TP_CMD_BAM 0x20
#define J1939_TP_CMD_RTS 0x10
#define J1939_TP_CMD_CTS 0x11
#define J1939_TP_CMD_EOF 0x13
#define J1939_TP_CMD_ABORT 0xff

#define J1939_ETP_CMD_RTS 0x14
#define J1939_ETP_CMD_CTS 0x15
#define J1939_ETP_CMD_DPO 0x16
#define J1939_ETP_CMD_EOF 0x17
#define J1939_ETP_CMD_ABORT 0xff

#define J1939_ABORT_BUSY 1
#define J1939_ABORT_RESOURCE 2
#define J1939_ABORT_TIMEOUT 3
#define J1939_ABORT_GENERIC 4
#define J1939_ABORT_FAULT 5

#define J1939_MAX_TP_PACKET_SIZE (7 * 0xff)
#define J1939_MAX_ETP_PACKET_SIZE (7 * 0x00ffffff)

static unsigned int j1939_tp_block = 255;
static unsigned int j1939_tp_max_packet_size = J1939_MAX_ETP_PACKET_SIZE;
static unsigned int j1939_tp_retry_ms = 20;
static unsigned int j1939_tp_packet_delay;
static unsigned int j1939_tp_padding = 1;

struct j1939_session {
	struct list_head list;
	atomic_t refs;
	spinlock_t lock;

	/* ifindex, src, dst, pgn define the session block
	 * the are _never_ modified after insertion in the list
	 * this decreases locking problems a _lot_
	 */
	struct j1939_sk_buff_cb *skcb;
	struct sk_buff *skb;
	int skb_iif;

	/* all tx related stuff (last_txcmd, pkt.tx)
	 * is protected (modified only) with the txtimer hrtimer
	 * 'total' & 'block' are never changed,
	 * last_cmd, last & block are protected by ->lock
	 * this means that the tx may run after cts is received that should
	 * have stopped tx, but this time discrepancy is never avoided anyhow
	 */
	u8 last_cmd, last_txcmd;
	bool transmission;
	bool extd;
	struct {
		/* these do not require 16 bit, they should fit in u8
		 * but putting in int makes it easier to deal with
		 */
		unsigned int total, done, last, tx;
		unsigned int block; /* for TP */
		unsigned int dpo; /* for ETP */
	} pkt;
	struct hrtimer txtimer, rxtimer;
};

/* forward declarations */
static struct j1939_session *j1939_session_new(struct sk_buff *skb);
static struct j1939_session *j1939_session_fresh_new(int size,
						     struct sk_buff *rel_skb,
						     pgn_t pgn);
static int j1939_tp_txnext(struct net *net, struct j1939_session *session);
static inline void j1939_tp_schedule_txtimer(struct j1939_session *session, int msec);

/* helpers */
static inline void j1939_fix_cb(struct j1939_sk_buff_cb *skcb)
{
	skcb->msg_flags &= ~MSG_SYN;
}

static inline struct list_head *j1939_sessionq(struct net *net, bool extd)
{
	return extd ? &net->can_j1939.tp_extsessionq :
		&net->can_j1939.tp_sessionq;
}

static inline void j1939_session_destroy(struct j1939_session *session)
{
	kfree_skb(session->skb);

	hrtimer_cancel(&session->rxtimer);
	hrtimer_cancel(&session->txtimer);

	kfree(session);
}

static inline bool j1939_cb_is_broadcast(const struct j1939_sk_buff_cb *skcb)
{
	return (!skcb->addr.dst_name && (skcb->addr.da == 0xff));
}

/* clean up work queue */
static void j1939_tp_del_work(struct work_struct *work)
{
	struct netns_can_j1939 *ncj;
	struct j1939_session *session;

	ncj = container_of(work, struct netns_can_j1939, tp_delwork);

	do {
		session = NULL;
		spin_lock_bh(&ncj->tp_dellock);
		if (list_empty(&ncj->tp_delsessionq)) {
			spin_unlock_bh(&ncj->tp_dellock);
			break;
		}
		session = list_first_entry(&ncj->tp_delsessionq,
					   struct j1939_session, list);
		list_del_init(&session->list);
		spin_unlock_bh(&ncj->tp_dellock);
		j1939_session_destroy(session);
	} while (1);
}

/* reference counter */
static inline void j1939_session_get(struct j1939_session *session)
{
	atomic_inc(&session->refs);
}

static void j1939_session_put(struct j1939_session *session)
{
	if (atomic_add_return(-1, &session->refs) >= 0)
		/* not the last one */
		return;


	if (in_softirq()) {
		struct net *net = dev_net(session->skb->dev);

		hrtimer_try_to_cancel(&session->rxtimer);
		hrtimer_try_to_cancel(&session->txtimer);
		spin_lock_bh(&net->can_j1939.tp_dellock);
		list_add_tail(&session->list, &net->can_j1939.tp_delsessionq);
		spin_unlock_bh(&net->can_j1939.tp_dellock);
		schedule_work(&net->can_j1939.tp_delwork);
	} else if (WARN_ON_ONCE(!in_task())) {
		hrtimer_cancel(&session->rxtimer);
		hrtimer_cancel(&session->txtimer);
		/* destroy session right here */
		j1939_session_destroy(session);
	}
}

/* transport status locking */
static inline void j1939_session_lock(struct j1939_session *session)
{
	j1939_session_get(session); /* safety measure */
	spin_lock_bh(&session->lock);
}

static inline void j1939_session_unlock(struct net *net, struct j1939_session *session)
{
	spin_unlock_bh(&session->lock);
	j1939_session_put(session);
}

static inline void j1939_sessionlist_lock(struct net *net)
{
	spin_lock_bh(&net->can_j1939.tp_lock);
}

static inline void j1939_sessionlist_unlock(struct net *net)
{
	spin_unlock_bh(&net->can_j1939.tp_lock);
}

/* see if we are receiver
 * returns 0 for broadcasts, although we will receive them
 */
static inline int j1939_tp_im_receiver(struct sk_buff *skb)
{
	struct j1939_sk_buff_cb *skcb = j1939_skb_to_cb(skb);

	return skcb->dst_flags & J1939_ECU_LOCAL;
}

/* see if we are sender */
static inline int j1939_tp_im_transmitter(struct sk_buff *skb)
{
	struct j1939_sk_buff_cb *skcb = j1939_skb_to_cb(skb);

	return skcb->src_flags & J1939_ECU_LOCAL;
}

/* see if we are involved as either receiver or transmitter */
static int j1939_tp_im_involved(struct sk_buff *skb, bool swap)
{
	return swap ? j1939_tp_im_receiver(skb) : j1939_tp_im_transmitter(skb);
}

static int j1939_tp_im_involved_anydir(struct sk_buff *skb)
{
	struct j1939_sk_buff_cb *skcb = j1939_skb_to_cb(skb);

	return (skcb->src_flags | skcb->dst_flags) & J1939_ECU_LOCAL;
}

/* extract pgn from flow-ctl message */
static inline pgn_t j1939_xtp_ctl_to_pgn(const u8 *dat)
{
	pgn_t pgn;

	pgn = (dat[7] << 16) | (dat[6] << 8) | (dat[5] << 0);
	if (j1939_pgn_is_pdu1(pgn))
		pgn &= 0xffff00;
	return pgn;
}

static inline unsigned int j1939_tp_ctl_to_size(const u8 *dat)
{
	return (dat[2] << 8) + (dat[1] << 0);
}

static inline unsigned int j1939_etp_ctl_to_packet(const u8 *dat)
{
	return (dat[4] << 16) | (dat[3] << 8) | (dat[2] << 0);
}

static inline unsigned int j1939_etp_ctl_to_size(const u8 *dat)
{
	return (dat[4] << 24) | (dat[3] << 16) |
		(dat[2] << 8) | (dat[1] << 0);
}

/* find existing session:
 * reverse: swap cb's src & dst
 * there is no problem with matching broadcasts, since
 * broadcasts (no dst, no da) would never call this
 * with reverse == true
 */
static bool j1939_tp_match(struct j1939_session *session, struct sk_buff *skb,
			   bool reverse)
{
	struct j1939_sk_buff_cb *skcb = j1939_skb_to_cb(skb);

	if (session->skb_iif != skb->skb_iif)
		return false;
	if (reverse) {
		if (session->skcb->addr.src_name) {
			if (session->skcb->addr.src_name != skcb->addr.dst_name)
				return false;
		} else if (session->skcb->addr.sa != skcb->addr.da) {
			return false;
		}

		if (session->skcb->addr.dst_name) {
			if (session->skcb->addr.dst_name != skcb->addr.src_name)
				return false;
		} else if (session->skcb->addr.da != skcb->addr.sa) {
			return false;
		}
	} else {
		if (session->skcb->addr.src_name) {
			if (session->skcb->addr.src_name != skcb->addr.src_name)
				return false;
		} else if (session->skcb->addr.sa != skcb->addr.sa) {
			return false;
		}

		if (session->skcb->addr.dst_name) {
			if (session->skcb->addr.dst_name != skcb->addr.dst_name)
				return false;
		} else if (session->skcb->addr.da != skcb->addr.da) {
			return false;
		}
	}

	return true;
}

static struct j1939_session *j1939_session_get_by_skb_locked(struct net *net, struct list_head *root,
						  struct sk_buff *skb, bool reverse)
{
	struct j1939_session *session;

	lockdep_assert_held(&net->can_j1939.tp_lock);

	list_for_each_entry(session, root, list) {
		j1939_session_get(session);
		if (j1939_tp_match(session, skb, reverse))
			return session;
		j1939_session_put(session);
	}

	return NULL;
}

static struct j1939_session *j1939_session_get_by_skb(struct net *net, struct list_head *root,
					   struct sk_buff *skb, bool reverse)
{
	struct j1939_session *session;

	j1939_sessionlist_lock(net);
	session = j1939_session_get_by_skb_locked(net, root, skb, reverse);
	j1939_sessionlist_unlock(net);

	return session;
}

static void j1939_skbcb_swap(struct j1939_sk_buff_cb *skcb)
{
	swap(skcb->addr.dst_name, skcb->addr.src_name);
	swap(skcb->addr.da, skcb->addr.sa);
	swap(skcb->dst_flags, skcb->src_flags);
}

static struct sk_buff *j1939_tp_tx_dat_prep(struct sk_buff *related,
					    bool extd, bool ctl, bool swap_src_dst)
{
	struct sk_buff *skb;
	struct j1939_sk_buff_cb *skcb;

	skb = alloc_skb(sizeof(struct can_frame) + sizeof(struct can_skb_priv),
			GFP_ATOMIC);
	if (unlikely(!skb))
		return ERR_PTR(-ENOMEM);

	skb->dev = related->dev;
	can_skb_reserve(skb);
	can_skb_prv(skb)->ifindex = can_skb_prv(related)->ifindex;
	/* reserve CAN header */
	skb_reserve(skb, offsetof(struct can_frame, data));
	skb->protocol = related->protocol;
	skb->pkt_type = related->pkt_type;
	skb->ip_summed = related->ip_summed;

	memcpy(skb->cb, related->cb, sizeof(skb->cb));
	skcb = j1939_skb_to_cb(skb);
	j1939_fix_cb(skcb);
	if (swap_src_dst)
		j1939_skbcb_swap(skcb);

	if (ctl)
		skcb->addr.pgn = extd ? J1939_ETP_PGN_CTL : J1939_TP_PGN_CTL;
	else
		skcb->addr.pgn = extd ? J1939_ETP_PGN_DAT : J1939_TP_PGN_DAT;

	return skb;
}

/* TP transmit packet functions */
static int j1939_tp_tx_dat(struct sk_buff *related, bool extd,
			   const u8 *dat, int len)
{
	struct sk_buff *skb;
	u8 *skdat;

	skb = j1939_tp_tx_dat_prep(related, extd, false, false);
	if (IS_ERR(skb))
		return PTR_ERR(skb);

	skdat = skb_put(skb, len);
	memcpy(skdat, dat, len);
	if (j1939_tp_padding && len < 8)
		memset(skb_put(skb, 8 - len), 0xff, 8 - len);

	return j1939_send(dev_net(skb->dev), skb);
}

static int j1939_xtp_do_tx_ctl(struct sk_buff *related, bool extd,
			       bool swap_src_dst, pgn_t pgn, const u8 *dat)
{
	struct sk_buff *skb;
	u8 *skdat;

	if (!j1939_tp_im_involved(related, swap_src_dst))
		return 0;

	skb = j1939_tp_tx_dat_prep(related, extd, true, swap_src_dst);
	if (IS_ERR(skb))
		return PTR_ERR(skb);

	skdat = skb_put(skb, 8);
	memcpy(skdat, dat, 5);
	skdat[5] = (pgn >> 0);
	skdat[6] = (pgn >> 8);
	skdat[7] = (pgn >> 16);

	return j1939_send(dev_net(skb->dev), skb);
}

static inline int j1939_tp_tx_ctl(struct j1939_session *session,
				  bool swap_src_dst, const u8 *dat)
{
	return j1939_xtp_do_tx_ctl(session->skb, session->extd, swap_src_dst,
				   session->skcb->addr.pgn, dat);
}

static int j1939_xtp_tx_abort(struct sk_buff *related, bool extd,
			      bool swap_src_dst, int err, pgn_t pgn)
{
	u8 dat[5];

	if (!j1939_tp_im_involved(related, swap_src_dst))
		return 0;

	memset(dat, 0xff, sizeof(dat));
	dat[0] = J1939_TP_CMD_ABORT;
	if (!extd)
		dat[1] = err ?: J1939_ABORT_GENERIC;
	return j1939_xtp_do_tx_ctl(related, extd, swap_src_dst, pgn, dat);
}

/* timer & scheduler functions */
static inline void j1939_session_schedule_txnow(struct j1939_session *session)
{
	hrtimer_start(&session->txtimer, ktime_set(0, 0),
		      HRTIMER_MODE_REL_SOFT);
}

static enum hrtimer_restart j1939_tp_txtimer(struct hrtimer *hrtimer)
{
	struct j1939_session *session =
		container_of(hrtimer, struct j1939_session, txtimer);
	struct net *net = dev_net(session->skb->dev);
	int ret;

	j1939_session_get(session);
	ret = j1939_tp_txnext(net, session);
	if (ret < 0)
		j1939_tp_schedule_txtimer(session, j1939_tp_retry_ms ?: 20);
	j1939_session_put(session);

	return HRTIMER_NORESTART;
}

static inline void j1939_tp_schedule_txtimer(struct j1939_session *session, int msec)
{
	hrtimer_start(&session->txtimer,
		      ktime_set(msec / 1000, (msec % 1000) * 1000000UL),
		      HRTIMER_MODE_REL_SOFT);
}

static inline void j1939_tp_set_rxtimeout(struct j1939_session *session, int msec)
{
	hrtimer_start(&session->rxtimer,
		      ktime_set(msec / 1000, (msec % 1000) * 1000000UL),
		      HRTIMER_MODE_REL_SOFT);
}

/* session completion functions */

/* j1939_session_drop
 * removes a session from open session list
 */
static inline void j1939_session_drop(struct net *net, struct j1939_session *session)
{
	j1939_sessionlist_lock(net);
	list_del_init(&session->list);
	j1939_sessionlist_unlock(net);

	if (session->transmission) {
		if (session->skb && session->skb->sk)
			j1939_sock_pending_del(session->skb->sk);
		wake_up_all(&net->can_j1939.tp_wait);
	}
	j1939_session_put(session);
}

static inline void j1939_session_completed(struct net *net, struct j1939_session *session)
{
	/* distribute among j1939 receivers */
	j1939_sk_recv(session->skb);
	j1939_session_drop(net, session);
}

static void j1939_session_cancel(struct net *net, struct j1939_session *session, int err)
{
	if (err >= 0 && j1939_tp_im_involved_anydir(session->skb))
	{
		if (!j1939_cb_is_broadcast(session->skcb))
		{
			/* do not send aborts on incoming broadcasts */
			j1939_xtp_tx_abort(session->skb, session->extd,
					   !(session->skcb->src_flags & J1939_ECU_LOCAL),
					   err, session->skcb->addr.pgn);
		}
	}
	j1939_session_drop(net, session);
}

static enum hrtimer_restart j1939_tp_rxtimer(struct hrtimer *hrtimer)
{
	struct j1939_session *session = container_of(hrtimer, struct j1939_session,
						     rxtimer);
	struct net *net = dev_net(session->skb->dev);

	j1939_session_get(session);
	pr_alert("%s: timeout on %i\n", __func__, session->skb_iif);
	j1939_session_cancel(net, session, J1939_ABORT_TIMEOUT);
	j1939_session_put(session);

	return HRTIMER_NORESTART;
}

/* receive packet functions */
static void _j1939_xtp_rx_bad_message(struct net *net, struct sk_buff *skb, bool extd, bool reverse)
{
	struct j1939_session *session;
	pgn_t pgn;

	pgn = j1939_xtp_ctl_to_pgn(skb->data);
	session = j1939_session_get_by_skb(net, j1939_sessionq(net, extd), skb, reverse);
	if (session /*&& (session->skcb->addr.pgn == pgn)*/) {
		/* do not allow TP control messages on 2 pgn's */
		j1939_session_cancel(net, session, J1939_ABORT_FAULT);
		j1939_session_put(session);
		return;
	}
	j1939_xtp_tx_abort(skb, extd, 0, J1939_ABORT_FAULT, pgn);
	if (!session)
		return;
	j1939_session_put(session);
}

/* abort packets may come in 2 directions */
static void j1939_xtp_rx_bad_message(struct net *net, struct sk_buff *skb, bool extd)
{
	pr_info("%s, pgn %05x\n", __func__, j1939_xtp_ctl_to_pgn(skb->data));

	_j1939_xtp_rx_bad_message(net, skb, extd, 0);
	_j1939_xtp_rx_bad_message(net, skb, extd, 1);
}

static void _j1939_xtp_rx_abort(struct net *net, struct sk_buff *skb, bool extd, bool reverse)
{
	struct j1939_session *session;
	pgn_t pgn;

	pgn = j1939_xtp_ctl_to_pgn(skb->data);
	session = j1939_session_get_by_skb(net, j1939_sessionq(net, extd), skb, reverse);
	if (!session)
		return;
	if (session->transmission && !session->last_txcmd) {
		/* empty block:
		 * do not drop session when a transmit session did not
		 * start yet
		 */
	} else if (session->skcb->addr.pgn == pgn) {
		j1939_session_drop(net, session);
	}

	/* TODO: maybe cancel current connection
	 * as another pgn was communicated
	 */
	j1939_session_put(session);
}

/* abort packets may come in 2 directions */
static inline void j1939_xtp_rx_abort(struct net *net, struct sk_buff *skb, bool extd)
{
	pr_info("%s %i, %05x\n", __func__, skb->skb_iif,
		j1939_xtp_ctl_to_pgn(skb->data));

	_j1939_xtp_rx_abort(net, skb, extd, 0);
	_j1939_xtp_rx_abort(net, skb, extd, 1);
}

static void j1939_xtp_rx_eof(struct net *net, struct sk_buff *skb, bool extd)
{
	struct j1939_session *session;
	pgn_t pgn;

	/* end of tx cycle */
	pgn = j1939_xtp_ctl_to_pgn(skb->data);
	session = j1939_session_get_by_skb(net, j1939_sessionq(net, extd), skb, true);
	if (!session) {
		/* strange, we had EOF on closed connection
		 * do nothing, as EOF closes the connection anyway
		 */
		return;
	}

	if (session->skcb->addr.pgn != pgn) {
		j1939_xtp_tx_abort(skb, extd, 1, J1939_ABORT_BUSY, pgn);
		j1939_session_cancel(net, session, J1939_ABORT_BUSY);
	} else {
		/* transmitted without problems */
		j1939_session_completed(net, session);
	}
	j1939_session_put(session);
}

static void j1939_xtp_rx_cts(struct net *net, struct sk_buff *skb, bool extd)
{
	struct j1939_session *session;
	pgn_t pgn;
	unsigned int pkt;
	const u8 *dat;

	dat = skb->data;
	pgn = j1939_xtp_ctl_to_pgn(skb->data);
	session = j1939_session_get_by_skb(net, j1939_sessionq(net, extd), skb, true);
	if (!session) {
		/* 'CTS shall be ignored' */
		return;
	}

	if (session->skcb->addr.pgn != pgn) {
		/* what to do? */
		j1939_xtp_tx_abort(skb, extd, 1, J1939_ABORT_BUSY, pgn);
		j1939_session_cancel(net, session, J1939_ABORT_BUSY);
		j1939_session_put(session);
		return;
	}

	j1939_session_lock(session);
	pkt = extd ? j1939_etp_ctl_to_packet(dat) : dat[2];
	if (!dat[0]) {
		hrtimer_cancel(&session->txtimer);
	} else if (!pkt) {
		goto bad_fmt;
	} else if (dat[1] > session->pkt.block /* 0xff for etp */) {
		goto bad_fmt;
	} else {
		/* set packet counters only when not CTS(0) */
		session->pkt.done = pkt - 1;
		session->pkt.last = session->pkt.done + dat[1];
		if (session->pkt.last > session->pkt.total)
			/* safety measure */
			session->pkt.last = session->pkt.total;
		/* TODO: do not set tx here, do it in txtimer */
		session->pkt.tx = session->pkt.done;
	}

	session->last_cmd = dat[0];
	j1939_session_unlock(net, session);
	if (dat[1]) {
		j1939_tp_set_rxtimeout(session, 1250);
		if (j1939_tp_im_transmitter(session->skb))
			j1939_session_schedule_txnow(session);
	} else {
		/* CTS(0) */
		j1939_tp_set_rxtimeout(session, 550);
	}
	j1939_session_put(session);
	return;
 bad_fmt:
	j1939_session_unlock(net, session);
	j1939_session_cancel(net, session, J1939_ABORT_FAULT);
	j1939_session_put(session);
}

static void j1939_xtp_rx_rts(struct net *net, struct sk_buff *skb, bool extd)
{
	struct j1939_sk_buff_cb *skcb = j1939_skb_to_cb(skb);
	struct j1939_session *session;
	int len;
	const u8 *dat;
	pgn_t pgn;

	dat = skb->data;
	pgn = j1939_xtp_ctl_to_pgn(dat);

	pr_alert("Debugging - Function: %s Number: 1 \n",__func__);

		if (dat[0] == J1939_TP_CMD_RTS && j1939_cb_is_broadcast(skcb)) {
			pr_alert("%s: rts without destination (%i %02x)\n", __func__,
				 skb->skb_iif, skcb->addr.sa);
			return;
		}

		/* TODO: abort RTS when a similar
		 * TP is pending in the other direction
		 */
		session = j1939_session_get_by_skb(net, j1939_sessionq(net, extd), skb, false);
		if (session && !j1939_tp_im_transmitter(skb))
		{

			/* RTS on pending connection */
			j1939_session_cancel(net, session, J1939_ABORT_BUSY);
			if (pgn != session->skcb->addr.pgn && dat[0] != J1939_TP_CMD_BAM)
			{
				j1939_xtp_tx_abort(skb, extd, 1, J1939_ABORT_BUSY, pgn);
			}
			j1939_session_put(session);
			return;
		}
		else if (!session && j1939_tp_im_transmitter(skb))
		{
			pr_alert("%s: I should tx (%i %02x %02x)\n", __func__,
				 skb->skb_iif, skcb->addr.sa, skcb->addr.da);
			return;
		}

	pr_alert("Debugging - Function: %s Number: 4 \n",__func__);

		if (session && session->last_cmd != 0)
		{
			/* we received a second rts on the same connection */
			pr_alert("%s: connection exists (%i %02x %02x)\n", __func__,skb->skb_iif, skcb->addr.sa, skcb->addr.da);

/* Goes into here!!!!!  This is where it kills the session*/

			j1939_session_cancel(net, session, J1939_ABORT_BUSY);
			j1939_session_put(session);
			return;
		}

	if (session)
	{
		pr_alert("Debugging - Function: %s Number: 6 \n",__func__);
		/* make sure 'sa' & 'da' are correct !
		 * They may be 'not filled in yet' for sending
		 * skb's, since they did not pass the Address Claim ever.
		 */
		session->skcb->addr.sa = skcb->addr.sa;
		session->skcb->addr.da = skcb->addr.da;
	}
		else
		{
			int abort = 0;

			if (extd)
			{
				len = j1939_etp_ctl_to_size(dat);
				if (len > J1939_MAX_ETP_PACKET_SIZE)
				{
					abort = J1939_ABORT_FAULT;
				}
				else if (j1939_tp_max_packet_size && (len > j1939_tp_max_packet_size))
				{
					abort = J1939_ABORT_RESOURCE;
				}
				else if (len <= J1939_MAX_TP_PACKET_SIZE)
				{
					abort = J1939_ABORT_FAULT;
				}
			}
			else
			{
				len = j1939_tp_ctl_to_size(dat);
				if (len > J1939_MAX_TP_PACKET_SIZE)
				{
					abort = J1939_ABORT_FAULT;
				}
				else if (j1939_tp_max_packet_size && (len > j1939_tp_max_packet_size))
				{
					abort = J1939_ABORT_RESOURCE;
				}
			}
			if (abort)
			{
				j1939_xtp_tx_abort(skb, extd, 1, abort, pgn);
				return;
			}
			session = j1939_session_fresh_new(len, skb, pgn);
			if (!session)
			{
				j1939_xtp_tx_abort(skb, extd, 1, J1939_ABORT_RESOURCE,
						   pgn);
				return;
			}

			session->extd = extd;

			/* initialize the control buffer: plain copy */
			session->pkt.total = (len + 6) / 7;
			session->pkt.block = 0xff;
			if (!extd)
			{
				if (dat[3] != session->pkt.total)
					pr_alert("%s: strange total, %u != %u\n",
						 __func__, session->pkt.total,
						 dat[3]);
				session->pkt.total = dat[3];
				session->pkt.block = min(dat[3], dat[4]);
			}
			session->pkt.done = 0;
			session->pkt.tx = 0;
			j1939_session_get(session); /* equivalent to j1939_tp_find() */
			j1939_sessionlist_lock(net);
			list_add_tail(&session->list, j1939_sessionq(net, extd));
			j1939_sessionlist_unlock(net);
		}

	pr_alert("Debugging - Function: %s Number: 20 \n",__func__);
	session->last_cmd = dat[0];

	j1939_tp_set_rxtimeout(session, 1250);

		if (j1939_tp_im_receiver(session->skb))
		{
			if (extd || dat[0] != J1939_TP_CMD_BAM)
			{
				j1939_session_schedule_txnow(session);
			}
		}

	pr_alert("Debugging - Function: %s Number: 23 \n",__func__);
	/* as soon as it's inserted, things can go fast
	 * protect against a long delay
	 * between spin_unlock & next statement
	 * so, only release here, at the end
	 */
	/* Experiencing a timeout here after aborting earlier...*/
	j1939_session_put(session);
}

static void j1939_xtp_rx_dpo(struct net *net, struct sk_buff *skb, bool extd)
{
	struct j1939_session *session;
	pgn_t pgn;
	const u8 *dat = skb->data;

	pgn = j1939_xtp_ctl_to_pgn(dat);
	session = j1939_session_get_by_skb(net, j1939_sessionq(net, extd), skb, false);
	if (!session) {
		pr_info("%s: %s\n", __func__, "no connection found");
		return;
	}

	if (session->skcb->addr.pgn != pgn) {
		pr_info("%s: different pgn\n", __func__);
		j1939_xtp_tx_abort(skb, 1, 1, J1939_ABORT_BUSY, pgn);
		j1939_session_cancel(net, session, J1939_ABORT_BUSY);
		j1939_session_put(session);
		return;
	}

	/* transmitted without problems */
	session->pkt.dpo = j1939_etp_ctl_to_packet(skb->data);
	session->last_cmd = dat[0];
	j1939_tp_set_rxtimeout(session, 750);
	j1939_session_put(session);
}

static void j1939_xtp_rx_dat(struct net *net, struct sk_buff *skb, bool extd)
{
	struct j1939_session *session;
	const u8 *dat;
	u8 *tpdat;
	int offset;
	int nbytes;
	int final;
	int do_cts_eof;
	int packet;

	session = j1939_session_get_by_skb(net, j1939_sessionq(net, extd), skb, false);
	if (!session) {
		pr_info("%s:%s\n", __func__, "no connection found");
		return;
	}
	dat = skb->data;
	if (skb->len <= 1)
		/* makes no sense */
		goto strange_packet_unlocked;

	j1939_session_lock(session);

	switch (session->last_cmd) {
	case 0xff:
		break;
	case J1939_ETP_CMD_DPO:
		if (extd)
			break;
	case J1939_TP_CMD_BAM:
	case J1939_TP_CMD_CTS:
		if (!extd)
			break;
	default:
		pr_info("%s: last %02x\n", __func__,
			session->last_cmd);
		goto strange_packet;
	}

	packet = (dat[0] - 1 + session->pkt.dpo);
	offset = packet * 7;
	if (packet > session->pkt.total ||
	    (session->pkt.done + 1) > session->pkt.total) {
		pr_info("%s: should have been completed\n", __func__);
		goto strange_packet;
	}
	nbytes = session->skb->len - offset;
	if (nbytes > 7)
		nbytes = 7;
	if (nbytes <= 0 || (nbytes + 1) > skb->len) {
		pr_info("%s: nbytes %i, len %i\n", __func__, nbytes,
			skb->len);
		goto strange_packet;
	}
	tpdat = session->skb->data;
	memcpy(&tpdat[offset], &dat[1], nbytes);
	if (packet == session->pkt.done)
		++session->pkt.done;

	if (!extd && j1939_cb_is_broadcast(session->skcb)) {
		final = session->pkt.done >= session->pkt.total;
		do_cts_eof = 0;
	} else {
		final = 0; /* never final, an EOF must follow */
		do_cts_eof = (session->pkt.done >= session->pkt.last);
	}
	j1939_session_unlock(net, session);
	if (final) {
		j1939_session_completed(net, session);
	} else if (do_cts_eof) {
		j1939_tp_set_rxtimeout(session, 1250);
		if (j1939_tp_im_receiver(session->skb))
			j1939_session_schedule_txnow(session);
	} else {
		j1939_tp_set_rxtimeout(session, 250);
	}
	session->last_cmd = 0xff;
	j1939_session_put(session);
	return;

 strange_packet:
	/* unlock session (spinlock) before trying to send */
	j1939_session_unlock(net, session);
 strange_packet_unlocked:
	j1939_session_cancel(net, session, J1939_ABORT_FAULT);
	j1939_session_put(session);
}

/* transmit function */
static int j1939_tp_txnext(struct net *net, struct j1939_session *session)
{
	u8 dat[8];
	const u8 *tpdat;
	int ret, offset, pkt_done, pkt_end;
	unsigned int pkt, len, pdelay;

	memset(dat, 0xff, sizeof(dat));
	j1939_session_get(session); /* do not loose it */

	switch (session->last_cmd) {
	case 0:
		if (!j1939_tp_im_transmitter(session->skb))
			break;
		dat[1] = (session->skb->len >> 0);
		dat[2] = (session->skb->len >> 8);
		dat[3] = session->pkt.total;
		if (session->extd) {
			dat[0] = J1939_ETP_CMD_RTS;
			dat[1] = (session->skb->len >> 0);
			dat[2] = (session->skb->len >> 8);
			dat[3] = (session->skb->len >> 16);
			dat[4] = (session->skb->len >> 24);
		} else if (j1939_cb_is_broadcast(session->skcb)) {
			dat[0] = J1939_TP_CMD_BAM;
			/* fake cts for broadcast */
			session->pkt.tx = 0;
		} else {
			dat[0] = J1939_TP_CMD_RTS;
			dat[4] = dat[3];
		}
		if (dat[0] == session->last_txcmd)
			/* done already */
			break;
		ret = j1939_tp_tx_ctl(session, false, dat);
		if (ret < 0)
			goto failed;
		session->last_txcmd = dat[0];
		/* must lock? */
		if (J1939_TP_CMD_BAM == dat[0])
		{
			//printk("DEBUG: Passed %s %d \n",__FUNCTION__,__LINE__);
			//printk("DEBUG: Calling j1939tp_schedule_txtimer\n");
			//Use  50 ms delay
			if(j1939cb_use_bamdelay(session->skcb))
			{
				//printk("DEBUG: Using 50 ms delay\n");

				j1939_tp_schedule_txtimer(session, 50);
			}
			//Don't use bam delay
			else
			{
				//printk("DEBUG: Using 1 ms delay\n");

				//Use 1 ms delay instead
				j1939_tp_schedule_txtimer(session, 1);
			}
		}
		j1939_tp_set_rxtimeout(session, 1250);
		break;
	case J1939_TP_CMD_RTS:
	case J1939_ETP_CMD_RTS: /* fallthrough */
		if (!j1939_tp_im_receiver(session->skb))
			break;
 tx_cts:
		ret = 0;
		len = session->pkt.total - session->pkt.done;
		len = min(max(len, session->pkt.block), j1939_tp_block ?: 255);

		if (session->extd) {
			pkt = session->pkt.done + 1;
			dat[0] = J1939_ETP_CMD_CTS;
			dat[1] = len;
			dat[2] = (pkt >> 0);
			dat[3] = (pkt >> 8);
			dat[4] = (pkt >> 16);
		} else {
			dat[0] = J1939_TP_CMD_CTS;
			dat[1] = len;
			dat[2] = session->pkt.done + 1;
		}
		if (dat[0] == session->last_txcmd)
			/* done already */
			break;
		ret = j1939_tp_tx_ctl(session, true, dat);
		if (ret < 0)
			goto failed;
		if (len)
			/* only mark cts done when len is set */
			session->last_txcmd = dat[0];
		j1939_tp_set_rxtimeout(session, 1250);
		break;
	case J1939_ETP_CMD_CTS:
		if (j1939_tp_im_transmitter(session->skb) && session->extd &&
		    session->last_txcmd != J1939_ETP_CMD_DPO) {
			/* do dpo */
			dat[0] = J1939_ETP_CMD_DPO;
			session->pkt.dpo = session->pkt.done;
			pkt = session->pkt.dpo;
			dat[1] = session->pkt.last - session->pkt.done;
			dat[2] = (pkt >> 0);
			dat[3] = (pkt >> 8);
			dat[4] = (pkt >> 16);
			ret = j1939_tp_tx_ctl(session, false, dat);
			if (ret < 0)
				goto failed;
			session->last_txcmd = dat[0];
			j1939_tp_set_rxtimeout(session, 1250);
			session->pkt.tx = session->pkt.done;
		}
		/* fallthrough */
	case J1939_TP_CMD_CTS: /* fallthrough */
	case 0xff: /* did some data */			/* FIXME: let David Jander recheck this */
	case J1939_ETP_CMD_DPO: /* fallthrough */
		if ((session->extd || !j1939_cb_is_broadcast(session->skcb)) &&
		    j1939_tp_im_receiver(session->skb)) {
			if (session->pkt.done >= session->pkt.total) {
				if (session->extd) {
					dat[0] = J1939_ETP_CMD_EOF;
					dat[1] = session->skb->len >> 0;
					dat[2] = session->skb->len >> 8;
					dat[3] = session->skb->len >> 16;
					dat[4] = session->skb->len >> 24;
				} else {
					dat[0] = J1939_TP_CMD_EOF;
					dat[1] = session->skb->len;
					dat[2] = session->skb->len >> 8;
					dat[3] = session->pkt.total;
				}
				if (dat[0] == session->last_txcmd)
					/* done already */
					break;
				ret = j1939_tp_tx_ctl(session, true, dat);
				if (ret < 0)
					goto failed;
				session->last_txcmd = dat[0];
				j1939_tp_set_rxtimeout(session, 1250);
				/* wait for the EOF packet to come in */
				break;
			} else if (session->pkt.done >= session->pkt.last) {
				session->last_txcmd = 0;
				goto tx_cts;
			}
		}
	case J1939_TP_CMD_BAM: /* fallthrough */
		if (!j1939_tp_im_transmitter(session->skb))
			break;
		tpdat = session->skb->data;
		ret = 0;
		pkt_done = 0;
		pkt_end = (!session->extd && j1939_cb_is_broadcast(session->skcb))
			? session->pkt.total : session->pkt.last;

		while (session->pkt.tx < pkt_end) {
			dat[0] = session->pkt.tx - session->pkt.dpo + 1;
			offset = session->pkt.tx * 7;
			len = session->skb->len - offset;
			if (len > 7)
				len = 7;
			memcpy(&dat[1], &tpdat[offset], len);
			ret = j1939_tp_tx_dat(session->skb, session->extd,
					      dat, len + 1);
			if (ret < 0)
				break;
			session->last_txcmd = 0xff;
			++pkt_done;
			++session->pkt.tx;

			if(j1939_cb_is_broadcast(session->skcb) && j1939cb_use_bamdelay(session->skcb))
			{
				 pdelay = 50;
			}
			else
			{
				 pdelay = j1939_tp_packet_delay;
			}

			if (session->pkt.tx < session->pkt.total && pdelay) {
				j1939_tp_schedule_txtimer(session, pdelay);
				break;
			}
		}
		if (pkt_done)
			j1939_tp_set_rxtimeout(session, 250);
		if (ret)
			goto failed;
		break;
	}
	j1939_session_put(session);
	return 0;
 failed:
	j1939_session_put(session);
	return ret;
}

static inline int j1939_tp_tx_initial(struct net *net, struct j1939_session *session)
{
	int ret;

	j1939_session_get(session);
	ret = j1939_tp_txnext(net, session);
	/* set nonblocking for further packets */
	session->skcb->msg_flags |= MSG_DONTWAIT;
	j1939_session_put(session);
	return ret;
}

/* this call is to be used as probe within wait_event_xxx() */
static int j1939_session_insert(struct net *net, struct j1939_session *session)
{
	struct j1939_session *pending;

	j1939_sessionlist_lock(net);
	pending = j1939_session_get_by_skb_locked(net, j1939_sessionq(net, session->extd),
				       session->skb, false);
	if (pending)
		/* revert the effect of find() */
		j1939_session_put(pending);
	else
		list_add_tail(&session->list, j1939_sessionq(net, session->extd));
	j1939_sessionlist_unlock(net);
	return pending ? 0 : 1;
}

/* j1939 main intf */
int j1939_tp_send(struct net *net, struct j1939_priv *priv, struct sk_buff *skb)
{
	struct j1939_sk_buff_cb *skcb = j1939_skb_to_cb(skb);
	struct j1939_session *session;
	int ret;

	if (skcb->addr.pgn == J1939_TP_PGN_DAT ||
	    skcb->addr.pgn == J1939_TP_PGN_CTL ||
	    skcb->addr.pgn == J1939_ETP_PGN_DAT ||
	    skcb->addr.pgn == J1939_ETP_PGN_CTL)
		/* avoid conflict */
		return -EDOM;
	else if ((skb->len > J1939_MAX_ETP_PACKET_SIZE) ||
		 (j1939_tp_max_packet_size && (skb->len > j1939_tp_max_packet_size)))
		return -EMSGSIZE;

	if (skb->len > J1939_MAX_TP_PACKET_SIZE) {
		if (j1939_cb_is_broadcast(skcb))
			return -EDESTADDRREQ;
	}

	/* fill in addresses from names */
	ret = j1939_ac_fixup(priv, skb);
	if (unlikely(ret))
		return ret;

	/* fix dst_flags, it may be used there soon */
	if (j1939_address_is_unicast(skcb->addr.da) &&
	    priv->ents[skcb->addr.da].nusers)
		skcb->dst_flags |= J1939_ECU_LOCAL;
	/* src is always local, I'm sending ... */
	skcb->src_flags |= J1939_ECU_LOCAL;

	/* prepare new session */
	session = j1939_session_new(skb);
	if (!session)
		return -ENOMEM;

	session->skb_iif = can_skb_prv(skb)->ifindex;
	session->extd = (skb->len > J1939_MAX_TP_PACKET_SIZE) ?
		J1939_EXTENDED : J1939_REGULAR;
	session->transmission = true;
	session->pkt.total = (skb->len + 6) / 7;
	session->pkt.block = session->extd ? 255 :
		min(j1939_tp_block ?: 255, session->pkt.total);
	if (j1939_cb_is_broadcast(session->skcb))
		/* set the end-packet for broadcast */
		session->pkt.last = session->pkt.total;

	/* insert into queue, but avoid collision with pending session */
	if (session->skcb->msg_flags & MSG_DONTWAIT)
		ret = j1939_session_insert(net, session) ? 0 : -EAGAIN;
	else
		ret = wait_event_interruptible(net->can_j1939.tp_wait,
					       j1939_session_insert(net, session));
	if (ret < 0)
		goto failed;

	ret = j1939_tp_tx_initial(net, session);
	if (!ret)
		/* transmission started */
		return ret;
	j1939_sessionlist_lock(net);
	list_del_init(&session->list);
	j1939_sessionlist_unlock(net);
 failed:
	/* hide the skb from j1939_session_drop, as it would
	 * kfree_skb, but our caller will kfree_skb(skb) too.
	 */
	session->skb = NULL;
	j1939_session_drop(net, session);
	return ret;
}

int j1939_tp_recv(struct net *net, struct sk_buff *skb)
{
	struct j1939_sk_buff_cb *skcb = j1939_skb_to_cb(skb);
	const u8 *dat;

	switch (skcb->addr.pgn) {
	case J1939_ETP_PGN_DAT:
		j1939_xtp_rx_dat(net, skb, J1939_EXTENDED);
		break;
	case J1939_ETP_PGN_CTL:
		pr_alert("Debugging - Function: %s case J1939_ETP_PGN_CTL \n",__func__);
		if (skb->len < 8) {
			j1939_xtp_rx_bad_message(net, skb, J1939_EXTENDED);
			break;
		}
		dat = skb->data;
		switch (*dat) {
		case J1939_ETP_CMD_RTS:
			j1939_xtp_rx_rts(net, skb, J1939_EXTENDED);
			break;
		case J1939_ETP_CMD_CTS:
			j1939_xtp_rx_cts(net, skb, J1939_EXTENDED);
			break;
		case J1939_ETP_CMD_DPO:
			j1939_xtp_rx_dpo(net, skb, J1939_EXTENDED);
			break;
		case J1939_ETP_CMD_EOF:
			j1939_xtp_rx_eof(net, skb, J1939_EXTENDED);
			break;
		case J1939_ETP_CMD_ABORT:
			j1939_xtp_rx_abort(net, skb, J1939_EXTENDED);
			break;
		default:
			j1939_xtp_rx_bad_message(net, skb, J1939_EXTENDED);
			break;
		}
		break;
	case J1939_TP_PGN_DAT:
		j1939_xtp_rx_dat(net, skb, J1939_REGULAR);
		break;
	case J1939_TP_PGN_CTL:
		pr_alert("Debugging - Function: %s case J1939_TP_PGN_CTL \n",__func__);
		if (skb->len < 8) {
			j1939_xtp_rx_bad_message(net, skb, J1939_REGULAR);
			break;
		}
		dat = skb->data;
		switch (*dat) {
		case J1939_TP_CMD_BAM:
		case J1939_TP_CMD_RTS:
			j1939_xtp_rx_rts(net, skb, J1939_REGULAR);
			break;
		case J1939_TP_CMD_CTS:
			j1939_xtp_rx_cts(net, skb, J1939_REGULAR);
			break;
		case J1939_TP_CMD_EOF:
			j1939_xtp_rx_eof(net, skb, J1939_REGULAR);
			break;
		case J1939_TP_CMD_ABORT:
			j1939_xtp_rx_abort(net, skb, J1939_REGULAR);
			break;
		default:
			j1939_xtp_rx_bad_message(net, skb, J1939_REGULAR);
			break;
		}
		break;
	default:
		return 0; /* no problem */
	}
	return 1; /* "I processed the message" */
}

static struct j1939_session *j1939_session_fresh_new(int size,
						     struct sk_buff *rel_skb,
						     pgn_t pgn)
{
	struct sk_buff *skb;
	struct j1939_sk_buff_cb *skcb;
	struct j1939_session *session;

	/* this SKB is allocated without headroom for CAN skb's.
	 * This may not pose a problem, this SKB will never
	 * enter generic CAN functions
	 */
	skb = alloc_skb(size, GFP_ATOMIC);
	if (!skb)
		return NULL;

	skcb = j1939_skb_to_cb(skb);
	memcpy(skcb, rel_skb->cb, sizeof(*skcb));
	j1939_fix_cb(skcb);
	skcb->addr.pgn = pgn;

	session = j1939_session_new(skb);
	if (!session) {
		kfree_skb(skb);
		return NULL;
	}
	session->skb_iif = rel_skb->skb_iif;
	skb->skb_iif = rel_skb->skb_iif;
	skb->dev = rel_skb->dev;

	/* alloc data area */
	skb_put(skb, size);
	return session;
}

static struct j1939_session *j1939_session_new(struct sk_buff *skb)
{
	struct j1939_session *session;

	session = kzalloc(sizeof(*session), gfp_any());
	if (!session)
		return NULL;
	INIT_LIST_HEAD(&session->list);
	spin_lock_init(&session->lock);
	session->skb = skb;

	session->skcb = j1939_skb_to_cb(session->skb);
	hrtimer_init(&session->txtimer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_REL_SOFT);
	session->txtimer.function = j1939_tp_txtimer;
	hrtimer_init(&session->rxtimer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_REL_SOFT);
	session->rxtimer.function = j1939_tp_rxtimer;

	return session;
}

int j1939_tp_rmdev_notifier(struct net_device *ndev)
{
	struct net *net = dev_net(ndev);
	struct j1939_session *session, *saved;

	j1939_sessionlist_lock(net);
	list_for_each_entry_safe(session, saved,
				 &net->can_j1939.tp_sessionq, list) {
		if (session->skb_iif != ndev->ifindex)
			continue;
		list_del_init(&session->list);
		j1939_session_put(session);
	}
	list_for_each_entry_safe(session, saved,
				 &net->can_j1939.tp_extsessionq, list) {
		if (session->skb_iif != ndev->ifindex)
			continue;
		list_del_init(&session->list);
		j1939_session_put(session);
	}
	j1939_sessionlist_unlock(net);
	return NOTIFY_DONE;
}

static int __net_init j1939_tp_pernet_init(struct net *net)
{
	spin_lock_init(&net->can_j1939.tp_lock);
	INIT_LIST_HEAD(&net->can_j1939.tp_sessionq);
	INIT_LIST_HEAD(&net->can_j1939.tp_extsessionq);
	spin_lock_init(&net->can_j1939.tp_dellock);
	INIT_LIST_HEAD(&net->can_j1939.tp_delsessionq);
	INIT_WORK(&net->can_j1939.tp_delwork, j1939_tp_del_work);
	init_waitqueue_head(&net->can_j1939.tp_wait);
	return 0;
}

static void __net_exit j1939_tp_pernet_exit(struct net *net)
{
	struct j1939_session *session, *saved;

	wake_up_all(&net->can_j1939.tp_wait);

	j1939_sessionlist_lock(net);
	list_for_each_entry_safe(session, saved,
				 &net->can_j1939.tp_extsessionq, list) {
		list_del_init(&session->list);
		j1939_session_put(session);
	}
	list_for_each_entry_safe(session, saved,
				 &net->can_j1939.tp_sessionq, list) {
		list_del_init(&session->list);
		j1939_session_put(session);
	}
	j1939_sessionlist_unlock(net);
}

static struct pernet_operations j1939_tp_pernet_ops = {
	.init = j1939_tp_pernet_init,
	.exit = j1939_tp_pernet_exit,
};

/* module init */
int __init j1939_tp_module_init(void)
{
	register_pernet_subsys(&j1939_tp_pernet_ops);
	return 0;
}

void j1939_tp_module_exit(void)
{
	unregister_pernet_subsys(&j1939_tp_pernet_ops);
}
