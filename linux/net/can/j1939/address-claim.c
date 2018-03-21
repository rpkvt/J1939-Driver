/*
 * Copyright (c) 2010-2011 EIA Electronics
 *
 * Authors:
 * Pieter Beyens <pieter.beyens@eia.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 */

/* J1939 Address Claiming.
 * Address Claiming in the kernel
 * - keeps track of the AC states of ECU's,
 * - resolves NAME<=>SA taking into account the AC states of ECU's.
 *
 * All Address Claim msgs (including host-originated msg) are processed
 * at the receive path (a sent msg is always received again via CAN echo).
 * As such, the processing of AC msgs is done in the order on which msgs
 * are sent on the bus.
 *
 * This module doesn't send msgs itself (e.g. replies on Address Claims),
 * this is the responsibility of a user space application or daemon.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/skbuff.h>
#include <linux/byteorder/generic.h>

#include "j1939-priv.h"

static inline name_t candata_to_name(const struct sk_buff *skb)
{
	return le64_to_cpup((__le64 *)skb->data);
}

static inline int ac_msg_is_request_for_ac(struct sk_buff *skb)
{
	struct j1939_sk_buff_cb *skcb = j1939_get_cb(skb);
	int req_pgn;

	if ((skb->len < 3) || (skcb->addr.pgn != PGN_REQUEST))
		return 0;

	req_pgn = skb->data[0] | (skb->data[1] << 8) | (skb->data[2] << 16);

	return req_pgn == PGN_ADDRESS_CLAIMED;
}

static int j1939_verify_outgoing_address_claim(struct sk_buff *skb)
{
	struct j1939_sk_buff_cb *skcb = j1939_get_cb(skb);

	if (skb->len != 8) {
		pr_notice("tx address claim with dlc %i\n", skb->len);
		return -EPROTO;
	}

	if (skcb->addr.src_name != candata_to_name(skb)) {
		pr_notice("tx address claim with different name\n");
		return -EPROTO;
	}

	if (skcb->addr.sa == J1939_NO_ADDR) {
		pr_notice("tx address claim with broadcast sa\n");
		return -EPROTO;
	}

	/* ac must always be a broadcast */
	if (skcb->addr.dst_name || (skcb->addr.da != J1939_NO_ADDR)) {
		pr_notice("tx address claim with dest, not broadcast\n");
		return -EPROTO;
	}
	return 0;
}

int j1939_fixup_address_claim(struct sk_buff *skb)
{
	int ret;
	u8 sa;
	struct j1939_sk_buff_cb *skcb = j1939_get_cb(skb);

	/* network mgmt: address claiming msgs */
	if (skcb->addr.pgn == PGN_ADDRESS_CLAIMED) {
		struct j1939_ecu *ecu;

		ret = j1939_verify_outgoing_address_claim(skb);
		/* return both when failure & when successful */
		if (ret < 0)
			return ret;
		ecu = j1939_ecu_find_by_name(skcb->addr.src_name,
					     skb->dev->ifindex);
		if (!ecu)
			return -ENODEV;

		if (ecu->sa != skcb->addr.sa)
			/* hold further traffic for ecu, remove from parent */
			j1939_ecu_remove_sa(ecu);
		put_j1939_ecu(ecu);
	} else if (skcb->addr.src_name) {
		/* assign source address */
		sa = j1939_name_to_sa(skcb->addr.src_name, skb->dev->ifindex);
		if (!j1939_address_is_unicast(sa) &&
		    !ac_msg_is_request_for_ac(skb)) {
			pr_notice("tx drop: invalid sa for name 0x%016llx\n",
				     skcb->addr.src_name);
			return -EADDRNOTAVAIL;
		}
		skcb->addr.sa = sa;
	}

	/* assign destination address */
	if (skcb->addr.dst_name) {
		sa = j1939_name_to_sa(skcb->addr.dst_name, skb->dev->ifindex);
		if (!j1939_address_is_unicast(sa)) {
			pr_notice("tx drop: invalid da for name 0x%016llx\n",
				     skcb->addr.dst_name);
			return -EADDRNOTAVAIL;
		}
		skcb->addr.da = sa;
	}
	return 0;
}

static void j1939_process_address_claim(struct sk_buff *skb, struct j1939_priv *priv)
{
	struct j1939_sk_buff_cb *skcb = j1939_get_cb(skb);
	struct j1939_ecu *ecu, *prev;
	name_t name;

	if (skb->len != 8) {
		pr_notice("rx address claim with wrong dlc %i\n", skb->len);
		return;
	}

	name = candata_to_name(skb);
	skcb->addr.src_name = name;
	if (!name) {
		pr_notice("rx address claim without name\n");
		return;
	}

	if (!j1939_address_is_valid(skcb->addr.sa)) {
		pr_notice("rx address claim with broadcast sa\n");
		return;
	}

	write_lock_bh(&priv->lock);

	ecu = _j1939_ecu_get_register(priv, name,
				      j1939_address_is_unicast(skcb->addr.sa));
	if (IS_ERR(ecu))
		goto done;

	if (skcb->addr.sa >= J1939_IDLE_ADDR) {
		_j1939_ecu_unregister(ecu);
		goto done;
	}

	/* save new SA */
	if (skcb->addr.sa != ecu->sa)
		_j1939_ecu_remove_sa(ecu);
	/* cancel pending (previous) address claim */
	hrtimer_try_to_cancel(&ecu->ac_timer);
	ecu->sa = skcb->addr.sa;

	prev = priv->ents[skcb->addr.sa].ecu;
	if (prev && prev != ecu) {
		if (ecu->name > prev->name) {
			_j1939_ecu_unregister(ecu);
			goto done;
		} else {
			/* kick prev */
			_j1939_ecu_unregister(prev);
		}
	}

	/* schedule timer in 250 msec to commit address change */
	hrtimer_start(&ecu->ac_timer, ktime_set(0, 250000000),
		      HRTIMER_MODE_REL);
	/* rxtime administration */
	ecu->rxtime = ktime_get();
 done:
	write_unlock_bh(&priv->lock);
}

void j1939_recv_address_claim(struct sk_buff *skb, struct j1939_priv *priv)
{
	struct j1939_sk_buff_cb *skcb = j1939_get_cb(skb);
	struct j1939_ecu *ecu;

	/* network mgmt */
	if (skcb->addr.pgn == PGN_ADDRESS_CLAIMED) {
		j1939_process_address_claim(skb, priv);
	} else if (j1939_address_is_unicast(skcb->addr.sa)) {
		ecu = _j1939_ecu_find_by_addr(skcb->addr.sa, priv);
		if (ecu) {
			/* source administration */
			ecu->rxtime = ktime_get();
			skcb->addr.src_name = ecu->name;
			put_j1939_ecu(ecu);
		}
	}

	/* assign destination stuff */
	ecu = _j1939_ecu_find_by_addr(skcb->addr.da, priv);
	if (ecu) {
		skcb->addr.dst_name = ecu->name;
		put_j1939_ecu(ecu);
	}
}
