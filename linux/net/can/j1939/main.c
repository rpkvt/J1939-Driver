// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2010-2011 EIA Electronics
 *
 * Authors:
 * Kurt Van Dijck <kurt.van.dijck@eia.be>
 * Pieter Beyens <pieter.beyens@eia.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 */

/* Core of can-j1939 that links j1939 to CAN. */

#include <linux/version.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/list.h>
#include <linux/if_arp.h>
#include <net/tcp_states.h>

#include <linux/can.h>
#include <linux/can/core.h>
#include "j1939-priv.h"

MODULE_DESCRIPTION("PF_CAN SAE J1939");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("EIA Electronics (Kurt Van Dijck & Pieter Beyens)");
MODULE_ALIAS("can-proto-" __stringify(CAN_J1939));

/* LOWLEVEL CAN interface */

/* CAN_HDR: #bytes before can_frame data part */
#define J1939_CAN_HDR (offsetof(struct can_frame, data))

/* CAN_FTR: #bytes beyond data part */
#define J1939_CAN_FTR (sizeof(struct can_frame) - J1939_CAN_HDR - \
		 sizeof(((struct can_frame *)0)->data))

/* lowest layer */
static void j1939_can_recv(struct sk_buff *iskb, void *data)
{
	struct j1939_priv *priv = data;
	struct net_device *ndev = priv->ndev;
	struct net *net = dev_net(ndev);
	struct sk_buff *skb;
	struct j1939_sk_buff_cb *skcb;
	struct can_frame *cf;

	/* create a copy of the skb
	 * j1939 only delivers the real data bytes,
	 * the header goes into sockaddr.
	 * j1939 may not touch the incoming skb in such way
	 */
	skb = skb_clone(iskb, GFP_ATOMIC);

	/* get a pointer to the header of the skb
	 * the skb payload (pointer) is moved, so that the next skb_data
	 * returns the actual payload
	 */
	cf = (void *)skb->data;
	skb_pull(skb, J1939_CAN_HDR);

	/* fix length, set to dlc, with 8 maximum */
	skb_trim(skb, min_t(uint8_t, cf->can_dlc, 8));

	/* set addr */
	skcb = j1939_skb_to_cb(skb);
	memset(skcb, 0, sizeof(*skcb));

	/* save incoming socket, without assigning the skb to it */
	skcb->insock = iskb->sk;
	skcb->priority = (cf->can_id >> 26) & 0x7;
	skcb->addr.sa = cf->can_id;
	skcb->addr.pgn = (cf->can_id >> 8) & J1939_PGN_MAX;
	if (j1939_pgn_is_pdu1(skcb->addr.pgn)) {
		/* Type 1: with destination address */
		skcb->addr.da = skcb->addr.pgn;
		/* normalize pgn: strip dst address */
		skcb->addr.pgn &= 0x3ff00;
	} else {
		/* set broadcast address */
		skcb->addr.da = J1939_NO_ADDR;
	}

	/* update localflags */
	read_lock_bh(&priv->lock);
	if (j1939_address_is_unicast(skcb->addr.sa) &&
	    priv->ents[skcb->addr.sa].nusers)
		skcb->src_flags |= J1939_ECU_LOCAL;
	if (j1939_address_is_unicast(skcb->addr.da) &&
	    priv->ents[skcb->addr.da].nusers)
		skcb->dst_flags |= J1939_ECU_LOCAL;
	read_unlock_bh(&priv->lock);

	/* deliver into the j1939 stack ... */
	j1939_ac_recv(priv, skb);

	if (j1939_tp_recv(net, skb))
		/* this means the transport layer processed the message */
		goto done;
	j1939_sk_recv(skb);
 done:
	kfree_skb(skb);
}

/* NETDEV MANAGEMENT */

/* values for can_rx_(un)register */
#define J1939_CAN_ID CAN_EFF_FLAG
#define J1939_CAN_MASK (CAN_EFF_FLAG | CAN_RTR_FLAG)

static DEFINE_SPINLOCK(j1939_netdev_lock);

static struct j1939_priv *j1939_priv_create(struct net_device *ndev)
{
	struct j1939_priv *priv;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	rwlock_init(&priv->lock);
	INIT_LIST_HEAD(&priv->ecus);
	priv->ndev = ndev;
	kref_init(&priv->kref);
	dev_hold(ndev);

	return priv;
}

static inline void j1939_priv_set(struct net_device *ndev, struct j1939_priv *priv)
{
	struct can_ml_priv *can_ml_priv = ndev->ml_priv;

	can_ml_priv->j1939_priv = priv;
}

static void __j1939_priv_release(struct kref *kref)
{
	struct j1939_priv *priv = container_of(kref, struct j1939_priv, kref);
	struct net_device *ndev = priv->ndev;
	struct j1939_ecu *ecu, *tmp;

	can_rx_unregister(dev_net(ndev), ndev, J1939_CAN_ID, J1939_CAN_MASK,
			  j1939_can_recv, priv);

	/* remove pending transport protocol sessions */
	j1939_tp_rmdev_notifier(ndev);

	/* cleanup priv */
	write_lock_bh(&priv->lock);
	list_for_each_entry_safe(ecu, tmp, &priv->ecus, list)
		j1939_ecu_unregister_locked(ecu);
	write_unlock_bh(&priv->lock);

	/* unlink from netdev */
	j1939_priv_set(ndev, NULL);

	dev_put(ndev);
	kfree(priv);
}

void j1939_priv_put(struct j1939_priv *priv)
{
	kref_put(&priv->kref, __j1939_priv_release);
}

int j1939_netdev_start(struct net *net, struct net_device *ndev)
{
	struct j1939_priv *priv;
	int ret;

	spin_lock(&j1939_netdev_lock);
	priv = j1939_priv_get(ndev);
	spin_unlock(&j1939_netdev_lock);
	if (priv)
		return 0;

	priv = j1939_priv_create(ndev);
	if (!priv)
		return -ENOMEM;

	/* add CAN handler */
	ret = can_rx_register(net, ndev, J1939_CAN_ID, J1939_CAN_MASK,
			      j1939_can_recv, priv, "j1939", NULL);
	if (ret < 0)
		goto out_dev_put;

	spin_lock(&j1939_netdev_lock);
	if (j1939_priv_get(ndev)) {
		/* Someone was faster than us, use their priv and roll
		 * back our's.
		 */
		spin_unlock(&j1939_netdev_lock);
		goto out_rx_unregister;
	}
	j1939_priv_set(ndev, priv);
	spin_unlock(&j1939_netdev_lock);

	return 0;

 out_rx_unregister:
	can_rx_unregister(net, ndev, J1939_CAN_ID, J1939_CAN_MASK,
			  j1939_can_recv, priv);
 out_dev_put:
	dev_put(ndev);
	kfree(priv);

	return ret;
}

/* get pointer to priv without increasing ref counter */
static inline struct j1939_priv *j1939_ndev_to_priv(struct net_device *ndev)
{
	struct can_ml_priv *can_ml_priv = ndev->ml_priv;

	return can_ml_priv->j1939_priv;
}

void j1939_netdev_stop(struct net_device *ndev)
{
	struct j1939_priv *priv;

	spin_lock(&j1939_netdev_lock);
	priv = j1939_ndev_to_priv(ndev);
	j1939_priv_put(priv);
	spin_unlock(&j1939_netdev_lock);
}

struct j1939_priv *j1939_priv_get(struct net_device *ndev)
{
	struct j1939_priv *priv;

	if (ndev->type != ARPHRD_CAN)
		return NULL;

	priv = j1939_ndev_to_priv(ndev);
	if (priv)
		kref_get(&priv->kref);

	return priv;
}

static struct j1939_priv *j1939_priv_get_by_index(struct net *net, int ifindex)
{
	struct j1939_priv *priv;
	struct net_device *ndev;

	ndev = dev_get_by_index(net, ifindex);
	if (!ndev)
		return NULL;

	priv = j1939_priv_get(ndev);
	dev_put(ndev);

	return priv;
}

int j1939_send(struct net *net, struct sk_buff *skb)
{
	int ret, dlc;
	canid_t canid;
	struct j1939_sk_buff_cb *skcb = j1939_skb_to_cb(skb);
	struct j1939_priv *priv;
	struct can_frame *cf;

	priv = j1939_priv_get_by_index(net, skb->dev->ifindex);
	if (!priv) {
		ret = -EINVAL;
		goto failed;
	}

	if (skb->len > 8) {
		/* re-route via transport protocol */
		ret = j1939_tp_send(net, priv, skb);
		j1939_priv_put(priv);
		return ret;
	}

	/* apply sanity checks */
	if (j1939_pgn_is_pdu1(skcb->addr.pgn))
		skcb->addr.pgn &= 0x3ff00;
	else
		skcb->addr.pgn &= J1939_PGN_MAX;

	if (skcb->priority > 7)
		skcb->priority = 6;

	ret = j1939_ac_fixup(priv, skb);
	j1939_priv_put(priv);
	if (unlikely(ret))
		goto failed;
	dlc = skb->len;
	if (dlc > 8) {
		ret = -EMSGSIZE;
		goto failed;
	}

	/* re-claim the CAN_HDR from the SKB */
	cf = skb_push(skb, J1939_CAN_HDR);

	/* make it a full can frame again */
	skb_put(skb, J1939_CAN_FTR + (8 - dlc));

	canid = CAN_EFF_FLAG |
		(skcb->addr.sa) |
		((skcb->priority & 0x7) << 26);
	if (j1939_pgn_is_pdu1(skcb->addr.pgn))
		canid |= ((skcb->addr.pgn & 0x3ff00) << 8) |
			(skcb->addr.da << 8);
	else
		canid |= ((skcb->addr.pgn & J1939_PGN_MAX) << 8);

	cf->can_id = canid;
	cf->can_dlc = dlc;

	return can_send(skb, 1);
 failed:
	consume_skb(skb);
	return ret;
}

static int j1939_netdev_notify(struct notifier_block *nb,
			       unsigned long msg, void *data)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(data);

	if (!net_eq(dev_net(ndev), &init_net))
		return NOTIFY_DONE;

	if (ndev->type != ARPHRD_CAN)
		return NOTIFY_DONE;

	switch (msg) {
	case NETDEV_UNREGISTER:
		j1939_tp_rmdev_notifier(ndev);
		j1939_sk_netdev_event(ndev, ENODEV);
		break;

	case NETDEV_DOWN:
		j1939_sk_netdev_event(ndev, ENETDOWN);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block j1939_netdev_notifier = {
	.notifier_call = j1939_netdev_notify,
};

/* MODULE interface */
static __init int j1939_module_init(void)
{
	int ret;

	pr_info("can: SAE J1939\n");

	ret = register_netdevice_notifier(&j1939_netdev_notifier);
	if (ret)
		goto fail_notifier;

	ret = can_proto_register(&j1939_can_proto);
	if (ret < 0) {
		pr_err("can: registration of j1939 protocol failed\n");
		goto fail_sk;
	}
	ret = j1939_tp_module_init();
	if (ret < 0)
		goto fail_tp;

	return 0;

 fail_tp:
	can_proto_unregister(&j1939_can_proto);
 fail_sk:
	unregister_netdevice_notifier(&j1939_netdev_notifier);
 fail_notifier:
	return ret;
}

static __exit void j1939_module_exit(void)
{
	j1939_tp_module_exit();

	can_proto_unregister(&j1939_can_proto);

	unregister_netdevice_notifier(&j1939_netdev_notifier);
}

module_init(j1939_module_init);
module_exit(j1939_module_exit);
