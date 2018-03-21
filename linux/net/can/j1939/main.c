/*
 * Copyright (c) 2010-2011 EIA Electronics
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

static const char j1939_procname[] = "can-j1939";
struct proc_dir_entry *j1939_procdir;

/* LOWLEVEL CAN interface */

/* CAN_HDR: #bytes before can_frame data part */
#define CAN_HDR (offsetof(struct can_frame, data))

/* CAN_FTR: #bytes beyond data part */
#define CAN_FTR (sizeof(struct can_frame) - CAN_HDR - \
		 sizeof(((struct can_frame *)0)->data))

/* lowest layer */
static void j1939_can_recv(struct sk_buff *iskb, void *data)
{
	struct j1939_priv *priv = data;
	struct sk_buff *skb;
	struct j1939_sk_buff_cb *skcb;
	struct can_frame *cf;
	struct addr_ent *paddr;

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
	skb_pull(skb, CAN_HDR);

	/* fix length, set to dlc, with 8 maximum */
	skb_trim(skb, min_t(uint8_t, cf->can_dlc, 8));

	/* set addr */
	skcb = j1939_get_cb(skb);
	memset(skcb, 0, sizeof(*skcb));

	/* save incoming socket, without assigning the skb to it */
	skcb->insock = iskb->sk;
	skcb->priority = (cf->can_id & 0x1c000000) >> 26;
	skcb->addr.sa = cf->can_id;
	skcb->addr.pgn = (cf->can_id & 0x3ffff00) >> 8;
	if (pgn_is_pdu1(skcb->addr.pgn)) {
		/* Type 1: with destination address */
		skcb->addr.da = skcb->addr.pgn;
		/* normalize pgn: strip dst address */
		skcb->addr.pgn &= 0x3ff00;
	} else {
		/* set broadcast address */
		skcb->addr.da = J1939_NO_ADDR;
	}

	/* update local rxtime cache */
	write_lock_bh(&priv->lock);
	if (j1939_address_is_unicast(skcb->addr.sa)) {
		paddr = &priv->ents[skcb->addr.sa];
		paddr->rxtime = ktime_get();
		if (paddr->ecu && skcb->addr.pgn != PGN_ADDRESS_CLAIMED)
			paddr->ecu->rxtime = paddr->rxtime;
	}
	write_unlock_bh(&priv->lock);

	/* update localflags */
	read_lock_bh(&priv->lock);
	if (j1939_address_is_unicast(skcb->addr.sa) &&
	    priv->ents[skcb->addr.sa].nusers)
		skcb->src_flags |= ECU_LOCAL;
	if (j1939_address_is_unicast(skcb->addr.da) &&
			priv->ents[skcb->addr.da].nusers)
		skcb->dst_flags |= ECU_LOCAL;
	read_unlock_bh(&priv->lock);

	/* deliver into the j1939 stack ... */
	j1939_recv_address_claim(skb, priv);

	if (j1939_recv_transport(skb))
		/* this means the transport layer processed the message */
		goto done;
	j1939_recv(skb);
 done:
	kfree_skb(skb);
}

int j1939_send(struct sk_buff *skb)
{
	int ret, dlc;
	canid_t canid;
	struct j1939_sk_buff_cb *skcb = j1939_get_cb(skb);
	struct can_frame *cf;

	if (skb->len > 8)
	{
		/* re-route via transport protocol */
		return j1939_send_transport(skb);
	}

	/* apply sanity checks */
	skcb->addr.pgn &= (pgn_is_pdu1(skcb->addr.pgn)) ? 0x3ff00 : 0x3ffff;
	if (skcb->priority > 7)
		skcb->priority = 6;

	ret = j1939_fixup_address_claim(skb);
	if (unlikely(ret))
		goto failed;
	dlc = skb->len;
	if (dlc > 8) {
		ret = -EMSGSIZE;
		goto failed;
	}

	/* re-claim the CAN_HDR from the SKB */
	cf = (void *)skb_push(skb, CAN_HDR);

	/* make it a full can frame again */
	skb_put(skb, CAN_FTR + (8 - dlc));

	canid = CAN_EFF_FLAG |
		(skcb->addr.sa) |
		((skcb->priority & 0x7) << 26);
	if (pgn_is_pdu1(skcb->addr.pgn))
		canid |= ((skcb->addr.pgn & 0x3ff00) << 8) |
			(skcb->addr.da << 8);
	else
		canid |= ((skcb->addr.pgn & 0x3ffff) << 8);

	cf->can_id = canid;
	cf->can_dlc = dlc;

	return can_send(skb, 1);
 failed:
	consume_skb(skb);
	return ret;
}
EXPORT_SYMBOL_GPL(j1939_send);

/* iterate over ECUs,
 * and register flagged ECUs on their claimed SA
 */
static void j1939_priv_ac_task(unsigned long val)
{
	struct j1939_priv *priv = (void *)val;
	struct j1939_ecu *ecu;

	write_lock_bh(&priv->lock);
	list_for_each_entry(ecu, &priv->ecus, list) {
		/* next 2 (read & set) could be merged into xxx? */
		if (!atomic_read(&ecu->ac_delay_expired))
			continue;

		atomic_set(&ecu->ac_delay_expired, 0);
		if (j1939_address_is_unicast(ecu->sa)) {
			ecu->priv->ents[ecu->sa].ecu = ecu;
			ecu->priv->ents[ecu->sa].nusers += ecu->nusers;
		}
	}
	write_unlock_bh(&priv->lock);
}

/* NETDEV MANAGEMENT */

/* values for can_rx_(un)register */
#define J1939_CAN_ID CAN_EFF_FLAG
#define J1939_CAN_MASK (CAN_EFF_FLAG | CAN_RTR_FLAG)

static DEFINE_SPINLOCK(j1939_netdev_lock);

int j1939_netdev_start(struct net_device *netdev)
{
	struct j1939_priv *priv;
	int ret;

	spin_lock(&j1939_netdev_lock);
	priv = j1939_priv_get(netdev);
	spin_unlock(&j1939_netdev_lock);
	if (priv)
		return 0;

	/* create j1939_priv */
	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	/* TODO: use tasklet_hrtimer_init() instead */
	tasklet_init(&priv->ac_task, j1939_priv_ac_task, (unsigned long)priv);
	rwlock_init(&priv->lock);
	INIT_LIST_HEAD(&priv->ecus);
	priv->netdev = netdev;
	priv->ifindex = netdev->ifindex;
	kref_init(&priv->kref);
	dev_hold(netdev);

	/* add CAN handler */
	ret = can_rx_register(&init_net, netdev, J1939_CAN_ID, J1939_CAN_MASK,
			      j1939_can_recv, priv, "j1939", NULL);
	if (ret < 0)
		goto out_dev_put;

	spin_lock(&j1939_netdev_lock);
	if (j1939_priv_get(netdev)) {
		/* Someone was faster than us, use their priv and roll
		 * back our's. */
		spin_unlock(&j1939_netdev_lock);
		goto out_rx_unregister;
	}
	j1939_priv_set(netdev, priv);
	spin_unlock(&j1939_netdev_lock);

	return 0;

 out_rx_unregister:
	can_rx_unregister(&init_net, netdev, J1939_CAN_ID, J1939_CAN_MASK,
			  j1939_can_recv, priv);
 out_dev_put:
	dev_put(netdev);
	kfree(priv);

	return ret;
}

void j1939_netdev_stop(struct net_device *netdev)
{
	struct j1939_priv *priv;

	spin_lock(&j1939_netdev_lock);
	priv = __j1939_priv_get(netdev);
	j1939_priv_put(priv);
	spin_unlock(&j1939_netdev_lock);
}

/* device interface */
void __j1939_priv_release(struct kref *kref)
{
	struct j1939_priv *priv = container_of(kref, struct j1939_priv, kref);
	struct j1939_ecu *ecu;

	can_rx_unregister(&init_net, priv->netdev, J1939_CAN_ID, J1939_CAN_MASK,
			  j1939_can_recv, priv);

	tasklet_disable_nosync(&priv->ac_task);

	/* remove pending transport protocol sessions */
	j1939tp_rmdev_notifier(priv->netdev);

	/* cleanup priv */
	write_lock_bh(&priv->lock);
	/* TODO: list_for_each() */
	while (!list_empty(&priv->ecus)) {
		ecu = list_first_entry(&priv->ecus, struct j1939_ecu, list);
		_j1939_ecu_unregister(ecu);
	}
	write_unlock_bh(&priv->lock);

	/* unlink from netdev */
	j1939_priv_set(priv->netdev, NULL);

	dev_put(priv->netdev);
	kfree(priv);
}

struct j1939_priv *j1939_priv_get(struct net_device *dev)
{
	struct j1939_priv *priv;

	if (dev->type != ARPHRD_CAN)
		return NULL;

	priv = __j1939_priv_get(dev);
	if (priv)
		kref_get(&priv->kref);

	return priv;
}

struct j1939_priv *j1939_priv_get_by_ifindex(int ifindex)
{
	struct j1939_priv *priv;
	struct net_device *netdev;

	printk("%s: ifindex=%d\n", __func__, ifindex);

	netdev = dev_get_by_index(&init_net, ifindex);
	if (!netdev)
		return NULL;

	priv = j1939_priv_get(netdev);
	dev_put(netdev);

	return priv;
}

static int j1939_netdev_notify(struct notifier_block *nb,
			       unsigned long msg, void *data)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(data);

	if (!net_eq(dev_net(netdev), &init_net))
		return NOTIFY_DONE;

	if (netdev->type != ARPHRD_CAN)
		return NOTIFY_DONE;

	switch (msg) {
	case NETDEV_UNREGISTER:
		j1939tp_rmdev_notifier(netdev);
		j1939sk_netdev_event(netdev, ENODEV);
		break;

	case NETDEV_DOWN:
		j1939sk_netdev_event(netdev, ENETDOWN);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block j1939_netdev_notifier = {
	.notifier_call = j1939_netdev_notify,
};

/* proc access to the addr+name database */
static int j1939_proc_show_addr(struct seq_file *sqf, void *v)
{
	struct net_device *netdev;
	struct j1939_priv *priv;
	int j;

	seq_puts(sqf, "iface\tsa\t#users\n");
	rcu_read_lock();
	for_each_netdev_rcu(&init_net, netdev) {
		priv = j1939_priv_get(netdev);
		if (!priv)
			continue;
		read_lock_bh(&priv->lock);
		for (j = 0; j < 0xfe; ++j) {
			if (!priv->ents[j].nusers)
				continue;
			seq_printf(sqf, "%s\t%02x\t%i\n",
				   netdev->name, j, priv->ents[j].nusers);
		}
		read_unlock_bh(&priv->lock);
		j1939_priv_put(priv);
	}
	rcu_read_unlock();
	return 0;
}

static int j1939_proc_show_name(struct seq_file *sqf, void *v)
{
	struct net_device *netdev;
	struct j1939_priv *priv;
	struct j1939_ecu *ecu;

	seq_puts(sqf, "iface\tname\tsa\t#users\n");
	rcu_read_lock();
	for_each_netdev_rcu(&init_net, netdev) {
		priv = j1939_priv_get(netdev);
		if (!priv)
			continue;
		read_lock_bh(&priv->lock);
		list_for_each_entry(ecu, &priv->ecus, list)
			seq_printf(sqf, "%s\t%016llx\t%02x%s\t%i\n",
				   netdev->name, ecu->name, ecu->sa,
				   (priv->ents[ecu->sa].ecu == ecu) ? "" : "?",
				   ecu->nusers);
		read_unlock_bh(&priv->lock);
		j1939_priv_put(priv);
	}
	rcu_read_unlock();
	return 0;
}

static int j1939_proc_open_addr(struct inode *inode, struct file *file)
{
	return single_open(file, j1939_proc_show_addr, NULL);
}

static int j1939_proc_open_name(struct inode *inode, struct file *file)
{
	return single_open(file, j1939_proc_show_name, NULL);
}

static const struct file_operations j1939_proc_ops_addr = {
	.owner		= THIS_MODULE,
	.open		= j1939_proc_open_addr,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations j1939_proc_ops_name = {
	.owner		= THIS_MODULE,
	.open		= j1939_proc_open_name,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* MODULE interface */
static __init int j1939_module_init(void)
{
	int ret;

	pr_info("can: SAE J1939\n");

	/* create /proc/net/can directory */
	j1939_procdir = proc_mkdir(j1939_procname, init_net.proc_net);
	if (!j1939_procdir)
		return -EINVAL;

	ret = register_netdevice_notifier(&j1939_netdev_notifier);
	if (ret)
		goto fail_notifier;

	ret = can_proto_register(&j1939_can_proto);
	if (ret < 0) {
		pr_err("can: registration of j1939 protocol failed\n");
		goto fail_sk;
	}
	ret = j1939tp_module_init();
	if (ret < 0)
		goto fail_tp;

	if (!proc_create("addr", 0444, j1939_procdir, &j1939_proc_ops_addr))
		goto fail_addr;
	if (!proc_create("name", 0444, j1939_procdir, &j1939_proc_ops_name))
		goto fail_name;
	return 0;

 fail_name:
	remove_proc_entry("addr", j1939_procdir);
 fail_addr:
	j1939tp_module_exit();
 fail_tp:
	can_proto_unregister(&j1939_can_proto);
 fail_sk:
	unregister_netdevice_notifier(&j1939_netdev_notifier);
 fail_notifier:
	proc_remove(j1939_procdir);
	j1939_procdir = NULL;
	return ret;
}

static __exit void j1939_module_exit(void)
{
	remove_proc_entry("name", j1939_procdir);
	remove_proc_entry("addr", j1939_procdir);
	j1939tp_module_exit();

	can_proto_unregister(&j1939_can_proto);

	unregister_netdevice_notifier(&j1939_netdev_notifier);

	proc_remove(j1939_procdir);
	j1939_procdir = NULL;
}

module_init(j1939_module_init);
module_exit(j1939_module_exit);
