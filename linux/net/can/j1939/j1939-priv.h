/*
 * j1939-priv.h
 *
 * Copyright (c) 2010-2011 EIA Electronics
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _J1939_PRIV_H_
#define _J1939_PRIV_H_

#include <linux/atomic.h>
#include <linux/if_arp.h>
#include <linux/interrupt.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/can/can-ml.h>
#include <linux/can/j1939.h>

#include <net/sock.h>

#include "../af_can.h"

/* TODO: return ENETRESET on busoff. */

#define PGN_REQUEST 0x0ea00
#define PGN_ADDRESS_CLAIMED 0x0ee00
#define PGN_MAX 0x3ffff

#define SA_MAX_UNICAST 0xfd

/* j1939 devices */
struct j1939_ecu {
	struct list_head list;
	ktime_t rxtime;
	name_t name;
	u8 sa;

	/* atomic flag, set by ac_timer
	 * cleared/processed by segment's tasklet
	 * indicates that this ecu successfully claimed @sa as its address
	 * By communicating this from the ac_timer event to segments tasklet,
	 * a context locking problem is solved. All other 'ecu readers'
	 * must only lock with _bh, not with _irq.
	 */
	atomic_t ac_delay_expired;
	struct hrtimer ac_timer;
	struct kref kref;
	struct j1939_priv *priv;

	/* count users, to help transport protocol decide for interaction */
	int nusers;
};

struct j1939_priv {
	struct list_head ecus;
	/* local list entry in priv
	 * These allow irq (& softirq) context lookups on j1939 devices
	 * This approach (separate lists) is done as the other 2 alternatives
	 * are not easier or even wrong
	 * 1) using the pure kobject methods involves mutexes, which are not
	 *    allowed in irq context.
	 * 2) duplicating data structures would require a lot of synchronization
	 *    code
	 * usage:
	 */

	/* segments need a lock to protect the above list */
	rwlock_t lock;

	int ifindex;			/* TODO: redundant with netdev? */
	struct net_device *netdev;

	/* list of 256 ecu ptrs, that cache the claimed addresses.
	 * also protected by the above lock
	 * don't use directly, use j1939_ecu_set_address() instead
	 */
	struct addr_ent {
		ktime_t rxtime;
		struct j1939_ecu *ecu;
		/* count users, to help transport protocol */
		int nusers;
	} ents[256];

	/* tasklet to process ecu address claimed events.
	 * These events raise in hardirq context. Signalling the event
	 * and scheduling this tasklet successfully moves the
	 * event to softirq context
	 */
	struct tasklet_struct ac_task;

	struct kref kref;
};

void put_j1939_ecu(struct j1939_ecu *ecu);

static inline void get_j1939_ecu(struct j1939_ecu *dut)
{
	kref_get(&dut->kref);
}

/* keep the cache of what is local */
void j1939_addr_local_get(struct j1939_priv *priv, u8 sa);
void j1939_addr_local_put(struct j1939_priv *priv, u8 sa);
void j1939_name_local_get(struct j1939_priv *priv, name_t name);
void j1939_name_local_put(struct j1939_priv *priv, name_t name);

/* conversion function between (struct sock | struct sk_buff)->sk_priority
 * from linux and j1939 priority field
 */
static inline priority_t j1939_prio(int sk_priority)
{
	if (sk_priority < 0)
		return 6; /* default */
	else if (sk_priority > 7)
		return 0;
	else
		return 7 - sk_priority;
}

static inline int j1939_to_sk_priority(priority_t j1939_prio)
{
	return 7 - j1939_prio;
}

static inline bool j1939_address_is_valid(u8 sa)
{
	return sa != J1939_NO_ADDR;
}

static inline bool j1939_address_is_unicast(u8 sa)
{
	return sa <= SA_MAX_UNICAST;
}

static inline bool pgn_is_pdu1(pgn_t pgn)
{
	/* ignore dp & res bits for this */
	return (pgn & 0xff00) < 0xf000;
}

/* function to see if pgn is to be evaluated */
static inline bool pgn_is_valid(pgn_t pgn)
{
	return pgn <= PGN_MAX;
}

/* test function to avoid non-zero DA placeholder
 * for pdu1 pgn's */
static inline bool pgn_is_clean_pdu(pgn_t pgn)
{
	return pgn_is_pdu1(pgn) ? !(pgn & 0xff) : 1;
}

/* utility to correctly unregister a SA */
static inline void _j1939_ecu_remove_sa(struct j1939_ecu *ecu)
{
	if (!j1939_address_is_unicast(ecu->sa))
		return;
	if (ecu->priv && ecu->priv->ents[ecu->sa].ecu == ecu) {
		ecu->priv->ents[ecu->sa].ecu = NULL;
		ecu->priv->ents[ecu->sa].nusers -= ecu->nusers;
	}
}

static inline void j1939_ecu_remove_sa(struct j1939_ecu *ecu)
{
	if (!j1939_address_is_unicast(ecu->sa))
		return;
	write_lock_bh(&ecu->priv->lock);
	_j1939_ecu_remove_sa(ecu);
	write_unlock_bh(&ecu->priv->lock);
}

u8 j1939_name_to_sa(name_t name, int ifindex);
struct j1939_ecu *_j1939_ecu_find_by_addr(u8 sa, struct j1939_priv *priv);
struct j1939_ecu *j1939_ecu_find_by_name(name_t name, int ifindex);
/* find_by_name, with kref & read_lock taken */
struct j1939_ecu *j1939_ecu_find_priv_default_tx(int ifindex, name_t *pname,
						 u8 *paddr);
extern struct proc_dir_entry *j1939_procdir;

struct j1939_addr {
	name_t src_name;
	name_t dst_name;
	pgn_t pgn;

	u8 sa;
	u8 da;
};

/* control buffer of the sk_buff */
struct j1939_sk_buff_cb {
	struct j1939_addr addr;
	priority_t priority;

	/* Flags for quick lookups during skb processing
	 * These are set in the receive path only
	 */
	int src_flags;
	int dst_flags;

#define ECU_LOCAL 1
	/*  Flags for modifying the transport protocol*/ 
	int tpflags;
#define BAM_NODELAY 1
	/* for tx, MSG_SYN will be used to sync on sockets */
	int msg_flags;

	/* j1939 clones incoming skb's.
	 * insock saves the incoming skb->sk
	 * to determine local generated packets
	 */
	struct sock *insock;
};

static inline struct j1939_sk_buff_cb *j1939_get_cb(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct j1939_sk_buff_cb) > sizeof(skb->cb));

	return (struct j1939_sk_buff_cb *)skb->cb;
}


//Check if we want to disable the normal BAM 50 ms delay
//Return 0 if we want to disable the delay
//Return 1 if we want to keep the delay
static inline int j1939cb_use_bamdelay(const struct j1939_sk_buff_cb *skcb)
{
	//printk(KERN_ALERT "DEBUG: Passed %s %d \n",__FUNCTION__,__LINE__);
	//printk(KERN_ALERT "DEBUG: skcb->tpflags state: %d\n",skcb->tpflags);

	if(skcb->tpflags & BAM_NODELAY)
	{
		return 0;
	}

	return 1;
}

static inline int j1939cb_is_broadcast(const struct j1939_sk_buff_cb *skcb)
{
	return (!skcb->addr.dst_name && (skcb->addr.da == 0xff));
}

int j1939_send(struct sk_buff *);
void j1939_recv(struct sk_buff *);

/* stack entries */
int j1939_send_transport(struct sk_buff *);
int j1939_recv_transport(struct sk_buff *);
int j1939_fixup_address_claim(struct sk_buff *);
void j1939_recv_address_claim(struct sk_buff *, struct j1939_priv *priv);

/* network management */

/* j1939_ecu_get_register
 * 'create' & 'register' & 'get' new ecu
 * when a matching ecu already exists, then that is returned
 */
struct j1939_ecu *_j1939_ecu_get_register(struct j1939_priv *priv,
					  name_t name, bool create_if_necessary);

/* unregister must be called with lock held */
void _j1939_ecu_unregister(struct j1939_ecu *);

int j1939_netdev_start(struct net_device *);
void j1939_netdev_stop(struct net_device *);

void __j1939_priv_release(struct kref *kref);
struct j1939_priv *j1939_priv_get(struct net_device *dev);
struct j1939_priv *j1939_priv_get_by_ifindex(int ifindex);


static inline void j1939_priv_set(struct net_device *dev, struct j1939_priv *priv)
{
	struct can_ml_priv *can_ml_priv = dev->ml_priv;

	can_ml_priv->j1939_priv = priv;
}

static inline struct j1939_priv *__j1939_priv_get(struct net_device *dev)
{
	struct can_ml_priv *can_ml_priv = dev->ml_priv;

	return can_ml_priv->j1939_priv;
}

static inline void j1939_priv_put(struct j1939_priv *priv)
{
	kref_put(&priv->kref, __j1939_priv_release);
}

/* notify/alert all j1939 sockets bound to ifindex */
void j1939sk_netdev_event(struct net_device *netdev, int error_code);
int j1939tp_rmdev_notifier(struct net_device *netdev);

/* decrement pending skb for a j1939 socket */
void j1939_sock_pending_del(struct sock *sk);

/* separate module-init/modules-exit's */
__init int j1939tp_module_init(void);

void j1939tp_module_exit(void);

/* CAN protocol */
extern const struct can_proto j1939_can_proto;

#endif /* _J1939_PRIV_H_ */
