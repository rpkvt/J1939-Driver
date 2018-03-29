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

/* bus for j1939 remote devices
 * Since rtnetlink, no real bus is used.
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/workqueue.h>

#include "j1939-priv.h"

#define ecu_dbg(_ecu, fmt, ...) \
{ \
	struct j1939_ecu *ecu = _ecu; \
	pr_debug("j1939-%i,%016llx,%02x: " fmt, ecu->priv->ndev->ifindex, \
		 ecu->name, ecu->addr, ##__VA_ARGS__); \
}

static void __j1939_ecu_release(struct kref *kref)
{
	struct j1939_ecu *ecu = container_of(kref, struct j1939_ecu, kref);

	kfree(ecu);
}

void j1939_ecu_put(struct j1939_ecu *ecu)
{
	kref_put(&ecu->kref, __j1939_ecu_release);
}

static void j1939_ecu_get(struct j1939_ecu *ecu)
{
	kref_get(&ecu->kref);
}

static bool j1939_ecu_is_mapped_locked(struct j1939_ecu *ecu)
{
	struct j1939_priv *priv = ecu->priv;

	lockdep_assert_held(&priv->lock);

	return j1939_ecu_find_by_addr_locked(priv, ecu->addr) == ecu;
}

/* ECU device interface */
/* map ECU to a bus address space */
static void j1939_ecu_map_locked(struct j1939_ecu *ecu)
{
	lockdep_assert_held(&ecu->priv->lock);

	if (!j1939_address_is_unicast(ecu->addr))
		return;

	ecu->priv->ents[ecu->addr].ecu = ecu;
	ecu->priv->ents[ecu->addr].nusers += ecu->nusers;
}

/* unmap ECU from a bus address space */
void j1939_ecu_unmap_locked(struct j1939_ecu *ecu)
{
	lockdep_assert_held(&ecu->priv->lock);

	if (!j1939_address_is_unicast(ecu->addr))
		return;

	if (!j1939_ecu_is_mapped_locked(ecu))
		return;

	ecu->priv->ents[ecu->addr].ecu = NULL;
	ecu->priv->ents[ecu->addr].nusers -= ecu->nusers;
}

void j1939_ecu_unmap(struct j1939_ecu *ecu)
{
	write_lock_bh(&ecu->priv->lock);
	j1939_ecu_unmap_locked(ecu);
	write_unlock_bh(&ecu->priv->lock);
}

static enum hrtimer_restart j1939_ecu_timer_handler(struct hrtimer *hrtimer)
{
	struct j1939_ecu *ecu =
		container_of(hrtimer, struct j1939_ecu, ac_timer);
	struct j1939_priv *priv = ecu->priv;

	write_lock_bh(&priv->lock);
	/* TODO: can we test if ecu->addr is unicast before starting
	 * the timer?
	 */
	j1939_ecu_map_locked(ecu);
	write_unlock_bh(&priv->lock);

	return HRTIMER_NORESTART;
}

struct j1939_ecu *j1939_ecu_create_locked(struct j1939_priv *priv, name_t name)
{
	struct j1939_ecu *ecu;

	lockdep_assert_held(&priv->lock);

	ecu = kzalloc(sizeof(*ecu), gfp_any());
	if (!ecu)
		return ERR_PTR(-ENOMEM);
	kref_init(&ecu->kref);
	ecu->addr = J1939_IDLE_ADDR;
	ecu->name = name;

	hrtimer_init(&ecu->ac_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_SOFT);
	ecu->ac_timer.function = j1939_ecu_timer_handler;
	INIT_LIST_HEAD(&ecu->list);

	ecu->priv = priv;
	list_add_tail(&ecu->list, &priv->ecus);

	ecu_dbg(ecu, "%s\n", __func__);
	return ecu;
}

void j1939_ecu_unregister_locked(struct j1939_ecu *ecu)
{
	lockdep_assert_held(&ecu->priv->lock);

	ecu_dbg(ecu, "unregister\n");
	hrtimer_cancel(&ecu->ac_timer);

	j1939_ecu_unmap_locked(ecu);
	list_del_init(&ecu->list);
	j1939_ecu_put(ecu);
}

struct j1939_ecu *j1939_ecu_find_by_addr_locked(struct j1939_priv *priv, u8 addr)
{
	lockdep_assert_held(&priv->lock);

	return priv->ents[addr].ecu;
}

struct j1939_ecu *j1939_ecu_get_by_addr_locked(struct j1939_priv *priv, u8 addr)
{
	struct j1939_ecu *ecu;

	lockdep_assert_held(&priv->lock);

	if (!j1939_address_is_unicast(addr))
		return NULL;

	ecu = j1939_ecu_find_by_addr_locked(priv, addr);
	if (ecu)
		j1939_ecu_get(ecu);

	return ecu;
}

struct j1939_ecu *j1939_ecu_get_by_addr(struct j1939_priv *priv, u8 addr)
{
	struct j1939_ecu *ecu;

	read_lock_bh(&priv->lock);
	ecu = j1939_ecu_get_by_addr_locked(priv, addr);
	read_unlock_bh(&priv->lock);

	return ecu;
}

/* get pointer to ecu without increasing ref counter */
struct j1939_ecu *j1939_ecu_find_by_name_locked(struct j1939_priv *priv, name_t name)
{
	struct j1939_ecu *ecu;

	lockdep_assert_held(&priv->lock);

	list_for_each_entry(ecu, &priv->ecus, list) {
		if (ecu->name == name)
			return ecu;
	}

	return NULL;
}

struct j1939_ecu *j1939_ecu_get_by_name_locked(struct j1939_priv *priv, name_t name)
{
	struct j1939_ecu *ecu;

	lockdep_assert_held(&priv->lock);

	if (!name)
		return NULL;

	ecu = j1939_ecu_find_by_name_locked(priv, name);
	if (ecu)
		j1939_ecu_get(ecu);

	return ecu;
}

struct j1939_ecu *j1939_ecu_get_by_name(struct j1939_priv *priv, name_t name)
{
	struct j1939_ecu *ecu;

	read_lock_bh(&priv->lock);
	ecu = j1939_ecu_get_by_name_locked(priv, name);
	read_unlock_bh(&priv->lock);

	return ecu;
}

u8 j1939_name_to_addr(struct j1939_priv *priv, name_t name)
{
	struct j1939_ecu *ecu;
	int addr = J1939_IDLE_ADDR;

	if (!name)
		return J1939_NO_ADDR;

	read_lock_bh(&priv->lock);
	ecu = j1939_ecu_find_by_name_locked(priv, name);
	if (j1939_ecu_is_mapped_locked(ecu))
		/* ecu's SA is registered */
		addr = ecu->addr;

	read_unlock_bh(&priv->lock);

	return addr;
}

/* TX addr/name accounting
 * Transport protocol needs to know if a SA is local or not
 * These functions originate from userspace manipulating sockets,
 * so locking is straigforward
 */

int j1939_local_ecu_get(struct j1939_priv *priv, name_t name, u8 sa)
{
	struct j1939_ecu *ecu;
	int err = 0;

	write_lock_bh(&priv->lock);

	if (j1939_address_is_unicast(sa))
		priv->ents[sa].nusers++;

	if (!name)
		goto done;

	ecu = j1939_ecu_find_by_name_locked(priv, name);
	if (!ecu)
		ecu = j1939_ecu_create_locked(priv, name);
	err = PTR_ERR_OR_ZERO(ecu);
	if (err)
		goto done;

	j1939_ecu_get(ecu);
	ecu->nusers++;
	/* TODO: do we care if ecu->addr != sa? */
	if (j1939_ecu_is_mapped_locked(ecu))
		/* ecu's sa is active already */
		priv->ents[ecu->addr].nusers++;

 done:
	write_unlock_bh(&priv->lock);

	return err;
}

void j1939_local_ecu_put(struct j1939_priv *priv, name_t name, u8 sa)
{
	struct j1939_ecu *ecu;

	write_lock_bh(&priv->lock);

	if (j1939_address_is_unicast(sa))
		priv->ents[sa].nusers--;

	if (!name)
		goto done;

	ecu = j1939_ecu_find_by_name_locked(priv, name);
	if (WARN_ON_ONCE(!ecu))
		goto done;

	ecu->nusers--;
	/* TODO: do we care if ecu->addr != sa? */
	if (j1939_ecu_is_mapped_locked(ecu))
		/* ecu's sa is active already */
		priv->ents[ecu->addr].nusers--;
	j1939_ecu_put(ecu);

 done:
	write_unlock_bh(&priv->lock);
}
