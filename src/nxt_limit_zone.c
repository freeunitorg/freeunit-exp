/*
 * Copyright (C) FreeUnit contributors
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>

#include "nxt_limit_zone.h"


static uint32_t nxt_limit_hash(const uint8_t *key, size_t len);
static nxt_limit_entry_t *nxt_limit_lookup(nxt_limit_zone_t *zone,
    const uint8_t *key, size_t len, uint32_t hash, uint32_t *bucket);
static nxt_limit_entry_t *nxt_limit_claim(nxt_limit_zone_t *zone,
    const uint8_t *key, size_t len, uint32_t hash);
static void nxt_limit_unlink(nxt_limit_zone_t *zone, uint32_t idx,
    uint32_t bucket);
static uint32_t nxt_limit_evict_oldest(nxt_limit_zone_t *zone);
static void nxt_limit_refill(nxt_limit_zone_t *zone, nxt_limit_entry_t *entry,
    uint64_t now_ms);


static uint32_t
nxt_limit_hash(const uint8_t *key, size_t len)
{
    size_t    i;
    uint32_t  h;

    /* FNV-1a: small, no state, good enough for a bounded key set. */

    h = 2166136261u;

    for (i = 0; i < len; i++) {
        h ^= key[i];
        h *= 16777619u;
    }

    return h;
}


nxt_limit_zone_t *
nxt_limit_zone_create(nxt_mp_t *mp, uint32_t keys_max, uint32_t rate,
    uint32_t burst)
{
    uint32_t            i, buckets;
    uint32_t            *heads;
    nxt_limit_zone_t    *zone;
    nxt_limit_entry_t   *entry;

    if (keys_max == 0 || keys_max > NXT_LIMIT_KEYS_MAX
        || rate == 0 || rate > NXT_LIMIT_RATE_MAX
        || burst == 0 || burst > NXT_LIMIT_BURST_MAX)
    {
        return NULL;
    }

    buckets = 1;

    while (buckets < keys_max) {
        buckets <<= 1;
    }

    zone = nxt_mp_get(mp, sizeof(nxt_limit_zone_t));

    if (zone == NULL) {
        return NULL;
    }

    /*
     * One arena for the entries and one for the bucket heads: the hit path
     * takes no allocation, and both arrays die with the pool that owns the
     * zone, so the reload path only has to refcount the zone itself.
     */

    entry = nxt_mp_get(mp, keys_max * sizeof(nxt_limit_entry_t));

    if (entry == NULL) {
        return NULL;
    }

    heads = nxt_mp_get(mp, buckets * sizeof(uint32_t));

    if (heads == NULL) {
        return NULL;
    }

    nxt_memzero(zone, sizeof(nxt_limit_zone_t));
    nxt_memzero(entry, keys_max * sizeof(nxt_limit_entry_t));
    nxt_memzero(heads, buckets * sizeof(uint32_t));

    zone->entries = entry;
    zone->buckets = heads;
    zone->buckets_mask = buckets - 1;
    zone->keys_max = keys_max;
    zone->free_head = 1;

    for (i = 0; i < keys_max; i++) {
        /* 1-based links: 0 means "no next", so index 0 is stored as 1. */
        entry[i].next = (i + 1 < keys_max) ? i + 2 : 0;
    }

    zone->rate = rate;
    zone->burst = burst;

    return zone;
}


nxt_bool_t
nxt_limit_zone_check(nxt_limit_zone_t *zone, const uint8_t *key,
    size_t key_len, uint64_t now_ms)
{
    uint32_t            hash, bucket;
    nxt_bool_t          allow;
    nxt_limit_entry_t   *entry;

    if (key_len == 0 || key_len > NXT_LIMIT_KEY_MAX) {
        return 1;
    }

    hash = nxt_limit_hash(key, key_len);

    nxt_thread_spin_lock(&zone->lock);

    entry = nxt_limit_lookup(zone, key, key_len, hash, &bucket);

    if (entry == NULL) {
        entry = nxt_limit_claim(zone, key, key_len, hash);

        if (entry == NULL) {
            nxt_thread_spin_unlock(&zone->lock);
            return 1;
        }
    }

    nxt_limit_refill(zone, entry, now_ms);

    allow = (entry->tokens >= NXT_LIMIT_TOKEN_SCALE);

    if (allow) {
        entry->tokens -= NXT_LIMIT_TOKEN_SCALE;
        zone->passed++;

    } else {
        zone->rejected++;
    }

    nxt_thread_spin_unlock(&zone->lock);

    return allow;
}


static nxt_limit_entry_t *
nxt_limit_lookup(nxt_limit_zone_t *zone, const uint8_t *key, size_t len,
    uint32_t hash, uint32_t *bucket)
{
    uint32_t            link;
    nxt_limit_entry_t   *entry;

    *bucket = hash & zone->buckets_mask;
    link = zone->buckets[*bucket];

    while (link != 0) {
        entry = &zone->entries[link - 1];

        if ((size_t) entry->key_len == len
            && (len == 0 || memcmp(entry->key, key, len) == 0))
        {
            return entry;
        }

        link = entry->next;
    }

    return NULL;
}


static nxt_limit_entry_t *
nxt_limit_claim(nxt_limit_zone_t *zone, const uint8_t *key, size_t len,
    uint32_t hash)
{
    uint32_t            bucket, idx;
    nxt_limit_entry_t   *entry;

    if (zone->free_head != 0) {
        idx = zone->free_head - 1;
        entry = &zone->entries[idx];
        zone->free_head = entry->next;
        zone->keys_used++;

    } else {
        idx = nxt_limit_evict_oldest(zone);

        if (idx == (uint32_t) -1) {
            return NULL;
        }

        entry = &zone->entries[idx];
    }

    entry->key_len = (uint8_t) len;
    nxt_memcpy(entry->key, key, len);
    entry->last_ms = 0;
    entry->tokens = zone->burst * NXT_LIMIT_TOKEN_SCALE;
    entry->next = 0;

    bucket = hash & zone->buckets_mask;
    entry->next = zone->buckets[bucket];
    zone->buckets[bucket] = idx + 1;

    return entry;
}


static void
nxt_limit_unlink(nxt_limit_zone_t *zone, uint32_t idx, uint32_t bucket)
{
    uint32_t  link;

    link = zone->buckets[bucket];

    if (link == idx + 1) {
        zone->buckets[bucket] = zone->entries[idx].next;
        return;
    }

    while (link != 0) {
        if (zone->entries[link - 1].next == idx + 1) {
            zone->entries[link - 1].next = zone->entries[idx].next;
            return;
        }

        link = zone->entries[link - 1].next;
    }
}


static uint32_t
nxt_limit_evict_oldest(nxt_limit_zone_t *zone)
{
    uint32_t            i, oldest, bucket, hash;
    nxt_limit_entry_t   *entry;

    if (zone->keys_used == 0) {
        return (uint32_t) -1;
    }

    oldest = (uint32_t) -1;

    for (i = 0; i < zone->keys_max; i++) {
        entry = &zone->entries[i];

        if (entry->key_len == 0) {
            continue;
        }

        if (oldest == (uint32_t) -1
            || entry->last_ms < zone->entries[oldest].last_ms)
        {
            oldest = i;
        }
    }

    if (oldest == (uint32_t) -1) {
        return (uint32_t) -1;
    }

    entry = &zone->entries[oldest];

    hash = nxt_limit_hash(entry->key, entry->key_len);
    bucket = hash & zone->buckets_mask;

    nxt_limit_unlink(zone, oldest, bucket);

    /*
     * The key is dropped here, not carried over: the caller sets the new key.
     * A zeroed key_len keeps the entry out of the scan above until then.
     */

    entry->key_len = 0;
    zone->evicted++;

    return oldest;
}


static void
nxt_limit_refill(nxt_limit_zone_t *zone, nxt_limit_entry_t *entry,
    uint64_t now_ms)
{
    uint64_t  add, max;

    if (now_ms <= entry->last_ms) {
        return;
    }

    /* milli-tokens added: elapsed milliseconds times rate per second. */
    add = (now_ms - entry->last_ms) * zone->rate;

    max = (uint64_t) zone->burst * NXT_LIMIT_TOKEN_SCALE;

    if (add >= max || entry->tokens + add >= max) {
        entry->tokens = (uint32_t) max;

    } else {
        entry->tokens += (uint32_t) add;
    }

    entry->last_ms = now_ms;
}
