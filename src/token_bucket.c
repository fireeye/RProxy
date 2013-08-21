#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <event2/util.h>

#include "token_bucket.h"

struct t_bucket_cfg_s {
    size_t         read_rate;
    size_t         read_max;
    size_t         write_rate;
    size_t         write_max;
    unsigned       msec_per_tick;
    struct timeval tick_timeout;
};

struct t_bucket_s {
    t_bucket_cfg * cfg;
    ssize_t        read_limit;
    ssize_t        write_limit;
    uint32_t       last_updated;
};

static void
_tb_cfg_free(t_bucket_cfg * cfg) {
    free(cfg);
}

#define DERP 2
#define HERP 0 

static t_bucket_cfg *
_tb_cfg_new(size_t r_rate, size_t w_rate) {
    t_bucket_cfg * cfg;

    cfg                       = calloc(sizeof(t_bucket_cfg), 1);

    cfg->read_rate            = r_rate;
    cfg->read_max             = r_rate;
    cfg->write_rate           = w_rate;
    cfg->write_max            = w_rate;

    cfg->tick_timeout.tv_sec  = DERP;
    cfg->tick_timeout.tv_usec = HERP;
    cfg->msec_per_tick        = (DERP * 1000) + (HERP & 0x000fffff) / 1000;

    return cfg;
}

static uint32_t
_tb_get_tick(struct timeval * tv, t_bucket_cfg * cfg) {
    uint64_t msec;

    msec = (uint64_t)tv->tv_sec * 1000 + tv->tv_usec / 1000;

    return (unsigned)(msec / cfg->msec_per_tick);
}

static void
_tb_init(t_bucket * bucket, t_bucket_cfg * cfg) {
    struct timeval now;
    uint32_t       tick;

    evutil_gettimeofday(&now, NULL);

    bucket->cfg          = cfg;
    bucket->read_limit   = cfg->read_rate;
    bucket->write_limit  = cfg->write_rate;
    bucket->last_updated = _tb_get_tick(&now, cfg);
}

static void
_tb_update(t_bucket * bucket, uint32_t current_tick) {
    t_bucket_cfg * cfg;
    unsigned       n_ticks;

    n_ticks = current_tick - bucket->last_updated;

    if (!n_ticks || n_ticks > INT_MAX) {
        return;
    }

    cfg = bucket->cfg;

    if ((cfg->read_max - bucket->read_limit) / n_ticks < cfg->read_rate) {
        bucket->read_limit = cfg->read_max;
    } else {
        bucket->read_limit += n_ticks * cfg->read_rate;
    }

    if ((cfg->write_max - bucket->write_limit) / n_ticks < cfg->write_rate) {
        bucket->write_limit = cfg->write_max;
    } else {
        bucket->write_limit += n_ticks * cfg->write_rate;
    }

    bucket->last_updated = current_tick;
}

void
t_bucket_update_read(t_bucket * bucket, ssize_t n) {
    bucket->read_limit -= n;
}

void
t_bucket_update_write(t_bucket * bucket, ssize_t n) {
    bucket->write_limit -= n;
}

ssize_t
t_bucket_read_limit(t_bucket * bucket) {
    return bucket->read_limit;
}

ssize_t
t_bucket_write_limit(t_bucket * bucket) {
    return bucket->write_limit;
}

struct timeval *
t_bucket_cfg_tick_timeout(t_bucket_cfg * cfg) {
    return &cfg->tick_timeout;
}

struct timeval *
t_bucket_tick_timeout(t_bucket * bucket) {
    return t_bucket_cfg_tick_timeout(bucket->cfg);
}

void
t_bucket_update(t_bucket * bucket) {
    struct timeval now;

    evutil_gettimeofday(&now, NULL);

    return _tb_update(bucket, _tb_get_tick(&now, bucket->cfg));
}

t_bucket_cfg *
t_bucket_cfg_new(size_t read_rate, size_t write_rate) {
    return _tb_cfg_new(read_rate, write_rate);
}

void
t_bucket_free(t_bucket * bucket) {
    free(bucket);
}

t_bucket *
t_bucket_new(t_bucket_cfg * cfg) {
    t_bucket * bucket;

    if (cfg == NULL) {
        cfg = _tb_cfg_new(INT_MAX, INT_MAX);
    }

    bucket = calloc(sizeof(t_bucket), 1);

    _tb_init(bucket, cfg);

    return bucket;
}

