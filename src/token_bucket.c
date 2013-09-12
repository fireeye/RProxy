#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>
#include <event2/util.h>
#include <pthread.h>

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
    t_bucket_cfg  * cfg;
    size_t          read_limit;
    size_t          write_limit;
    uint32_t        last_updated;
    pthread_mutex_t lock;
};

static uint32_t
_t_bucket_get_tick(t_bucket_cfg * cfg, struct timeval * tv) {
    uint64_t msec;

    msec = (uint64_t)tv->tv_sec * 1000 + tv->tv_usec / 1000;

    return (unsigned)(msec / cfg->msec_per_tick);
}

/**
 * @brief initializes the bucket using data from the config.
 *
 * @param bucket
 * @param cfg
 */
static void
_t_bucket_init(t_bucket * bucket, t_bucket_cfg * cfg) {
    struct timeval      now;
    uint32_t            tick;
    pthread_mutexattr_t attr;

    assert(bucket != NULL);

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&bucket->lock, &attr);

    evutil_gettimeofday(&now, NULL);

    bucket->cfg          = cfg;
    bucket->read_limit   = cfg->read_rate;
    bucket->write_limit  = cfg->write_rate;
    bucket->last_updated = _t_bucket_get_tick(cfg, &now);
}

void
t_bucket_update(t_bucket * bucket) {
    /* XXX: it should be noted that multiple threads calling this function
     * around the same time may throw off the n_ticks calculation. At some point
     * in time we should figure out a way to fix this.
     */
    struct timeval now;

    assert(bucket != NULL);

    pthread_mutex_lock(&bucket->lock);
    {
        t_bucket_cfg * cfg;
        unsigned       n_ticks;
        uint32_t       current_tick;

        evutil_gettimeofday(&now, NULL);

        cfg          = bucket->cfg;
        assert(cfg != NULL);

        current_tick = _t_bucket_get_tick(cfg, &now);
        n_ticks      = current_tick - bucket->last_updated;

        if (n_ticks == 0 || n_ticks > INT_MAX) {
            pthread_mutex_unlock(&bucket->lock);
            return;
        }

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
    pthread_mutex_unlock(&bucket->lock);
} /* t_bucket_update */

void
t_bucket_update_read(t_bucket * bucket, ssize_t n) {
    assert(bucket != NULL);

    pthread_mutex_lock(&bucket->lock);
    {
        bucket->read_limit -= n;
    }
    pthread_mutex_unlock(&bucket->lock);
}

void
t_bucket_update_write(t_bucket * bucket, ssize_t n) {
    assert(bucket != NULL);

    pthread_mutex_lock(&bucket->lock);
    {
        bucket->write_limit -= n;
    }
    pthread_mutex_unlock(&bucket->lock);
}

ssize_t
t_bucket_get_read_limit(t_bucket * bucket) {
    ssize_t res;

    assert(bucket != NULL);

    pthread_mutex_lock(&bucket->lock);
    {
        res = bucket->read_limit;
    }
    pthread_mutex_unlock(&bucket->lock);

    return res;
}

ssize_t
t_bucket_get_write_limit(t_bucket * bucket) {
    ssize_t res;

    assert(bucket != NULL);

    pthread_mutex_lock(&bucket->lock);
    {
        res = bucket->write_limit;
    }
    pthread_mutex_unlock(&bucket->lock);

    return res;
}

struct timeval *
t_bucket_cfg_get_tick_timeout(t_bucket_cfg * cfg) {
    assert(cfg != NULL);

    return &cfg->tick_timeout;
}

struct timeval *
t_bucket_get_tick_timeout(t_bucket * bucket) {
    assert(bucket != NULL);

    return t_bucket_cfg_get_tick_timeout(bucket->cfg);
}

size_t
t_bucket_cfg_get_read_rate(t_bucket_cfg * cfg) {
    assert(cfg != NULL);

    return cfg->read_rate;
}

size_t
t_bucket_get_read_rate(t_bucket * bucket) {
    assert(bucket != NULL);

    return t_bucket_cfg_get_read_rate(bucket->cfg);
}

size_t
t_bucket_cfg_get_write_rate(t_bucket_cfg * cfg) {
    assert(cfg != NULL);

    return cfg->write_rate;
}

size_t
t_bucket_get_write_rate(t_bucket * bucket) {
    assert(bucket != NULL);

    return t_bucket_cfg_get_write_rate(bucket->cfg);
}

t_bucket_cfg *
t_bucket_get_cfg(t_bucket * bucket) {
    assert(bucket != NULL);

    return bucket->cfg;
}

int
t_bucket_try_lock(t_bucket * bucket) {
    assert(bucket != NULL);

    return pthread_mutex_trylock(&bucket->lock);
}

int
t_bucket_lock(t_bucket * bucket) {
    assert(bucket != NULL);

    return pthread_mutex_lock(&bucket->lock);
}

int
t_bucket_unlock(t_bucket * bucket) {
    assert(bucket != NULL);

    return pthread_mutex_unlock(&bucket->lock);
}

t_bucket *
t_bucket_new(t_bucket_cfg * cfg) {
    t_bucket * bucket;

    assert(cfg != NULL);

    bucket = calloc(sizeof(t_bucket), 1);
    assert(bucket != NULL);

    _t_bucket_init(bucket, bucket->cfg);

    return bucket;
}

t_bucket_cfg *
t_bucket_cfg_new(size_t read_rate, size_t write_rate) {
    t_bucket_cfg * cfg;

    cfg                       = calloc(sizeof(t_bucket_cfg), 1);
    assert(cfg != NULL);

    cfg->read_rate            = read_rate;
    cfg->read_max             = read_rate;
    cfg->write_rate           = write_rate;
    cfg->write_max            = write_rate;

    cfg->tick_timeout.tv_sec  = 2;
    cfg->tick_timeout.tv_usec = 0;

    cfg->msec_per_tick        = (cfg->tick_timeout.tv_sec * 1000) +
                                (cfg->tick_timeout.tv_usec & 0x000fffff) / 1000;

    return cfg;
}

