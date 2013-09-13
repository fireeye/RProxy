#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include <limits.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/queue.h>

#include <event2/event.h>
#include <event2/util.h>
#include <event2/bufferevent.h>

#include "token_bucket.h"
#include "ratelim.h"

#ifndef TAILQ_END
#define TAILQ_END(head) NULL
#endif

struct ratelim_bev_s {
    pthread_mutex_t lock;

    struct bufferevent * bev;
    ratelim_group      * group;
    ratelim_cb           suspend_cb;
    ratelim_cb           resume_cb;
    void               * cbarg;

    TAILQ_ENTRY(ratelim_bev_s) next;
};

struct ratelim_group_s {
    pthread_mutex_t lock;

    struct event_base * evbase;
    struct event      * refill_ev;
    t_bucket_cfg      * t_cfg;
    t_bucket          * t_bucket;
    bool                rd_suspended;
    bool                wr_suspended;
    int                 n_members;

    TAILQ_HEAD(, ratelim_bev_s) members;
};

static void
_ratelim_resume_bev(ratelim_bev * bev, ratelim_group * group, short what) {
    assert(bev != NULL);

    pthread_mutex_lock(&group->lock);
    {
        if (!(bufferevent_get_enabled(bev->bev) & what)) {
            if (bev->resume_cb != NULL) {
                (bev->resume_cb)(bev, what, bev->cbarg);
            }
        }
    }
    pthread_mutex_unlock(&group->lock);
}

static void
_ratelim_resume_bev_read(ratelim_bev * bev, ratelim_group * group) {
    assert(bev != NULL);

    pthread_mutex_lock(&group->lock);
    {
        _ratelim_resume_bev(bev, group, EV_READ);
    }
    pthread_mutex_unlock(&group->lock);
}

static void
_ratelim_resume_bev_write(ratelim_bev * bev, ratelim_group * group) {
    assert(bev != NULL);

    pthread_mutex_lock(&group->lock);
    {
        _ratelim_resume_bev(bev, group, EV_WRITE);
    }
    pthread_mutex_unlock(&group->lock);
}

static void
_ratelim_suspend_bev(ratelim_bev * bev, ratelim_group * group, short what) {
    assert(bev != NULL);

    pthread_mutex_lock(&group->lock);
    {
        if ((bufferevent_get_enabled(bev->bev) & what)) {
            if (bev->suspend_cb != NULL) {
                (bev->suspend_cb)(bev, what, bev->cbarg);
            }
        }
    }
    pthread_mutex_unlock(&group->lock);
}

static void
_ratelim_suspend_bev_read(ratelim_bev * bev, ratelim_group * group) {
    assert(bev != NULL);

    pthread_mutex_lock(&group->lock);
    {
        _ratelim_suspend_bev(bev, group, EV_READ);
    }
    pthread_mutex_unlock(&group->lock);
}

static void
_ratelim_suspend_bev_write(ratelim_bev * bev, ratelim_group * group) {
    assert(bev != NULL);

    pthread_mutex_lock(&group->lock);
    {
        _ratelim_suspend_bev(bev, group, EV_WRITE);
    }
    pthread_mutex_unlock(&group->lock);
}

static ratelim_bev *
_ratelim_group_get_random_bev(ratelim_group * group) {
    ratelim_bev * bev;

    assert(group != NULL);

    pthread_mutex_lock(&group->lock);
    {
        int where;

        if (group->n_members == 0) {
            pthread_mutex_unlock(&group->lock);
            return NULL;
        }

        assert(!TAILQ_EMPTY(&group->members));

        where = rand() % group->n_members;
        bev   = TAILQ_FIRST(&group->members);

        while (where--) {
            bev = TAILQ_NEXT(bev, next);
        }
    }
    pthread_mutex_unlock(&group->lock);

    return bev;
}

#define FOREACH_RANDOM_ORDER(block)                                                                  \
    do {                                                                                             \
        first = _ratelim_group_get_random_bev(group);                                                \
                                                                                                     \
        for (bev = first; bev != TAILQ_END(&group->members); bev = TAILQ_NEXT(bev, next)) {          \
            block;                                                                                   \
        }                                                                                            \
                                                                                                     \
        for (bev = TAILQ_FIRST(&group->members); bev && bev != first; bev = TAILQ_NEXT(bev, next)) { \
            block;                                                                                   \
        }                                                                                            \
    } while (0)

static void
_ratelim_group_resume(ratelim_group * group, short what) {
    ratelim_bev * bev;
    ratelim_bev * first;

    assert(group != NULL);

    pthread_mutex_lock(&group->lock);
    {
        group->rd_suspended = false;

        FOREACH_RANDOM_ORDER({ _ratelim_resume_bev(bev, group, what); });
    }
    pthread_mutex_unlock(&group->lock);
}

static void
_ratelim_group_resume_reading(ratelim_group * group) {
    ratelim_bev * bev;
    ratelim_bev * first;

    assert(group != NULL);

    pthread_mutex_lock(&group->lock);
    {
        group->rd_suspended = false;

        _ratelim_group_resume(group, EV_READ);
    }
    pthread_mutex_unlock(&group->lock);
}

static void
_ratelim_group_resume_writing(ratelim_group * group) {
    ratelim_bev * bev;
    ratelim_bev * first;

    assert(group != NULL);

    pthread_mutex_lock(&group->lock);
    {
        group->wr_suspended = false;

        _ratelim_group_resume(group, EV_WRITE);
    }
    pthread_mutex_unlock(&group->lock);
}

static void
_ratelim_group_suspend(ratelim_group * group, short what) {
    ratelim_bev * bev;
    ratelim_bev * first;

    assert(group != NULL);

    pthread_mutex_lock(&group->lock);
    {
        first = TAILQ_FIRST(&group->members);

        for (bev = first; bev != TAILQ_END(&group->members); bev = TAILQ_NEXT(bev, next)) {
            _ratelim_suspend_bev(bev, group, what);
        }
    }
    pthread_mutex_unlock(&group->lock);
}

static void
_ratelim_group_suspend_writing(ratelim_group * group) {
    assert(group != NULL);

    pthread_mutex_lock(&group->lock);
    {
        group->wr_suspended = true;

        _ratelim_group_suspend(group, EV_WRITE);
    }
    pthread_mutex_unlock(&group->lock);
}

static void
_ratelim_group_suspend_reading(ratelim_group * group) {
    assert(group != NULL);

    pthread_mutex_lock(&group->lock);
    {
        group->rd_suspended = true;

        _ratelim_group_suspend(group, EV_READ);
    }
    pthread_mutex_unlock(&group->lock);
}

static void
_ratelim_refill_cb(int sock, short which, void * arg) {
    ratelim_group * group;

    group = (ratelim_group *)arg;
    assert(group != NULL);

    pthread_mutex_lock(&group->lock);
    {
        /* we want to aquire the lock for the token bucket, this allows for a better
         * distribution of ratelimiting across multiple threads.
         */
        t_bucket_lock(group->t_bucket);
        {
            t_bucket_update(group->t_bucket);

            if (group->rd_suspended == true) {
                if (t_bucket_get_read_limit(group->t_bucket) >= 1) {
                    _ratelim_group_resume_reading(group);
                }
            }

            if (group->wr_suspended == true) {
                if (t_bucket_get_write_limit(group->t_bucket) >= 1) {
                    _ratelim_group_resume_writing(group);
                }
            }

            /* As much as I hate to do this, it actually eases up the potential hogging
             * of the token bucket from other threads. This balances out even more due
             * to the while(t_bucket_lock()) above.
             */
            usleep(20000);
        }
        /* since we aquired the token bucket lock above, we need to unlock it */
        t_bucket_unlock(group->t_bucket);
    }
    pthread_mutex_unlock(&group->lock);
}

static ratelim_group *
_ratelim_group_new(struct event_base * base, t_bucket * bucket, size_t r_rate, size_t w_rate) {
    ratelim_group     * group;
    struct timeval    * tick_timeout;
    pthread_mutexattr_t attr;

    assert(base != NULL);

    group = calloc(sizeof(ratelim_group), 1);
    assert(group != NULL);

    if (bucket == NULL) {
        group->t_cfg    = t_bucket_cfg_new(r_rate, w_rate);
        group->t_bucket = t_bucket_new(group->t_cfg);
    } else {
        group->t_bucket = bucket;
        group->t_cfg    = t_bucket_get_cfg(bucket);
    }

    assert(group->t_cfg != NULL);
    assert(group->t_bucket != NULL);

    group->evbase       = base;
    group->rd_suspended = false;
    group->wr_suspended = false;

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&group->lock, &attr);

    tick_timeout     = t_bucket_get_tick_timeout(group->t_bucket);
    assert(tick_timeout != NULL);

    group->refill_ev = event_new(base, -1, EV_PERSIST, _ratelim_refill_cb, group);
    assert(group->refill_ev != NULL);

    event_add(group->refill_ev, tick_timeout);

    TAILQ_INIT(&group->members);

    return group;
} /* _ratelim_group_new */

static ratelim_bev *
_ratelim_bev_new(void) {
    ratelim_bev       * rl_bev;
    pthread_mutexattr_t attr;

    rl_bev = calloc(sizeof(ratelim_bev), 1);
    assert(rl_bev != NULL);

#if 0
    /* XXX should we default to bufferevent_(enable|disable)? */
    rl_bev->suspend_cb = _default_suspend_cb;
    rl_bev->resume_cb  = _default_resume_cb;
#endif

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&rl_bev->lock, &attr);

    return rl_bev;
}

void
ratelim_bev_setcb(ratelim_bev * bev, ratelim_group * group,
                  ratelim_cb suspendcb,
                  ratelim_cb resumecb, void * arg) {
    assert(bev != NULL);

    pthread_mutex_lock(&group->lock);
    pthread_mutex_lock(&bev->lock);
    {
        bev->suspend_cb = suspendcb;
        bev->resume_cb  = resumecb;
        bev->cbarg      = arg;
    }
    pthread_mutex_unlock(&bev->lock);
    pthread_mutex_unlock(&group->lock);
}

ratelim_bev *
ratelim_bev_new(ratelim_group * group) {
    ratelim_bev * rl_bev;

    assert(group != NULL);

    pthread_mutex_lock(&group->lock);
    {
        rl_bev        = _ratelim_bev_new();
        assert(rl_bev != NULL);

        rl_bev->group = group;
    }
    pthread_mutex_unlock(&group->lock);

    return rl_bev;
}

void
ratelim_add_bev(ratelim_bev * bev, ratelim_group * group) {
    assert(bev != NULL);
    assert(group != NULL);

    pthread_mutex_lock(&group->lock);
    pthread_mutex_lock(&bev->lock);
    {
        assert(bev->group != NULL);

        bev->group        = group;
        group->n_members += 1;

        TAILQ_INSERT_TAIL(&group->members, bev, next);

        if (group->rd_suspended == true) {
            _ratelim_suspend_bev_read(bev, group);
        }

        if (group->wr_suspended == true) {
            _ratelim_suspend_bev_write(bev, group);
        }
    }
    pthread_mutex_unlock(&bev->lock);
    pthread_mutex_unlock(&group->lock);
}

ratelim_bev *
ratelim_add_bufferevent(struct bufferevent * bev, ratelim_group * group) {
    ratelim_bev * rl_bev;

    assert(bev != NULL);
    assert(group != NULL);

    pthread_mutex_lock(&group->lock);
    {
        rl_bev        = _ratelim_bev_new();
        assert(rl_bev != NULL);

        rl_bev->bev   = bev;
        rl_bev->group = group;
        ratelim_add_bev(rl_bev, group);
    }
    pthread_mutex_unlock(&group->lock);

    return rl_bev;
}

void
ratelim_remove_bev(ratelim_bev * bev) {
    ratelim_group * group;

    assert(bev != NULL);

    pthread_mutex_lock(&bev->lock);
    pthread_mutex_lock(&bev->group->lock);
    {
        group             = bev->group;
        group->n_members -= 1;

        bev->group        = NULL;

        TAILQ_REMOVE(&group->members, bev, next);
    }
    pthread_mutex_unlock(&group->lock);
    pthread_mutex_unlock(&bev->lock);
}

void
ratelim_free_bev(ratelim_bev * bev) {
    ratelim_group * group;

    assert(bev != NULL);

    group = bev->group;

    if (group != NULL) {
        pthread_mutex_lock(&group->lock);
        {
            ratelim_remove_bev(bev);
        }
        pthread_mutex_unlock(&group->lock);
    }

    free(bev);
}

ratelim_group *
ratelim_group_new(struct event_base * base, size_t r_rate, size_t w_rate) {
    return _ratelim_group_new(base, NULL, r_rate, w_rate);
}

struct bufferevent *
ratelim_bev_get_bufferevent(ratelim_bev * bev) {
    assert(bev != NULL);

    return bev->bev;
}

void
ratelim_write_bev(ratelim_bev * bev, ratelim_group * group, ssize_t nbytes) {
    assert(bev != NULL);

    pthread_mutex_lock(&group->lock);
    pthread_mutex_lock(&bev->lock);
    {
        t_bucket_update_write(group->t_bucket, nbytes);

        if (t_bucket_get_write_limit(group->t_bucket) <= 0) {
            _ratelim_group_suspend_writing(group);
        } else if (group->wr_suspended == true) {
            _ratelim_group_resume_writing(group);
        }
    }
    pthread_mutex_unlock(&bev->lock);
    pthread_mutex_unlock(&group->lock);
}

void
ratelim_read_bev(ratelim_bev * bev, ratelim_group * group, ssize_t nbytes) {
    assert(bev != NULL);

    pthread_mutex_lock(&group->lock);
    pthread_mutex_lock(&bev->lock);
    {
        t_bucket_update_read(group->t_bucket, nbytes);

        if (t_bucket_get_read_limit(group->t_bucket) <= 0) {
            _ratelim_group_suspend_reading(group);
        } else if (group->rd_suspended == true) {
            _ratelim_group_resume_reading(group);
        }
    }
    pthread_mutex_unlock(&bev->lock);
    pthread_mutex_unlock(&group->lock);
}

ratelim_group *
ratelim_group_with_t_bucket(struct event_base * base, t_bucket * bucket) {
    size_t rd_rate;
    size_t wr_rate;

    assert(base != NULL);
    assert(bucket != NULL);

    rd_rate = t_bucket_get_read_rate(bucket);
    wr_rate = t_bucket_get_write_rate(bucket);

    return _ratelim_group_new(base, bucket, rd_rate, wr_rate);
}

