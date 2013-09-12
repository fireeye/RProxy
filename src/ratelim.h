#ifndef __RATELIM_H__
#define __RATELIM_H__

struct ratelim_bev_s;
struct ratelim_group_s;

typedef struct ratelim_bev_s   ratelim_bev;
typedef struct ratelim_group_s ratelim_group;

typedef void (*ratelim_cb)(ratelim_bev * rl_bev, short what, void * arg);

ratelim_group      * ratelim_group_new(struct event_base * base, size_t rd_rate, size_t wr_rate);
ratelim_group      * ratelim_group_with_t_bucket(struct event_base * base, t_bucket * bucket);
ratelim_bev        * ratelim_add_bufferevent(struct bufferevent * bev, ratelim_group * group);
void                 ratelim_add_bev(ratelim_bev * bev, ratelim_group * group);
void                 ratelim_bev_setcb(ratelim_bev * bev, ratelim_cb suspendcb, ratelim_cb resumecb, void * arg);
void                 ratelim_remove_bev(ratelim_bev * bev);
void                 ratelim_free_bev(ratelim_bev * bev);
void                 ratelim_write_bev(ratelim_bev * bev, ssize_t nbytes);
void                 ratelim_read_bev(ratelim_bev * bev, ssize_t nbytes);
struct bufferevent * ratelim_bev_get_bufferevent(ratelim_bev * bev);

#endif

