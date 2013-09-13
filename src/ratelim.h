#ifndef __RATELIM_H__
#define __RATELIM_H__

struct ratelim_bev_s;
struct ratelim_group_s;

typedef struct ratelim_bev_s   ratelim_bev;
typedef struct ratelim_group_s ratelim_group;

typedef void (*ratelim_cb)(ratelim_bev * rl_bev, short what, void * arg);


/**
 * @brief create a new group in which bufferevents can share limits. This will
 *        allocate its own tokenbucket.
 *
 * @param base
 * @param rd_rate max read for everything in the group in BYTES
 * @param wr_rate max write for everything in the group in BYTES
 *
 * @return
 */
ratelim_group * ratelim_group_new(struct event_base * base, size_t rd_rate, size_t wr_rate);



/**
 * @brief creates a new group which will use a pre-allocated token-bucket. This
 *        is good when you are using threads and want to use a global token bucket
 *        while still maintaining a lockless event loop.
 *
 * @param base
 * @param bucket
 *
 * @return
 */
ratelim_group * ratelim_group_with_t_bucket(struct event_base * base, t_bucket * bucket);


/**
 * @brief add a bufferevent to a group, this will return an abstract structure
 *        around the bufferevent which is used to interact with the underlying token
 *        bucket.
 *
 * @param bev
 * @param group
 *
 * @return
 */
ratelim_bev * ratelim_add_bufferevent(struct bufferevent * bev, ratelim_group * group);


/**
 * @brief if you already have an abstracted ratelim_bev allocated, you can move
 *        them into different groups using this.
 *
 * @param bev
 * @param group
 */
void ratelim_add_bev(ratelim_bev * bev, ratelim_group * group);


/**
 * @brief set callbacks on a bev/group which will execute whenever a bufferevent
 *        needs to be resumed or suspended. Since this API does not touch the
 *        bufferevent directly, it is up to the user to do this themselves.
 *
 * @param bev
 * @param group
 * @param suspendcb
 * @param resumecb
 * @param arg
 */
void ratelim_bev_setcb(ratelim_bev * bev, ratelim_group * group, ratelim_cb suspendcb, ratelim_cb resumecb, void * arg);


/**
 * @brief remove an abstracted ratelim_bev from a group. This will NOT free the
 *        structure, only removes it.
 *
 * @param bev
 */
void ratelim_remove_bev(ratelim_bev * bev);


/**
 * @brief frees the ratelim_bev structure, if it is currently assigned to a
 *        greoup, it is removed. The bufferevent is not free'd, this is left up to the
 *        caller.
 *
 * @param bev
 */
void ratelim_free_bev(ratelim_bev * bev);


/**
 * @brief inform the underlying token bucket that data has been written so that
 *        it can update appropriately.
 *
 * @param bev
 * @param group
 * @param nbytes
 */
void ratelim_write_bev(ratelim_bev * bev, ratelim_group * group, ssize_t nbytes);


/**
 * @brief inform the underlying token bucket that data has been read so that it
 *        can update appropriately.
 *
 * @param bev
 * @param group
 * @param nbytes
 */
void ratelim_read_bev(ratelim_bev * bev, ratelim_group * group, ssize_t nbytes);


/**
 * @brief get the real underlying bufferevent from the ratelim_bev structure.
 *
 * @param bev
 *
 * @return
 */
struct bufferevent * ratelim_bev_get_bufferevent(ratelim_bev * bev);

#endif

