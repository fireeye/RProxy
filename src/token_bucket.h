#ifndef __TOKEN_BUCKET_H__
#define __TOKEN_BUCKET_H__

struct t_bucket_cfg_s;
struct t_bucket_s;

typedef struct t_bucket_cfg_s t_bucket_cfg;
typedef struct t_bucket_s     t_bucket;


/**
 * @brief create a new config context which is passed to a new t_bucket, this
 *        defines the maximum BYTES-PER-SECOND for both read and write.
 *
 * @param read_rate max read bytes-per-second
 * @param write_rate max read bytes-per-second
 *
 * @return
 */
t_bucket_cfg * t_bucket_cfg_new(size_t read_rate, size_t write_rate);


/**
 * @brief creates an initializes a token bucket context.
 *
 * @param cfg
 *
 * @return
 */
t_bucket * t_bucket_new(t_bucket_cfg * cfg);


/**
 * @brief whenever data is written, this function should be called to update the
 *        buckets..
 *
 * @param bucket
 * @param n number of bytes written
 */
void t_bucket_update_write(t_bucket * bucket, ssize_t n);


/**
 * @brief whenever data is read, this function should be called to update the
 *        buckets.
 *
 * @param bucket
 * @param n number of bytes read
 */
void t_bucket_update_read(t_bucket * bucket, ssize_t n);


/**
 * @brief should be called whenever a token bucket is being refilled.
 *
 * @param bucket
 */
void t_bucket_update(t_bucket * bucket);


/**
 * @brief returns the number of bytes read into the bucket, if the number is
 *        greater than 0, the bucket (should) can be refilled. This should be
 *        called in a refill function.
 *
 * @param bucket
 *
 * @return
 */
ssize_t t_bucket_get_read_limit(t_bucket * bucket);


/**
 * @brief see t_bucket_get_read_limit() but for writes.
 *
 * @param bucket
 *
 * @return
 */
ssize_t t_bucket_get_write_limit(t_bucket * bucket);


/**
 * @brief gets the currently configured read rate out of the bucket, (calls
 *        cfg_get_read_rate).
 *
 * @param bucket
 *
 * @return
 */
size_t t_bucket_get_read_rate(t_bucket * bucket);


/**
 * @brief like above but using the config directly.
 *
 * @param cfg
 *
 * @return
 */
size_t t_bucket_cfg_get_read_rate(t_bucket_cfg * cfg);


/**
 * @brief like the aboove but for writes
 *
 * @param bucket
 *
 * @return
 */
size_t t_bucket_get_write_rate(t_bucket * bucket);


/**
 * @brief like the above but for write from the config directly
 *
 * @param bucket
 *
 * @return
 */
size_t t_bucket_cfg_get_write_rate(t_bucket_cfg * bucket);


/**
 * @brief returns the underlying configuration from a t_bucket structure
 *
 * @param bucket
 *
 * @return
 */
t_bucket_cfg * t_bucket_get_cfg(t_bucket * bucket);


/**
 * @brief gets the configured tick timeout directly from the config structure.
 *
 * @param cfg
 *
 * @return
 */
struct timeval * t_bucket_cfg_get_tick_timeout(t_bucket_cfg * cfg);


/**
 * @brief like above, but from  the base t_bucket config (which calls
 *        cfg_get_tick_timeout
 *
 * @param bucket
 *
 * @return
 */
struct timeval * t_bucket_get_tick_timeout(t_bucket * bucket);


/**
 * @brief simply attempts to lock the token bucket's mutex.
 *
 * @param bucket
 *
 * @return value of pthread_mutex_trylock()
 */
int t_bucket_try_lock(t_bucket * bucket);


/**
 * @brief simply locks the token bucket's mutex
 *
 * @param bucket
 *
 * @return value of pthread_mutex_lock()
 */
int t_bucket_lock(t_bucket * bucket);


/**
 * @brief simply unlocks the token bucket's mutex
 *
 * @param bucket
 *
 * @return the value of pthread_mutex_unlock()
 */
int t_bucket_unlock(t_bucket * bucket);

#endif

