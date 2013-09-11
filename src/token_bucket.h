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

#endif

