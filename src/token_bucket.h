#ifndef __TOKEN_BUCKET_H__
#define __TOKEN_BUCKET_H__

struct t_bucket_cfg_s;
struct t_bucket_s;

typedef struct t_bucket_cfg_s t_bucket_cfg;
typedef struct t_bucket_s     t_bucket;

t_bucket_cfg   * t_bucket_cfg_new(size_t read_rate, size_t write_rate);
t_bucket       * t_bucket_new(t_bucket_cfg * cfg);

void             t_bucket_cfg_free(t_bucket_cfg * cfg);
void             t_bucket_free(t_bucket * bucket);

void             t_bucket_update(t_bucket * bucket);
void             t_bucket_update_read(t_bucket * bucket, ssize_t n);
void             t_bucket_update_write(t_bucket * bucket, ssize_t n);

ssize_t          t_bucket_read_limit(t_bucket * bucket);
ssize_t          t_bucket_write_limit(t_bucket * bucket);

struct timeval * t_bucket_cfg_tick_timeout(t_bucket_cfg * cfg);
struct timeval * t_bucket_tick_timeout(t_bucket * bucket);

#endif

