#ifndef __EVRATELIM_H__
#define __EVRATELIM_H__

struct evratelim_bev_s;
struct evratelim_group_s;

typedef struct evratelim_bev_s   evratelim_bev;
typedef struct evratelim_group_s evratelim_group;

typedef void (*evratelim_cb)(evratelim_bev * rl_bev, short what, void * arg);

evratelim_group    * evratelim_group_new(struct event_base * base, size_t read_rate, size_t write_rate);
evratelim_bev      * evratelim_add_bufferevent(struct bufferevent * bev, evratelim_group * group);

void                 evratelim_bev_setcb(evratelim_bev * rl_bev, evratelim_cb, evratelim_cb, void * arg);
void                 evratelim_bev_remove(evratelim_bev * rl_bev);
void                 evratelim_bev_read(evratelim_bev * rl_bev, ssize_t len);
void                 evratelim_bev_write(evratelim_bev * rl_bev, ssize_t len);

struct bufferevent * evratelim_bev_bufferevent(evratelim_bev * rl_bev);

#endif

