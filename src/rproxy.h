/* Copyright [2012] [Mandiant, inc]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __RPROXY_H__
#define __RPROXY_H__

#include <stdbool.h>
#include <syslog.h>
#include <float.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <confuse.h>
#include <evhtp.h>

#include "lzq.h"

#define RPROXY_VERSION "1.0.21"

#if EVHTP_VERSION_MAJOR <= 0
#if EVHTP_VERSION_MINOR <= 4
#if EVHTP_VERSION_PATCH < 13
#error RProxy requires libevhtp v0.4.13 or greater
#endif
#endif
#endif

/************************************************
* configuration structure definitions
************************************************/

enum log_type {
    log_type_file,
    log_type_fd,
    log_type_syslog
};

enum rule_type {
    rule_type_exact,
    rule_type_regex,
    rule_type_glob
};

enum lb_method {
    lb_method_rtt = 0,
    lb_method_rr,
    lb_method_rand,
    lb_method_most_idle,
    lb_method_none
};

typedef struct rproxy_cfg     rproxy_cfg_t;
typedef struct rule_cfg       rule_cfg_t;
typedef struct vhost_cfg      vhost_cfg_t;
typedef struct server_cfg     server_cfg_t;
typedef struct downstream_cfg downstream_cfg_t;
typedef struct headers_cfg    headers_cfg_t;
typedef struct x509_ext_cfg   x509_ext_cfg_t;

typedef enum log_type         log_type;
typedef enum rule_type        rule_type;
typedef enum lb_method        lb_method;

struct rule_cfg {
    rule_type       type;        /**< what type of rule this is (regex/exact/glob) */
    lb_method       lb_method;   /**< method of load-balacinging (defaults to RTT) */
    char          * matchstr;    /**< the uri to match on */
    headers_cfg_t * headers;     /**< headers which are added to the backend request */
    lztq          * downstreams; /**< list of downstream names (as supplied by downstream_cfg_t->name */
    bool            passthrough;
    int             has_up_read_timeout;
    int             has_up_write_timeout;
    struct timeval  up_read_timeout;
    struct timeval  up_write_timeout;
};

/**
 * @brief a configuration structure representing a single x509 extension header.
 *
 */
struct x509_ext_cfg {
    char * name;                 /**< the name of the header */
    char * oid;                  /**< the oid of the x509 extension to pull */
};

/**
 * @brief which headers to add to the downstream request if avail.
 */
struct headers_cfg {
    bool   x_forwarded_for;
    bool   x_ssl_subject;
    bool   x_ssl_issuer;
    bool   x_ssl_notbefore;
    bool   x_ssl_notafter;
    bool   x_ssl_serial;
    bool   x_ssl_cipher;
    bool   x_ssl_certificate;
    lztq * x509_exts;
};


/**
 * @brief configuration for a single downstream.
 */
struct downstream_cfg {
    bool     enabled;               /**< true if server is enabled */
    char   * name;                  /**< the name of this downstream. the name is used as an identifier for rules */
    char   * host;                  /**< the hostname of the downstream */
    uint16_t port;                  /**< the port of the downstream */
    int      n_connections;         /**< number of connections to keep established */
    size_t   high_watermark;        /**< if the number of bytes pending on the output side
                                     * of the socket reaches this number, the proxy stops
                                     * reading from the upstream until all data has been written. */
    struct timeval retry_ival;      /**< retry timer if the downstream connection goes down */
    struct timeval read_timeout;
    struct timeval write_timeout;
};


struct vhost_cfg {
    evhtp_ssl_cfg_t * ssl_cfg;
    lztq            * rule_cfgs;    /**< list of rule_cfg_t's */
    lztq            * rules;        /* list of rule_t's */
    char            * server_name;
    lztq            * aliases;
    /* log_cfg_t       * log_cfg; */
};

/**
 * @brief configuration for a single listening frontend server.
 */
struct server_cfg {
    char   * bind_addr;             /**< address to bind on */
    uint16_t bind_port;             /**< port to bind on */
    int      num_threads;           /**< number of worker threads to start */
    int      max_pending;           /**< max pending requests before new connections are dropped */
    int      listen_backlog;        /**< listen backlog */

    struct timeval read_timeout;    /**< time to wait for reading before client is dropped */
    struct timeval write_timeout;   /**< time to wait for writing before client is dropped */
    struct timeval pending_timeout; /**< time to wait for a downstream to become available for a connection */

    evhtp_ssl_cfg_t * ssl_cfg;      /**< if enabled, the ssl configuration */
    lztq            * downstreams;  /**< list of downstream_cfg_t's */
    lztq            * vhosts;       /**< list of vhost_cfg_t's */
#if 0
    /* log_cfg_t       * log_cfg; */
    lztq * rules;                   /**< list of rule_cfg_t's */
#endif
};


/**
 * @brief main configuration structure.
 */
struct rproxy_cfg {
    bool   daemonize;               /**< should proxy run in background */
    int    max_nofile;              /**< max number of open file descriptors */
    char * rootdir;                 /**< root dir to daemonize */
    char * user;                    /**< user to run as */
    char * group;                   /**< group to run as */
    lztq * servers;                 /**< list of server_cfg_t's */
};

/********************************************
* Main structures
********************************************/

/**
 * @brief a downstream's connection status.
 */
enum downstream_status {
    downstream_status_nil = 0,      /**< connection has never been used */
    downstream_status_active,       /**< connection is actively processing */
    downstream_status_idle,         /**< connection is idle and available */
    downstream_status_down          /**< connection is down and cannot be used */
};

typedef struct rproxy            rproxy_t;
typedef struct downstream        downstream_t;
typedef struct downstream_c      downstream_c_t;
typedef struct request           request_t;
typedef struct rule              rule_t;
typedef struct pending_request_q pending_request_q_t;

typedef enum downstream_status   downstream_status;

#define REQUEST_HAS_ERROR(req) (req->error ? 1 : req->upstream_err ? 1 : 0)

/**
 * @brief structure which represents a full proxy request
 *
 */
struct request {
    rproxy_t        * rproxy;            /**< the parent rproxy_t structure */
    evhtp_request_t * upstream_request;  /**< the client request */
    downstream_c_t  * downstream_conn;   /**< the downstream connection */
    rule_t          * rule;              /**< the matched rule */
    htparser        * parser;            /**< htparser for responses from the downstream */
    event_t         * pending_ev;        /**< event timer for pending status */
    evbev_t         * upstream_bev;
    evbev_t         * downstream_bev;

    uint8_t error;                       /**< set of downstream returns some type of error */
    uint8_t upstream_err;                /**< set if the upstream encountered a socket error */
    uint8_t done;                        /**< request fully proxied and completed */
    uint8_t pending;                     /**< request is waiting for a downstream connection to be avail */
    uint8_t hit_highwm;
    uint8_t reading;

    TAILQ_ENTRY(request) next;
};

/**
 * @brief a structure representing a downstream connection.
 */
struct downstream_c {
    downstream_t    * parent;            /**< the parent downstream structure */
    evbev_t         * connection;        /**< the bufferevent connection */
    request_t       * request;           /**< the currently running request */
    event_t         * retry_timer;       /**< the timer event for reconnecting if down */
    downstream_status status;            /**< the status of this downstream */
    double            rtt;               /**< the last RTT for a request made to the connection */
    uint16_t          sport;             /**< the source port of the connected socket */
    uint8_t           bootstrapped;      /**< if not set to 1, the connection will immediately attempt the reconnect */
    struct timeval    tv_start;          /**< the time which the connection was set to active, used to calculate RTT */

    TAILQ_ENTRY(downstream_c) next;
};

/**
 * @brief a container active/idle/downed downstream connections
 */
struct downstream {
    downstream_cfg_t * config;           /**< this downstreams configuration */
    evbase_t         * evbase;
    rproxy_t         * rproxy;
    uint16_t           num_active;       /**< number of ents in the active list */
    uint16_t           num_idle;         /**< number of ents in the idle list */
    uint16_t           num_down;         /**< number of ents in the down list */

    TAILQ_HEAD(, downstream_c) active;   /**< list of active connections */
    TAILQ_HEAD(, downstream_c) idle;     /**< list of idle and ready connections */
    TAILQ_HEAD(, downstream_c) down;     /**< list of connections which are down */
};

struct rule {
    rproxy_t   * rproxy;
    rule_cfg_t * config;
    lztq       * downstreams;            /**< list of downstream_t's configured for this rule */
    lztq_elem  * last_downstream_used;   /**< the last downstream used to service a request. Used for round-robin loadbalancing */
};

TAILQ_HEAD(pending_request_q, request);

struct rproxy {
    evhtp_t           * htp;
    evbase_t          * evbase;
    event_t           * request_ev;
    server_cfg_t      * server_cfg;
    lztq              * rules;
    lztq              * downstreams; /**< list of all downstream_t's */
    int                 n_pending;   /**< number of pending requests */
    pending_request_q_t pending;     /**< list of pending upstream request_t's */
};

/************************************************
* Configuration parsing function definitions.
************************************************/
rproxy_cfg_t * rproxy_cfg_parse(const char * filename);

/***********************************************
* Downstream handling functions
***********************************************/
downstream_t   * downstream_new(rproxy_t *, downstream_cfg_t *);
void             downstream_free(void *);

downstream_c_t * downstream_connection_new(evbase_t *, downstream_t *);
downstream_c_t * downstream_connection_get(rule_t *);
void             downstream_connection_free(downstream_c_t *);
int              downstream_connection_init(evbase_t *, downstream_t *);

int              downstream_connection_set_active(downstream_c_t *);
int              downstream_connection_set_idle(downstream_c_t *);
int              downstream_connection_set_down(downstream_c_t *);

downstream_t   * downstream_find_by_name(lztq *, const char *);

/* downstream socket handling callbacks */
void downstream_connection_eventcb(evbev_t *, short, void *);
void downstream_connection_retry(int, short, void *);

/********************************************
* SSL verification callback functions
********************************************/
int ssl_x509_verifyfn(int, X509_STORE_CTX *);
int ssl_x509_issuedcb(X509_STORE_CTX *, X509 *, X509 *);

/***********************************************
* Request handling funcs (upstream/downstream)
***********************************************/
request_t * request_new(rproxy_t *);
void        request_free(request_t *);

/***********************************************
 * SSL helper functions.
 ************************************************/
unsigned char * ssl_subject_tostr(evhtp_ssl_t *);
unsigned char * ssl_issuer_tostr(evhtp_ssl_t *);
unsigned char * ssl_notbefore_tostr(evhtp_ssl_t *);
unsigned char * ssl_notafter_tostr(evhtp_ssl_t *);
unsigned char * ssl_serial_tostr(evhtp_ssl_t *);
unsigned char * ssl_cipher_tostr(evhtp_ssl_t *);
unsigned char * ssl_cert_tostr(evhtp_ssl_t *);
unsigned char * ssl_x509_ext_tostr(evhtp_ssl_t *, const char *);

#endif

