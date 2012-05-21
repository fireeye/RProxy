/*
 * Copyright [2012] [Mandiant, inc]
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
#include <assert.h>
#include <sys/queue.h>
#include <confuse.h>
#include <evhtp.h>

#define RPROXY_VERSION "1.0.23"


#if EVHTP_VERSION_MAJOR <= 0
#if EVHTP_VERSION_MINOR <= 4
#if EVHTP_VERSION_PATCH < 13
#error RProxy requires libevhtp v0.4.13 or greater
#endif
#endif
#endif


typedef struct rewrite_cfg       rewrite_cfg_t;
typedef struct downstream_cfg    downstream_cfg_t;
typedef struct server_cfg        server_cfg_t;
typedef struct headers_cfg       headers_cfg_t;
typedef struct x509_ext_cfg      x509_ext_cfg_t;
typedef struct logger_cfg        logger_cfg_t;
typedef struct rproxy_cfg        rproxy_cfg_t;
typedef struct downstream_c      downstream_c_t;
typedef struct downstream        downstream_t;
typedef struct rule              rule_t;
typedef struct request           request_t;
typedef struct logger_arg        logger_arg_t;
typedef struct logger_fns        logger_fns;
typedef struct logger            logger_t;
typedef struct rproxy            rproxy_t;

typedef struct downstream_q      downstream_q_t;
typedef struct pending_request_q pending_request_q_t;

typedef enum downstream_status   downstream_status;
typedef enum logger_argtype      logger_argtype;
typedef enum logger_type         logger_type;
typedef enum lb_method           lb_method;

/**
 * @brief a configuration structure representing a single rewrite rule.
 *
 * This structure is used to generate a rule_t structure which
 * is later used to generate the proper evhtp_regex based callbacks.
 */
struct rewrite_cfg {
    char * src;                      /**< a regex matching a client requests URI */
    char * dst;                      /**< the URI to redirect the request to the downstream */

    TAILQ_ENTRY(rewrite_cfg) next;
};

/**
 * @brief configuration for a single downstream.
 */
struct downstream_cfg {
    char   * host;                   /**< the hostname downstream */
    uint16_t port;                   /**< the port of the downstream */
    int      connections;            /**< number of connections to keep up */
    int      read_timeout;
    int      write_timeout;
    size_t   high_watermark;         /**< number of bytes which are pending to a
                                      * downstream connection. When this number is hit,
                                      * the proxy stops reading data from the upstream
                                      * until all data has been flushed */

    struct timeval retry_ival;       /**< number of seconds/useconds to retry if down */

    TAILQ_ENTRY(downstream_cfg) next;
};

/**
 * @brief a configuration structure representing a single x509 extension header.
 *
 */
struct x509_ext_cfg {
    char * name;                     /**< the name of the header */
    char * oid;                      /**< the oid of the x509 extension to pull */

    TAILQ_ENTRY(x509_ext_cfg) next;
};

/**
 * @brief which headers to add to the downstream request if avail.
 */
struct headers_cfg {
    bool x_forwarded_for;
    bool x_ssl_subject;
    bool x_ssl_issuer;
    bool x_ssl_notbefore;
    bool x_ssl_notafter;
    bool x_ssl_serial;
    bool x_ssl_cipher;
    bool x_ssl_certificate;

    TAILQ_HEAD(, x509_ext_cfg) x509_exts;
};

enum lb_method {
    lb_method_rtt = 0,
    lb_method_rr,
    lb_method_rand,
    lb_method_most_idle,
    lb_method_none
};

/**
 * @brief configuration for a single listening frontend server.
 */
struct server_cfg {
    char    * bind_addr;                      /**< address to bind to */
    uint16_t  bind_port;                      /**< port to bind to */
    int       num_threads;                    /**< number of worker threads to start */
    int       read_timeout;                   /**< timeout in seconds for upstream requests */
    int       write_timeout;                  /**< timeout in seconds for upstream writes */
    int       pending_timeout;                /**< timeout in seconds to wait for a downstream to become idle after connection */
    int       max_pending;                    /**< maximum number of pending requests */
    int       backlog;                        /**< backlog for listen() */
    lb_method lbalance_method;                /**< Method of loadbalancing (default RTT) */

    evhtp_ssl_cfg_t * ssl;                    /**< servers SSL configuration if enabled */
    headers_cfg_t   * headers;                /**< headers which are added to the backend request */
    logger_cfg_t    * logger;

    TAILQ_HEAD(, downstream_cfg) downstreams; /**< a list of downstream configs */
    TAILQ_HEAD(, rewrite_cfg) rewrites;       /**< a list of rewrite configs */

    TAILQ_ENTRY(server_cfg) next;
};

/**
 * @brief supported log output types
 */
enum logger_type {
    logger_type_file = 0,
    logger_type_syslog,
    logger_type_fd
};

struct logger_cfg {
    logger_type type;
    char      * filename;
    char      * errorlog;
    char      * format;
    int         syslog_facility;
};

/**
 * @brief structure representing the entire rproxy configuration file.
 */
struct rproxy_cfg {
    bool   daemonize;                 /**< if true process will run in background */
    char * rootdir;                   /**< root dir for daemonizing */
    char * user;                      /**< user to run as */
    char * group;                     /**< group to run as */
    int    max_nofile;                /**< the max number of open file descriptors */
    int    mem_trimsz;

    TAILQ_HEAD(, server_cfg) servers; /**< list of server configurations */
};

/**
 * @brief a downstream's connection status.
 */
enum downstream_status {
    downstream_status_nil = 0,        /**< connection has never been used */
    downstream_status_active,         /**< connection is actively processing */
    downstream_status_idle,           /**< connection is idle and available */
    downstream_status_down            /**< connection is down and cannot be used */
};


/**
 * @brief a structure representing a downstream connection.
 */
struct downstream_c {
    downstream_t    * parent;         /**< the parent downstream structure */
    evbev_t         * connection;     /**< the bufferevent connection */
    request_t       * request;        /**< the currently running request */
    event_t         * retry_timer;    /**< the timer event for reconnecting if down */
    downstream_status status;         /**< the status of this downstream */
    double            rtt;            /**< the last RTT for a request made to the connection */
    uint16_t          sport;          /**< the source port of the connected socket */
    uint8_t           bootstrapped;   /**< if not set to 1, the connection will immediately attempt the reconnect */
    struct timeval    tv_start;       /**< the time which the connection was set to active, used to calculate RTT */

    TAILQ_ENTRY(downstream_c) next;
};


/**
 * @brief a container active/idle/downed downstream connections
 */
struct downstream {
    downstream_cfg_t * config;         /**< this downstreams configuration */
    evbase_t         * evbase;
    rproxy_t         * rproxy;
    uint16_t           num_active;     /**< number of ents in the active list */
    uint16_t           num_idle;       /**< number of ents in the idle list */
    uint16_t           num_down;       /**< number of ents in the down list */

    TAILQ_HEAD(, downstream_c) active; /**< list of active connections */
    TAILQ_HEAD(, downstream_c) idle;   /**< list of idle and ready connections */
    TAILQ_HEAD(, downstream_c) down;   /**< list of connections which are down */

    TAILQ_ENTRY(downstream) next;
};


/**
 * @brief a matched rule container used as the argument for evhtp_set_regex_cb
 *
 */
struct rule {
    rproxy_t * rproxy;                  /**< the parent rproxy_t structure */
    char     * regex_from;              /**< a regex to match from the upstream */
    char     * regex_to;                /**< the regex uri to convert the 'from' sent to downstream */
};


#define REQUEST_HAS_ERROR(req) (req->error ? 1 : req->upstream_err ? 1 : 0)

/**
 * @brief structure which represents a full proxy request
 *
 */
struct request {
    rproxy_t        * rproxy;           /**< the parent rproxy_t structure */
    evhtp_request_t * upstream_request; /**< the client request */
    downstream_c_t  * downstream_conn;  /**< the downstream connection */
    rule_t          * rule;             /**< the matched rule */
    htparser        * parser;           /**< htparser for responses from the downstream */
    event_t         * pending_ev;       /**< event timer for pending status */

    uint8_t error;                      /**< set of downstream returns some type of error */
    uint8_t upstream_err;               /**< set if the upstream encountered a socket error */
    uint8_t done;                       /**< request fully proxied and completed */
    uint8_t pending;                    /**< request is waiting for a downstream connection to be avail */
    uint8_t hit_highwm;
    uint8_t reading;

    TAILQ_ENTRY(request) next;
};

enum logger_argtype {
    logger_argtype_nil = 0,
    logger_argtype_src,
    logger_argtype_proxy,
    logger_argtype_ts,
    logger_argtype_ua,
    logger_argtype_meth,
    logger_argtype_uri,
    logger_argtype_proto,
    logger_argtype_status,
    logger_argtype_ref,
    logger_argtype_host,
    logger_argtype_ds_sport,
    logger_argtype_us_sport,
    logger_argtype_us_hdrval,
    logger_argtype_ds_hdrval,
    logger_argtype_printable
};

struct logger_arg {
    logger_argtype type;
    char         * data;
    size_t         len;
    size_t         used;

    TAILQ_ENTRY(logger_arg) next;
};

/**
 * @brief logging callback functiosn for open/write/close
 */
struct logger_fns {
    void * (* logger_open)(void *);                /**< open a log */
    size_t (* logger_write)(const char *, void *); /**< write to a log */
    void   (* logger_close)(void *);               /**< close a log */
};


/**
 * @brief the logging wrapper backend.
 */
struct logger {
    logger_cfg_t * config;
    logger_fns     fns;                            /**< logging functions */
    void         * fnarg;                          /**< arguments returned from logger_open */
    FILE         * errorlog;                       /**< error logfile (default stderr) */

    TAILQ_HEAD(logger_args, logger_arg) args;      /* list of arguments to convert to a log string */
};

TAILQ_HEAD(downstream_q, downstream);
TAILQ_HEAD(pending_request_q, request);

/**
 * @brief the main rproxy_t structure
 */
struct rproxy {
    evhtp_t           * htp;                  /**< the evhtp_t backend */
    evbase_t          * evbase;               /**< the event base used for all events */
    event_t           * request_ev;           /**< event which is signaled to process pending upstream requests */
    logger_t          * logger;               /**< the logging backend */
    server_cfg_t      * server_cfg;           /**< server configuration */
    downstream_t      * last_downstream_used; /**< the last downstream used to service a request. Used for round-robin loadbalancing. */
    downstream_q_t      downstreams;          /**< list of downstreams */
    pending_request_q_t pending;              /**< list of pending upstream requests */
    int                 n_pending;            /**< number of pending requests */
};

int rproxy_init(evbase_t *, rproxy_cfg_t *);

/********************************************
 * configuration alloc/parsing functions
 *******************************************/

logger_cfg_t     * logger_cfg_new(void);
logger_cfg_t     * logger_cfg_parse(cfg_t *);
void               logger_cfg_free(logger_cfg_t *);

evhtp_ssl_cfg_t  * ssl_cfg_new(void);
evhtp_ssl_cfg_t  * ssl_cfg_parse(cfg_t *);
void               ssl_cfg_free(evhtp_ssl_cfg_t *);

downstream_cfg_t * downstream_cfg_new(void);
downstream_cfg_t * downstream_cfg_parse(cfg_t *);
void               downstream_cfg_free(downstream_cfg_t *);

rewrite_cfg_t    * rewrite_cfg_new(void);
rewrite_cfg_t    * rewrite_cfg_parse(cfg_t *);
void               rewrite_cfg_free(rewrite_cfg_t *);

headers_cfg_t    * headers_cfg_new(void);
headers_cfg_t    * headers_cfg_parse(cfg_t *);
void               headers_cfg_free(headers_cfg_t *);

server_cfg_t     * server_cfg_new(void);
server_cfg_t     * server_cfg_parse(cfg_t *);
void               server_cfg_free(server_cfg_t *);

rproxy_cfg_t     * rproxy_cfg_new(void);
rproxy_cfg_t     * rproxy_cfg_parse(cfg_t *);
rproxy_cfg_t     * rproxy_cfg_parse_file(const char *);
void               rproxy_cfg_free(rproxy_cfg_t *);

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
* Downstream handling functions
***********************************************/
downstream_t   * downstream_new(rproxy_t *, downstream_cfg_t *);
void             downstream_free(downstream_t *);

downstream_c_t * downstream_connection_new(evbase_t *, downstream_t *);
downstream_c_t * downstream_connection_get(rproxy_t *);
void             downstream_connection_free(downstream_c_t *);
int              downstream_connection_init(evbase_t *, downstream_t *);

int              downstream_connection_set_active(downstream_c_t *);
int              downstream_connection_set_idle(downstream_c_t *);
int              downstream_connection_set_down(downstream_c_t *);

/* downstream socket handling callbacks */
void downstream_connection_eventcb(evbev_t *, short, void *);
void downstream_connection_retry(int, short, void *);

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

/***********************************************
* Logger functions
***********************************************/
logger_t * logger_init(logger_cfg_t *);
void       logger_log_request(logger_t *, request_t *);
void       logger_log_errorf(logger_t *, char * fmt, ...);

#define logger_log_error(logger, fmt, ...)                  do {                                    \
        time_t t = time(NULL);                                                                      \
        struct tm * dm = localtime(&t);                                                             \
                                                                                                    \
        logger_log_errorf(logger, "[%02d:%02d:%02d] %s:[%d]: " fmt,                                 \
                          dm->tm_hour, dm->tm_min, dm->tm_sec, __FILE__, __LINE__, ## __VA_ARGS__); \
} while (0)

#define logger_log_request_error(logger, request, fmt, ...) do {                                            \
        time_t t = time(NULL);                                                                              \
        struct tm * dm = localtime(&t);                                                                     \
                                                                                                            \
        logger_log_request_errorf(logger, request, "[%02d:%02d:%02d] %s:[%d]: " fmt,                        \
                                  dm->tm_hour, dm->tm_min, dm->tm_sec, __FILE__, __LINE__, ## __VA_ARGS__); \
} while (0)


void * logger_open(logger_t *);
size_t logger_write(logger_t *, const char *);
void   logger_close(logger_t *);

#endif

