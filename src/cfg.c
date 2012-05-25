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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "rproxy.h"

#define DEFAULT_CIPHERS "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-RC4-SHA:ECDHE-RSA-AES128-SHA:RC4-SHA:RC4-MD5:ECDHE-RSA-AES256-SHA:AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA:AES128-SHA"

static cfg_opt_t logging_opts[] = {
    CFG_BOOL("enabled", cfg_false,                   CFGF_NONE),
    CFG_STR("type",     "file",                      CFGF_NONE),
    CFG_STR("filename", NULL,                        CFGF_NONE),
    CFG_STR("format",   "{SRC} {HOST} {URI} {HOST}", CFGF_NONE),
    CFG_STR("facility", "local0",                    CFGF_NONE),
    CFG_STR("errorlog", NULL,                        CFGF_NONE),
    CFG_END()
};

static cfg_opt_t x509_ext_opts[] = {
    CFG_STR("name", NULL, CFGF_NONE),
    CFG_STR("oid",  NULL, CFGF_NONE),
    CFG_END()
};

static cfg_opt_t headers_opts[] = {
    CFG_BOOL("x-forwarded-for",   cfg_true,      CFGF_NONE),
    CFG_BOOL("x-ssl-subject",     cfg_false,     CFGF_NONE),
    CFG_BOOL("x-ssl-issuer",      cfg_false,     CFGF_NONE),
    CFG_BOOL("x-ssl-notbefore",   cfg_false,     CFGF_NONE),
    CFG_BOOL("x-ssl-notafter",    cfg_false,     CFGF_NONE),
    CFG_BOOL("x-ssl-serial",      cfg_false,     CFGF_NONE),
    CFG_BOOL("x-ssl-cipher",      cfg_false,     CFGF_NONE),
    CFG_BOOL("x-ssl-certificate", cfg_true,      CFGF_NONE),
    CFG_SEC("x509-extension",     x509_ext_opts, CFGF_MULTI),
    CFG_END()
};

static cfg_opt_t retry_opts[] = {
    CFG_INT("seconds",  1, CFGF_NONE),
    CFG_INT("useconds", 0, CFGF_NONE),
    CFG_END()
};

static cfg_opt_t downstream_opts[] = {
    CFG_STR("addr",           "127.0.0.1", CFGF_NONE),
    CFG_INT("port",           80,          CFGF_NONE),
    CFG_INT("connections",    8,           CFGF_NONE),
    CFG_INT("high-watermark", 0,           CFGF_NONE),
    CFG_INT("read-timeout",   0,           CFGF_NONE),
    CFG_INT("write-timeout",  0,           CFGF_NONE),
    CFG_SEC("retry",          retry_opts,  CFGF_NONE),
    CFG_END()
};

static cfg_opt_t rewrite_opts[] = {
    CFG_STR("src", NULL, CFGF_NONE),
    CFG_STR("dst", NULL, CFGF_NONE),
    CFG_END()
};

static cfg_opt_t ssl_opts[] = {
    CFG_BOOL("enabled",           cfg_false,                   CFGF_NONE),
    CFG_STR_LIST("protocols-on",  "{ALL}",                     CFGF_NONE),
    CFG_STR_LIST("protocols-off", NULL,                        CFGF_NONE),
    CFG_STR("cert",               NULL,                        CFGF_NONE),
    CFG_STR("key",                NULL,                        CFGF_NONE),
    CFG_STR("ca",                 NULL,                        CFGF_NONE),
    CFG_STR("capath",             NULL,                        CFGF_NONE),
    CFG_STR("ciphers",            DEFAULT_CIPHERS,             CFGF_NONE),
    CFG_BOOL("verify-peer",       cfg_false,                   CFGF_NONE),
    CFG_BOOL("enforce-peer-cert", cfg_false,                   CFGF_NONE),
    CFG_INT("verify-depth",       0,                           CFGF_NONE),
    CFG_INT("context-timeout",    172800,                      CFGF_NONE),
    CFG_BOOL("cache-enabled",     cfg_true,                    CFGF_NONE),
    CFG_INT("cache-timeout",      1024,                        CFGF_NONE),
    CFG_INT("cache-size",         65535,                       CFGF_NONE),
    CFG_END()
};

static cfg_opt_t server_opts[] = {
    CFG_STR("addr",            "127.0.0.1",     CFGF_NONE),
    CFG_INT("port",            8080,            CFGF_NONE),
    CFG_STR("host",            NULL,            CFGF_NONE),
    CFG_INT("threads",         4,               CFGF_NONE),
    CFG_INT("read-timeout",    0,               CFGF_NONE),
    CFG_INT("write-timeout",   0,               CFGF_NONE),
    CFG_INT("pending-timeout", 0,               CFGF_NONE),
    CFG_INT("max-pending",     0,               CFGF_NONE),
    CFG_INT("backlog",         1024,            CFGF_NONE),
    CFG_STR("lb-method",       "rtt",           CFGF_NONE),
    CFG_SEC("ssl",             ssl_opts,        CFGF_NONE),
    CFG_SEC("rewrite",         rewrite_opts,    CFGF_MULTI),
    CFG_SEC("downstream",      downstream_opts, CFGF_MULTI),
    CFG_SEC("headers",         headers_opts,    CFGF_NONE),
    CFG_SEC("logging",         logging_opts,    CFGF_NONE),
    CFG_END()
};

static cfg_opt_t rproxy_opts[] = {
    CFG_BOOL("daemonize", cfg_false,   CFGF_NONE),
    CFG_STR("rootdir",    "/tmp",      CFGF_NONE),
    CFG_STR("user",       NULL,        CFGF_NONE),
    CFG_STR("group",      NULL,        CFGF_NONE),
    CFG_INT("memtrim-sz", 0,           CFGF_NONE),
    CFG_INT("max-nofile", 1024,        CFGF_NONE),
    CFG_SEC("server",     server_opts, CFGF_MULTI),
    CFG_END()
};

struct {
    int          facility;
    const char * str;
} facility_strmap[] = {
    { LOG_KERN,     "kern"     },
    { LOG_USER,     "user"     },
    { LOG_MAIL,     "mail"     },
    { LOG_DAEMON,   "daemon"   },
    { LOG_AUTH,     "auth"     },
    { LOG_SYSLOG,   "syslog"   },
    { LOG_LPR,      "lptr"     },
    { LOG_NEWS,     "news"     },
    { LOG_UUCP,     "uucp"     },
    { LOG_CRON,     "cron"     },
    { LOG_AUTHPRIV, "authpriv" },
    { LOG_FTP,      "ftp"      },
    { LOG_LOCAL0,   "local0"   },
    { LOG_LOCAL1,   "local1"   },
    { LOG_LOCAL2,   "local2"   },
    { LOG_LOCAL3,   "local3"   },
    { LOG_LOCAL4,   "local4"   },
    { LOG_LOCAL5,   "local5"   },
    { LOG_LOCAL6,   "local6"   },
    { LOG_LOCAL7,   "local7"   },
    { -1,           NULL       }
};

struct {
    logger_type  type;
    const char * str;
} logtype_strmap[] = {
    { logger_type_file,   "file"   },
    { logger_type_syslog, "syslog" },
    { logger_type_fd,     "fd"     },
    { -1,                 NULL     }
};


/**
 * @brief free logger_cfg_t resources
 *
 * @param c
 */
void
logger_cfg_free(logger_cfg_t * c) {
    if (c == NULL) {
        return;
    }

    if (c->filename) {
        free(c->filename);
    }
    if (c->format) {
        free(c->format);
    }

    free(c);
}

/**
 * @brief allocates a new logger_cfg_t resource
 *
 * @return logger_cfg_t * on success, NULL on error
 */
logger_cfg_t *
logger_cfg_new(void) {
    return calloc(sizeof(logger_cfg_t), 1);
}

/**
 * @brief parses a logger configuration
 *
 * @param cfg a libconfuse cfg_t structure containing logger info
 *
 * @return a logger_cfg_t instance on success, NULL on error
 */
logger_cfg_t *
logger_cfg_parse(cfg_t * cfg) {
    logger_cfg_t * lcfg;

    if (cfg == NULL) {
        return NULL;
    }

    /* if logging is not enabled, don't allocate */
    if (cfg_getbool(cfg, "enabled") == cfg_false) {
        return NULL;
    }

    if (!(lcfg = logger_cfg_new())) {
        return NULL;
    }

    if (cfg_getstr(cfg, "filename")) {
        lcfg->filename = strdup(cfg_getstr(cfg, "filename"));
    }

    if (cfg_getstr(cfg, "format")) {
        lcfg->format = strdup(cfg_getstr(cfg, "format"));
    }

    lcfg->type = logger_type_file;

    if (cfg_getstr(cfg, "type")) {
        int i;

        /* match the type value string to a logger_type enum */
        for (i = 0; logtype_strmap[i].str; i++) {
            if (!strcasecmp(logtype_strmap[i].str, cfg_getstr(cfg, "type"))) {
                lcfg->type = logtype_strmap[i].type;
                break;
            }
        }
    }

    if (cfg_getstr(cfg, "facility")) {
        int i;

        /* match the syslog facility value string to the integer var */
        for (i = 0; facility_strmap[i].str; i++) {
            if (!strcasecmp(facility_strmap[i].str, cfg_getstr(cfg, "facility"))) {
                lcfg->syslog_facility = facility_strmap[i].facility;
                break;
            }
        }
    }

    if (cfg_getstr(cfg, "errorlog")) {
        lcfg->errorlog = strdup(cfg_getstr(cfg, "errorlog"));
    }

    return lcfg;
} /* logger_cfg_parse */

/**
 * @brief free ssl configuration resources
 *
 * @param c
 */
void
ssl_cfg_free(evhtp_ssl_cfg_t * c) {
    if (c == NULL) {
        return;
    }

    if (c->pemfile) {
        free(c->pemfile);
    }
    if (c->privfile) {
        free(c->privfile);
    }
    if (c->cafile) {
        free(c->cafile);
    }
    if (c->capath) {
        free(c->capath);
    }
    if (c->ciphers) {
        free(c->ciphers);
    }

    free(c);
}

/**
 * @brief allocate a new ssl configuration resource
 *
 * @return evhtp_ssl_cfg_t * on success, NULL on error.
 */
evhtp_ssl_cfg_t *
ssl_cfg_new(void) {
    return calloc(sizeof(evhtp_ssl_cfg_t), 1);
}

/**
 * @brief parses and creates a new ssl_cfg_t resource
 *
 * @param cfg the libconfuse structure for the ssl opts
 *
 * @return evhtp_ssl_cfg_t * on success, NULL on error.
 */
evhtp_ssl_cfg_t *
ssl_cfg_parse(cfg_t * cfg) {
    evhtp_ssl_cfg_t * scfg;
    long              ssl_opts        = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;
    int               ssl_verify_mode = 0;
    int               proto_on_count;
    int               proto_off_count;
    int               i;

    if (cfg == NULL) {
        return NULL;
    }

    if (cfg_getbool(cfg, "enabled") == cfg_false) {
        return NULL;
    }

    if (!(scfg = ssl_cfg_new())) {
        return NULL;
    }

    if (cfg_getstr(cfg, "cert")) {
        scfg->pemfile = strdup(cfg_getstr(cfg, "cert"));
    }

    if (cfg_getstr(cfg, "key")) {
        scfg->privfile = strdup(cfg_getstr(cfg, "key"));
    }

    if (cfg_getstr(cfg, "ca")) {
        scfg->cafile = strdup(cfg_getstr(cfg, "ca"));
    }

    if (cfg_getstr(cfg, "capath")) {
        scfg->capath = strdup(cfg_getstr(cfg, "capath"));
    }

    if (cfg_getstr(cfg, "ciphers")) {
        scfg->ciphers = strdup(cfg_getstr(cfg, "ciphers"));
    }

    if (cfg_getbool(cfg, "verify-peer") == cfg_true) {
        ssl_verify_mode |= SSL_VERIFY_PEER;
    }

    if (cfg_getbool(cfg, "enforce-peer-cert") == cfg_true) {
        ssl_verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }

    if (ssl_verify_mode != 0) {
        scfg->verify_peer        = ssl_verify_mode;
        scfg->verify_depth       = cfg_getint(cfg, "verify-depth");
        scfg->x509_verify_cb     = ssl_x509_verifyfn;
        scfg->x509_chk_issued_cb = NULL;
    }

    if (cfg_getbool(cfg, "cache-enabled") == cfg_true) {
        scfg->scache_type    = evhtp_ssl_scache_type_internal;
        scfg->scache_size    = cfg_getint(cfg, "cache-size");
        scfg->scache_timeout = cfg_getint(cfg, "cache-timeout");
    }

    proto_on_count  = cfg_size(cfg, "protocols-on");
    proto_off_count = cfg_size(cfg, "protocols-off");

    for (i = 0; i < proto_on_count; i++) {
        const char * proto_str = cfg_getnstr(cfg, "protocols-on", i);

        if (!strcasecmp(proto_str, "SSLv2")) {
            ssl_opts &= ~SSL_OP_NO_SSLv2;
        } else if (!strcasecmp(proto_str, "SSLv3")) {
            ssl_opts &= ~SSL_OP_NO_SSLv3;
        } else if (!strcasecmp(proto_str, "TLSv1")) {
            ssl_opts &= ~SSL_OP_NO_TLSv1;
        } else if (!strcasecmp(proto_str, "ALL")) {
            ssl_opts = 0;
        }
    }

    for (i = 0; i < proto_off_count; i++) {
        const char * proto_str = cfg_getnstr(cfg, "protocols-off", i);

        if (!strcasecmp(proto_str, "SSLv2")) {
            ssl_opts |= SSL_OP_NO_SSLv2;
        } else if (!strcasecmp(proto_str, "SSLv3")) {
            ssl_opts |= SSL_OP_NO_SSLv3;
        } else if (!strcasecmp(proto_str, "TLSv1")) {
            ssl_opts |= SSL_OP_NO_TLSv1;
        } else if (!strcasecmp(proto_str, "ALL")) {
            ssl_opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;
        }
    }

    scfg->ssl_ctx_timeout = cfg_getint(cfg, "context-timeout");
    scfg->ssl_opts        = ssl_opts;

    return scfg;
} /* ssl_cfg_parse */

void
downstream_cfg_free(downstream_cfg_t * c) {
    if (c == NULL) {
        return;
    }

    if (c->host) {
        free(c->host);
    }

    free(c);
}

downstream_cfg_t *
downstream_cfg_new(void) {
    return calloc(sizeof(downstream_cfg_t), 1);
}

downstream_cfg_t *
downstream_cfg_parse(cfg_t * cfg) {
    downstream_cfg_t * dscfg;

    if (cfg == NULL) {
        return NULL;
    }

    if (!(dscfg = downstream_cfg_new())) {
        return NULL;
    }

    if (cfg_getstr(cfg, "addr")) {
        dscfg->host = strdup(cfg_getstr(cfg, "addr"));
    }

    dscfg->port           = cfg_getint(cfg, "port");
    dscfg->connections    = cfg_getint(cfg, "connections");
    dscfg->high_watermark = cfg_getint(cfg, "high-watermark");
    dscfg->read_timeout   = cfg_getint(cfg, "read-timeout");
    dscfg->write_timeout  = cfg_getint(cfg, "write-timeout");

    if (cfg_getsec(cfg, "retry")) {
        cfg_t * rcfg = cfg_getsec(cfg, "retry");

        dscfg->retry_ival.tv_sec  = cfg_getint(rcfg, "seconds");
        dscfg->retry_ival.tv_usec = cfg_getint(rcfg, "useconds");
    }

    return dscfg;
} /* downstream_cfg_parse */

void
rewrite_cfg_free(rewrite_cfg_t * c) {
    if (c == NULL) {
        return;
    }

    if (c->src) {
        free(c->src);
    }
    if (c->dst) {
        free(c->dst);
    }

    free(c);
}

rewrite_cfg_t *
rewrite_cfg_new(void) {
    return calloc(sizeof(rewrite_cfg_t), 1);
}

rewrite_cfg_t *
rewrite_cfg_parse(cfg_t * cfg) {
    rewrite_cfg_t * rwcfg;

    if (cfg == NULL) {
        return NULL;
    }

    if (!(rwcfg = rewrite_cfg_new())) {
        return NULL;
    }

    if (cfg_getstr(cfg, "src")) {
        rwcfg->src = strdup(cfg_getstr(cfg, "src"));
    }

    if (cfg_getstr(cfg, "dst")) {
        rwcfg->dst = strdup(cfg_getstr(cfg, "dst"));
    }

    return rwcfg;
}

void
x509_ext_cfg_free(x509_ext_cfg_t * c) {
    if (c == NULL) {
        return;
    }

    if (c->name) {
        free(c->name);
    }
    if (c->oid) {
        free(c->oid);
    }

    free(c);
}

x509_ext_cfg_t *
x509_ext_cfg_new(void) {
    return calloc(sizeof(x509_ext_cfg_t), 1);
}

x509_ext_cfg_t *
x509_ext_cfg_parse(cfg_t * cfg) {
    x509_ext_cfg_t * x509cfg;

    if (cfg == NULL) {
        return NULL;
    }

    if (!(x509cfg = x509_ext_cfg_new())) {
        return NULL;
    }

    if (cfg_getstr(cfg, "name")) {
        x509cfg->name = strdup(cfg_getstr(cfg, "name"));
    }

    if (cfg_getstr(cfg, "oid")) {
        x509cfg->oid = strdup(cfg_getstr(cfg, "oid"));
    }

    return x509cfg;
}

void
headers_cfg_free(headers_cfg_t * c) {
    x509_ext_cfg_t * xe;
    x509_ext_cfg_t * xe_save;

    if (c == NULL) {
        return;
    }

    for (xe = TAILQ_FIRST(&c->x509_exts); xe; xe = xe_save) {
        xe_save = TAILQ_NEXT(xe, next);

        x509_ext_cfg_free(xe);
    }

    free(c);
}

headers_cfg_t *
headers_cfg_new(void) {
    headers_cfg_t * c;

    if (!(c = calloc(sizeof(headers_cfg_t), 1))) {
        return NULL;
    }

    c->x_forwarded_for   = false;
    c->x_ssl_subject     = false;
    c->x_ssl_issuer      = false;
    c->x_ssl_notbefore   = false;
    c->x_ssl_notafter    = false;
    c->x_ssl_cipher      = false;
    c->x_ssl_certificate = false;

    TAILQ_INIT(&c->x509_exts);

    return c;
}

headers_cfg_t *
headers_cfg_parse(cfg_t * cfg) {
    headers_cfg_t * hcfg;
    int             n_x509_exts;
    int             i;

    if (cfg == NULL) {
        return NULL;
    }

    if (!(hcfg = headers_cfg_new())) {
        return NULL;
    }

    hcfg->x_forwarded_for   = cfg_getbool(cfg, "x-forwarded-for");
    hcfg->x_ssl_subject     = cfg_getbool(cfg, "x-ssl-subject");
    hcfg->x_ssl_issuer      = cfg_getbool(cfg, "x-ssl-issuer");
    hcfg->x_ssl_notbefore   = cfg_getbool(cfg, "x-ssl-notbefore");
    hcfg->x_ssl_notafter    = cfg_getbool(cfg, "x-ssl-notafter");
    hcfg->x_ssl_serial      = cfg_getbool(cfg, "x-ssl-serial");
    hcfg->x_ssl_cipher      = cfg_getbool(cfg, "x-ssl-cipher");
    hcfg->x_ssl_certificate = cfg_getbool(cfg, "x-ssl-certificate");

    n_x509_exts = cfg_size(cfg, "x509-extension");
    for (i = 0; i < n_x509_exts; i++) {
        x509_ext_cfg_t * x509cfg;

        if (!(x509cfg = x509_ext_cfg_parse(cfg_getnsec(cfg, "x509-extension", i)))) {
            continue;
        }

        TAILQ_INSERT_TAIL(&hcfg->x509_exts, x509cfg, next);
    }

    return hcfg;
}

void
server_cfg_free(server_cfg_t * c) {
    downstream_cfg_t * ds;
    downstream_cfg_t * ds_save;
    rewrite_cfg_t    * rw;
    rewrite_cfg_t    * rw_save;

    if (c == NULL) {
        return;
    }

    if (c->bind_addr) {
        free(c->bind_addr);
    }
    if (c->ssl) {
        free(c->ssl);
    }
    if (c->headers) {
        headers_cfg_free(c->headers);
    }

    for (ds = TAILQ_FIRST(&c->downstreams); ds; ds = ds_save) {
        ds_save = TAILQ_NEXT(ds, next);

        downstream_cfg_free(ds);
    }

    for (rw = TAILQ_FIRST(&c->rewrites); rw; rw = rw_save) {
        rw_save = TAILQ_NEXT(rw, next);

        rewrite_cfg_free(rw);
    }

    free(c);
}

server_cfg_t *
server_cfg_new(void) {
    server_cfg_t * cfg;

    if (!(cfg = calloc(sizeof(server_cfg_t), 1))) {
        return NULL;
    }

    TAILQ_INIT(&cfg->downstreams);
    TAILQ_INIT(&cfg->rewrites);

    return cfg;
}

/**
 * @brief Convert the config value of "lb-method" to a lb_method enum type.
 *
 * @param lbstr
 *
 * @return the lb_method enum
 */
static lb_method
_lbstr_to_lbtype(const char * lbstr) {
    if (!lbstr) {
        return lb_method_rtt;
    }

    if (!strcasecmp(lbstr, "rtt")) {
        return lb_method_rtt;
    }

    if (!strcasecmp(lbstr, "roundrobin")) {
        return lb_method_rr;
    }

    if (!strcasecmp(lbstr, "random")) {
        return lb_method_rand;
    }

    if (!strcasecmp(lbstr, "most-idle")) {
        return lb_method_most_idle;
    }

    if (!strcasecmp(lbstr, "none")) {
        return lb_method_none;
    }

    return lb_method_rtt;
}

server_cfg_t *
server_cfg_parse(cfg_t * cfg) {
    server_cfg_t * scfg;
    int            n_downstreams;
    int            n_rewrites;
    int            i;

    if (cfg == NULL) {
        return NULL;
    }

    if (!(scfg = server_cfg_new())) {
        return NULL;
    }

    scfg->num_threads     = cfg_getint(cfg, "threads");
    scfg->bind_addr       = strdup(cfg_getstr(cfg, "addr"));
    scfg->bind_port       = cfg_getint(cfg, "port");
    scfg->read_timeout    = cfg_getint(cfg, "read-timeout");
    scfg->write_timeout   = cfg_getint(cfg, "write-timeout");
    scfg->pending_timeout = cfg_getint(cfg, "pending-timeout");
    scfg->backlog         = cfg_getint(cfg, "backlog");
    scfg->max_pending     = cfg_getint(cfg, "max-pending");
    scfg->lbalance_method = _lbstr_to_lbtype(cfg_getstr(cfg, "lb-method"));

    scfg->ssl = ssl_cfg_parse(cfg_getsec(cfg, "ssl"));
    scfg->headers         = headers_cfg_parse(cfg_getsec(cfg, "headers"));
    scfg->logger          = logger_cfg_parse(cfg_getsec(cfg, "logging"));

    n_downstreams         = cfg_size(cfg, "downstream");
    n_rewrites = cfg_size(cfg, "rewrite");

    for (i = 0; i < n_downstreams; i++) {
        downstream_cfg_t * dscfg;

        if (!(dscfg = downstream_cfg_parse(cfg_getnsec(cfg, "downstream", i)))) {
            continue;
        }

        TAILQ_INSERT_TAIL(&scfg->downstreams, dscfg, next);
    }

    for (i = 0; i < n_rewrites; i++) {
        rewrite_cfg_t * rwcfg;

        if (!(rwcfg = rewrite_cfg_parse(cfg_getnsec(cfg, "rewrite", i)))) {
            continue;
        }

        TAILQ_INSERT_TAIL(&scfg->rewrites, rwcfg, next);
    }

    return scfg;
} /* server_cfg_parse */

void
rproxy_cfg_free(rproxy_cfg_t * cfg) {
    server_cfg_t * server;
    server_cfg_t * save;

    if (cfg == NULL) {
        return;
    }

    if (cfg->user) {
        free(cfg->user);
    }
    if (cfg->group) {
        free(cfg->group);
    }

    if (cfg->rootdir) {
        free(cfg->rootdir);
    }

    for (server = TAILQ_FIRST(&cfg->servers); server; server = save) {
        save = TAILQ_NEXT(server, next);

        server_cfg_free(server);
    }

    free(cfg);
}

rproxy_cfg_t *
rproxy_cfg_new(void) {
    rproxy_cfg_t * cfg;

    if (!(cfg = calloc(sizeof(rproxy_cfg_t), 1))) {
        return NULL;
    }

    TAILQ_INIT(&cfg->servers);

    return cfg;
}

rproxy_cfg_t *
rproxy_cfg_parse(cfg_t * cfg) {
    rproxy_cfg_t * rpcfg;
    int            n_servers;
    int            i;

    if (cfg == NULL) {
        return NULL;
    }

    if (!(rpcfg = rproxy_cfg_new())) {
        return NULL;
    }

    if (cfg_getstr(cfg, "user")) {
        rpcfg->user = strdup(cfg_getstr(cfg, "user"));
    }

    if (cfg_getstr(cfg, "group")) {
        rpcfg->group = strdup(cfg_getstr(cfg, "group"));
    }

    rpcfg->mem_trimsz = cfg_getint(cfg, "memtrim-sz");
    rpcfg->max_nofile = cfg_getint(cfg, "max-nofile");
    rpcfg->daemonize  = cfg_getbool(cfg, "daemonize");
    rpcfg->rootdir    = strdup(cfg_getstr(cfg, "rootdir"));

    n_servers         = cfg_size(cfg, "server");

    for (i = 0; i < n_servers; i++) {
        server_cfg_t * scfg;

        if (!(scfg = server_cfg_parse(cfg_getnsec(cfg, "server", i)))) {
            continue;
        }

        TAILQ_INSERT_TAIL(&rpcfg->servers, scfg, next);
    }

    return rpcfg;
}

rproxy_cfg_t *
rproxy_cfg_parse_file(const char * file) {
    rproxy_cfg_t * rpcfg;
    cfg_t        * cfg;

    if (file == NULL) {
        return NULL;
    }

    if (!(cfg = cfg_init(rproxy_opts, CFGF_NOCASE))) {
        return NULL;
    }

    if (cfg_parse(cfg, file) != 0) {
        return NULL;
    }

    rpcfg = rproxy_cfg_parse(cfg);
    cfg_free(cfg);

    return rpcfg;
}

