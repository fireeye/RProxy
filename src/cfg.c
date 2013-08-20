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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "rproxy.h"

#define DEFAULT_CIPHERS "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-RC4-SHA:ECDHE-RSA-AES128-SHA:RC4-SHA:RC4-MD5:ECDHE-RSA-AES256-SHA:AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA:AES128-SHA"

/* used to keep track of to-be-needed rlimit information, to be used later to
 * determine if the system settings can handle what is configured.
 */
static rproxy_rusage_t _rusage = { 0, 0, 0 };

static cfg_opt_t       ratelimit_opts[] = {
    CFG_INT("read",  UINT_MAX, CFGF_NONE),
    CFG_INT("write", UINT_MAX, CFGF_NONE),
    CFG_END()
};

static cfg_opt_t       ssl_crl_opts[] = {
    CFG_STR("file",        NULL,         CFGF_NONE),
    CFG_STR("dir",         NULL,         CFGF_NONE),
    CFG_INT_LIST("reload", "{ 10, 0  }", CFGF_NONE),
    CFG_END()
};

static cfg_opt_t       ssl_opts[] = {
    CFG_BOOL("enabled",           cfg_false,       CFGF_NONE),
    CFG_STR_LIST("protocols-on",  "{ALL}",         CFGF_NONE),
    CFG_STR_LIST("protocols-off", NULL,            CFGF_NONE),
    CFG_STR("cert",               NULL,            CFGF_NONE),
    CFG_STR("key",                NULL,            CFGF_NONE),
    CFG_STR("ca",                 NULL,            CFGF_NONE),
    CFG_STR("capath",             NULL,            CFGF_NONE),
    CFG_STR("ciphers",            DEFAULT_CIPHERS, CFGF_NONE),
    CFG_BOOL("verify-peer",       cfg_false,       CFGF_NONE),
    CFG_BOOL("enforce-peer-cert", cfg_false,       CFGF_NONE),
    CFG_INT("verify-depth",       0,               CFGF_NONE),
    CFG_INT("context-timeout",    172800,          CFGF_NONE),
    CFG_BOOL("cache-enabled",     cfg_true,        CFGF_NONE),
    CFG_INT("cache-timeout",      1024,            CFGF_NONE),
    CFG_INT("cache-size",         65535,           CFGF_NONE),
    CFG_SEC("crl",                ssl_crl_opts,    CFGF_NODEFAULT),
    CFG_END()
};

static cfg_opt_t       log_opts[] = {
    CFG_BOOL("enabled", cfg_false,                   CFGF_NONE),
    CFG_STR("output",   "file:/dev/stdout",          CFGF_NONE),
    CFG_STR("level",    "error",                     CFGF_NONE),
    CFG_STR("format",   "{SRC} {HOST} {URI} {HOST}", CFGF_NONE),
    CFG_END()
};

static cfg_opt_t       logging_opts[] = {
    CFG_SEC("request", log_opts, CFGF_NONE),
    CFG_SEC("error",   log_opts, CFGF_NONE),
    CFG_SEC("general", log_opts, CFGF_NONE),
    CFG_END()
};

static cfg_opt_t       downstream_opts[] = {
    CFG_BOOL("enabled",           cfg_true,       CFGF_NONE),
    CFG_STR("addr",               NULL,           CFGF_NODEFAULT),
    CFG_INT("port",               0,              CFGF_NODEFAULT),
    CFG_INT("connections",        1,              CFGF_NONE),
    CFG_INT("high-watermark",     0,              CFGF_NONE),
    CFG_INT_LIST("read-timeout",  "{ 0, 0 }",     CFGF_NONE),
    CFG_INT_LIST("write-timeout", "{ 0, 0 }",     CFGF_NONE),
    CFG_INT_LIST("retry",         "{ 0, 50000 }", CFGF_NONE),
    CFG_END()
};

static cfg_opt_t       x509_ext_opts[] = {
    CFG_STR("name", NULL, CFGF_NONE),
    CFG_STR("oid",  NULL, CFGF_NONE),
    CFG_END()
};

static cfg_opt_t       headers_opts[] = {
    CFG_BOOL("x-forwarded-for",   cfg_true,      CFGF_NONE),
    CFG_BOOL("x-ssl-subject",     cfg_false,     CFGF_NONE),
    CFG_BOOL("x-ssl-issuer",      cfg_false,     CFGF_NONE),
    CFG_BOOL("x-ssl-notbefore",   cfg_false,     CFGF_NONE),
    CFG_BOOL("x-ssl-notafter",    cfg_false,     CFGF_NONE),
    CFG_BOOL("x-ssl-serial",      cfg_false,     CFGF_NONE),
    CFG_BOOL("x-ssl-sha1",        cfg_false,     CFGF_NONE),
    CFG_BOOL("x-ssl-cipher",      cfg_false,     CFGF_NONE),
    CFG_BOOL("x-ssl-certificate", cfg_true,      CFGF_NONE),
    CFG_SEC("x509-extension",     x509_ext_opts, CFGF_MULTI),
    CFG_END()
};

static cfg_opt_t       rule_opts[] = {
    CFG_STR("uri-match",                   NULL,           CFGF_NODEFAULT),
    CFG_STR("uri-gmatch",                  NULL,           CFGF_NODEFAULT),
    CFG_STR("uri-rmatch",                  NULL,           CFGF_NODEFAULT),
    CFG_STR_LIST("downstreams",            NULL,           CFGF_NODEFAULT),
    CFG_STR("lb-method",                   "rtt",          CFGF_NONE),
    CFG_SEC("headers",                     headers_opts,   CFGF_NODEFAULT),
    CFG_INT_LIST("upstream-read-timeout",  NULL,           CFGF_NODEFAULT),
    CFG_INT_LIST("upstream-write-timeout", NULL,           CFGF_NODEFAULT),
    CFG_BOOL("passthrough",                cfg_false,      CFGF_NONE),
    CFG_BOOL("allow-redirect",             cfg_false,      CFGF_NONE),
    CFG_STR_LIST("redirect-filter",        NULL,           CFGF_NODEFAULT),
    CFG_SEC("rate-limit",                  ratelimit_opts, CFGF_NODEFAULT),
    CFG_END()
};

static cfg_opt_t       vhost_opts[] = {
    CFG_SEC("ssl",                ssl_opts,       CFGF_NODEFAULT),
    CFG_STR_LIST("aliases",       NULL,           CFGF_NONE),
    CFG_STR_LIST("strip-headers", "{}",           CFGF_NONE),
    CFG_SEC("logging",            logging_opts,   CFGF_NODEFAULT),
    CFG_SEC("headers",            headers_opts,   CFGF_NODEFAULT),
    CFG_SEC("rule",               rule_opts,      CFGF_TITLE | CFGF_MULTI | CFGF_NO_TITLE_DUPES),
    CFG_SEC("rate-limit",         ratelimit_opts, CFGF_NODEFAULT),
    CFG_END()
};

static cfg_opt_t       server_opts[] = {
    CFG_STR("addr",                      "127.0.0.1",     CFGF_NONE),
    CFG_INT("port",                      8080,            CFGF_NONE),
    CFG_INT("threads",                   4,               CFGF_NONE),
    CFG_INT_LIST("read-timeout",         "{ 0, 0 }",      CFGF_NONE),
    CFG_INT_LIST("write-timeout",        "{ 0, 0 }",      CFGF_NONE),
    CFG_INT_LIST("pending-timeout",      "{ 0, 0 }",      CFGF_NONE),
    CFG_INT("high-watermark",            0,               CFGF_NONE),
    CFG_INT("max-pending",               0,               CFGF_NONE),
    CFG_INT("backlog",                   1024,            CFGF_NONE),
    CFG_SEC("downstream",                downstream_opts, CFGF_MULTI | CFGF_TITLE | CFGF_NO_TITLE_DUPES),
    CFG_SEC("vhost",                     vhost_opts,      CFGF_MULTI | CFGF_TITLE | CFGF_NO_TITLE_DUPES),
    CFG_SEC("ssl",                       ssl_opts,        CFGF_NODEFAULT),
    CFG_SEC("logging",                   logging_opts,    CFGF_NODEFAULT),
    CFG_BOOL("disable-server-nagle",     cfg_false,       CFGF_NONE),
    CFG_BOOL("disable-client-nagle",     cfg_false,       CFGF_NONE),
    CFG_BOOL("disable-downstream-nagle", cfg_false,       CFGF_NONE),
    CFG_SEC("rate-limit",                ratelimit_opts,  CFGF_NODEFAULT),
    CFG_END()
};

static cfg_opt_t       rproxy_opts[] = {
    CFG_BOOL("daemonize", cfg_false,   CFGF_NONE),
    CFG_STR("rootdir",    "/tmp",      CFGF_NONE),
    CFG_STR("user",       NULL,        CFGF_NONE),
    CFG_STR("group",      NULL,        CFGF_NONE),
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

/**
 * @brief Convert the config value of "lb-method" to a lb_method enum type.
 *
 * @param lbstr
 *
 * @return the lb_method enum
 */
static lb_method
lbstr_to_lbtype(const char * lbstr) {
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

logger_cfg_t *
logger_cfg_new(void) {
    return (logger_cfg_t *)calloc(sizeof(logger_cfg_t), 1);
}

void
logger_cfg_free(logger_cfg_t * lcfg) {
    if (!lcfg) {
        return;
    }

    if (lcfg->path) {
        free(lcfg->path);
    }

    if (lcfg->format) {
        free(lcfg->format);
    }

    free(lcfg);
}

rproxy_cfg_t *
rproxy_cfg_new(void) {
    rproxy_cfg_t * cfg;

    cfg          = calloc(sizeof(rproxy_cfg_t), 1);
    assert(cfg != NULL);

    cfg->servers = lztq_new();
    assert(cfg->servers != NULL);

    return cfg;
}

void
rproxy_cfg_free(rproxy_cfg_t * cfg) {
    if (!cfg) {
        return;
    }

    if (cfg->rootdir) {
        free(cfg->rootdir);
    }

    if (cfg->user) {
        free(cfg->user);
    }

    if (cfg->group) {
        free(cfg->group);
    }

    lztq_free(cfg->servers);
    free(cfg);
}

headers_cfg_t *
headers_cfg_new(void) {
    headers_cfg_t * c;

    c = calloc(sizeof(headers_cfg_t), 1);
    assert(c != NULL);

    c->x_forwarded_for   = false;
    c->x_ssl_subject     = false;
    c->x_ssl_issuer      = false;
    c->x_ssl_notbefore   = false;
    c->x_ssl_notafter    = false;
    c->x_ssl_cipher      = false;
    c->x_ssl_certificate = false;

    c->x509_exts         = lztq_new();
    assert(c->x509_exts != NULL);

    return c;
}

void
headers_cfg_free(headers_cfg_t * cfg) {
    if (!cfg) {
        return;
    }

    lztq_free(cfg->x509_exts);
    free(cfg);
}

vhost_cfg_t *
vhost_cfg_new(void) {
    vhost_cfg_t * cfg;

    cfg = calloc(sizeof(vhost_cfg_t), 1);
    assert(cfg != NULL);

    cfg->rule_cfgs = lztq_new();
    assert(cfg->rule_cfgs != NULL);

    cfg->rules     = lztq_new();
    assert(cfg->rules != NULL);

    cfg->aliases   = lztq_new();
    assert(cfg->aliases != NULL);

    return cfg;
}

void
vhost_cfg_free(void * arg) {
    vhost_cfg_t * cfg = arg;

    if (!cfg) {
        return;
    }

    if (cfg->ssl_cfg) {
        free(cfg->ssl_cfg);
    }

    lztq_free(cfg->rules);
    lztq_free(cfg->rule_cfgs);
    free(cfg);
}

server_cfg_t *
server_cfg_new(void) {
    server_cfg_t * cfg;

    cfg              = calloc(sizeof(server_cfg_t), 1);
    cfg->downstreams = lztq_new();
    cfg->vhosts      = lztq_new();
    /* cfg->rules       = lztq_new(); */

    return cfg;
}

void
server_cfg_free(void * arg) {
    server_cfg_t * cfg = arg;

    if (!cfg) {
        return;
    }

    if (cfg->bind_addr) {
        free(cfg->bind_addr);
    }

    if (cfg->ssl_cfg) {
        free(cfg->ssl_cfg);
    }

    lztq_free(cfg->vhosts);
    lztq_free(cfg->downstreams);
    free(cfg);
}

rule_cfg_t *
rule_cfg_new(void) {
    rule_cfg_t * cfg;

    cfg = calloc(sizeof(rule_cfg_t), 1);
    assert(cfg != NULL);

    cfg->downstreams = lztq_new();
    assert(cfg != NULL);

    return cfg;
}

void
rule_cfg_free(void * arg) {
    rule_cfg_t * cfg = arg;

    if (!cfg) {
        return;
    }

    headers_cfg_free(cfg->headers);
    lztq_free(cfg->downstreams);
    free(cfg->matchstr);
    free(cfg);
}

downstream_cfg_t *
downstream_cfg_new(void) {
    return calloc(sizeof(downstream_cfg_t), 1);
}

void
downstream_cfg_free(void * arg) {
    downstream_cfg_t * cfg = arg;

    if (!cfg) {
        return;
    }

    if (cfg->name) {
        free(cfg->name);
    }

    if (cfg->host) {
        free(cfg->host);
    }

    free(cfg);
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

x509_ext_cfg_t *
x509_ext_cfg_new(void) {
    return calloc(sizeof(x509_ext_cfg_t), 1);
}

void
x509_ext_cfg_free(void * arg) {
    x509_ext_cfg_t * c = arg;

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

logger_cfg_t *
logger_cfg_parse(cfg_t * cfg) {
    logger_cfg_t * lcfg;
    char         * level_str;
    char         * output_str;
    char         * scheme;
    char         * path;
    int            i;

    if (cfg == NULL) {
        return NULL;
    }

    if (cfg_getbool(cfg, "enabled") == cfg_false) {
        return NULL;
    }

    lcfg        = logger_cfg_new();
    assert(lcfg != NULL);

    /* convert the level value from a string to the correct lzlog level enum */
    lcfg->level = lzlog_emerg;
    level_str   = cfg_getstr(cfg, "level");

    if (level_str != NULL) {
        if (!strcasecmp(level_str, "emerg")) {
            lcfg->level = lzlog_emerg;
        } else if (!strcasecmp(level_str, "alert")) {
            lcfg->level = lzlog_alert;
        } else if (!strcasecmp(level_str, "crit")) {
            lcfg->level = lzlog_crit;
        } else if (!strcasecmp(level_str, "error")) {
            lcfg->level = lzlog_err;
        } else if (!strcasecmp(level_str, "warn")) {
            lcfg->level = lzlog_warn;
        } else if (!strcasecmp(level_str, "notice")) {
            lcfg->level = lzlog_notice;
        } else if (!strcasecmp(level_str, "info")) {
            lcfg->level = lzlog_info;
        } else if (!strcasecmp(level_str, "debug")) {
            lcfg->level = lzlog_debug;
        } else {
            lcfg->level = lzlog_emerg;
        }
    }

    /* the output configuration directive is in the format of 'scheme:path'. If
     * the scheme is 'file', the path is the filename. If the scheme is
     * 'syslog', the path is the syslog facility.
     */
    output_str = strdup(cfg_getstr(cfg, "output"));
    assert(output_str != NULL);

    scheme     = strtok(output_str, ":");
    path       = strtok(NULL, ":");

    if (!strcasecmp(scheme, "file")) {
        lcfg->type = logger_type_file;
    } else if (!strcasecmp(scheme, "syslog")) {
        lcfg->type = logger_type_syslog;
    } else {
        lcfg->type = logger_type_file;
    }

    switch (lcfg->type) {
        case logger_type_file:
            lcfg->path = strdup(path);
            break;
        case logger_type_syslog:
            for (i = 0; facility_strmap[i].str; i++) {
                if (!strcasecmp(facility_strmap[i].str, path)) {
                    lcfg->facility = facility_strmap[i].facility;
                }
            }
            break;
        default:
            break;
    }

    lcfg->format = strdup(cfg_getstr(cfg, "format"));
    assert(lcfg->format != NULL);

    free(output_str);

    return lcfg;
} /* logger_cfg_parse */

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
    struct stat       file_stat;

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
        if (stat(scfg->pemfile, &file_stat) != 0) {
            fprintf(stderr, "Cannot find SSL cert file '%s'\n", scfg->pemfile);
            exit(EXIT_FAILURE);
        }
    }

    if (cfg_getstr(cfg, "key")) {
        scfg->privfile = strdup(cfg_getstr(cfg, "key"));
        if (stat(scfg->privfile, &file_stat) != 0) {
            fprintf(stderr, "Cannot find SSL key file '%s'\n", scfg->privfile);
            exit(EXIT_FAILURE);
        }
    }

    if (cfg_getstr(cfg, "ca")) {
        scfg->cafile = strdup(cfg_getstr(cfg, "ca"));
        if (stat(scfg->cafile, &file_stat) != 0) {
            fprintf(stderr, "Cannot find SSL ca file '%s'\n", scfg->cafile);
            exit(EXIT_FAILURE);
        }
    }

    if (cfg_getstr(cfg, "capath")) {
        scfg->capath = strdup(cfg_getstr(cfg, "capath"));
        if (stat(scfg->capath, &file_stat) != 0) {
            fprintf(stderr, "Cannot find SSL capath file '%s'\n", scfg->capath);
            exit(EXIT_FAILURE);
        }
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

    if (cfg_getsec(cfg, "crl")) {
        ssl_crl_cfg_t * crl_config;
        cfg_t         * crl_cfg;

        crl_cfg = cfg_getsec(cfg, "crl");
        assert(crl_cfg != NULL);

        if (!(crl_config = calloc(sizeof(ssl_crl_cfg_t), 1))) {
            fprintf(stderr, "Could not allocate crl cfg %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        if (cfg_getstr(crl_cfg, "file")) {
            crl_config->filename = strdup(cfg_getstr(crl_cfg, "file"));

            if (stat(crl_config->filename, &file_stat) == -1 || !S_ISREG(file_stat.st_mode)) {
                fprintf(stderr, "Cannot find CRL file '%s'\n", crl_config->filename);
                exit(EXIT_FAILURE);
            }
        }

        if (cfg_getstr(crl_cfg, "dir")) {
            crl_config->dirname = strdup(cfg_getstr(crl_cfg, "dir"));

            if (stat(crl_config->dirname, &file_stat) != 0 || !S_ISDIR(file_stat.st_mode)) {
                fprintf(stderr, "Cannot find CRL directory '%s'\n", crl_config->dirname);
                exit(EXIT_FAILURE);
            }
        }

        crl_config->reload_timer.tv_sec  = cfg_getnint(crl_cfg, "reload", 0);
        crl_config->reload_timer.tv_usec = cfg_getnint(crl_cfg, "reload", 1);

        /* at the moment evhtp does not give us an area where we can store this
         * type of information without breaking the configuration structure. But
         * it does have an optional user-supplied arguments, which we use here
         * to store our CRL configuration.
         */
        scfg->args = (void *)crl_config;
    }

    return scfg;
} /* ssl_cfg_parse */

/**
 * @brief parses ssl x509 extension headers
 *
 * @param cfg
 *
 * @return
 */
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

/**
 * @brief parses header addition config from server vhost { { rules { rule { headers { } } } } }
 *
 * @param cfg
 *
 * @return
 */
headers_cfg_t *
headers_cfg_parse(cfg_t * cfg) {
    headers_cfg_t * hcfg;
    int             n_x509_exts;
    int             i;

    if (cfg == NULL) {
        return NULL;
    }

    hcfg = headers_cfg_new();
    assert(hcfg != NULL);

    hcfg->x_forwarded_for   = cfg_getbool(cfg, "x-forwarded-for");
    hcfg->x_ssl_subject     = cfg_getbool(cfg, "x-ssl-subject");
    hcfg->x_ssl_issuer      = cfg_getbool(cfg, "x-ssl-issuer");
    hcfg->x_ssl_notbefore   = cfg_getbool(cfg, "x-ssl-notbefore");
    hcfg->x_ssl_notafter    = cfg_getbool(cfg, "x-ssl-notafter");
    hcfg->x_ssl_sha1        = cfg_getbool(cfg, "x-ssl-sha1");
    hcfg->x_ssl_serial      = cfg_getbool(cfg, "x-ssl-serial");
    hcfg->x_ssl_cipher      = cfg_getbool(cfg, "x-ssl-cipher");
    hcfg->x_ssl_certificate = cfg_getbool(cfg, "x-ssl-certificate");

    n_x509_exts = cfg_size(cfg, "x509-extension");

    for (i = 0; i < n_x509_exts; i++) {
        x509_ext_cfg_t * x509cfg;
        lztq_elem      * elem;

        x509cfg = x509_ext_cfg_parse(cfg_getnsec(cfg, "x509-extension", i));
        assert(x509cfg != NULL);

        elem    = lztq_append(hcfg->x509_exts, x509cfg, sizeof(x509cfg), x509_ext_cfg_free);
        assert(elem != NULL);
    }

    return hcfg;
}

/**
 * @brief parses a single rule from a server { vhost { rules { } } } config
 *
 * @param cfg
 *
 * @return
 */
rule_cfg_t *
rule_cfg_parse(cfg_t * cfg) {
    rule_cfg_t * rcfg;
    cfg_t      * ratelimit_cfg;
    const char * rname;
    int          i;

    assert(cfg != NULL);

    rname      = cfg_title(cfg);
    assert(rname != NULL);

    rcfg       = rule_cfg_new();
    assert(cfg != NULL);

    rcfg->name = strdup(rname);
    assert(rcfg->name != NULL);

    if (cfg_getstr(cfg, "uri-match")) {
        rcfg->type     = rule_type_exact;
        rcfg->matchstr = strdup(cfg_getstr(cfg, "uri-match"));
    } else if (cfg_getstr(cfg, "uri-gmatch")) {
        rcfg->type     = rule_type_glob;
        rcfg->matchstr = strdup(cfg_getstr(cfg, "uri-gmatch"));
    } else if (cfg_getstr(cfg, "uri-rmatch")) {
        rcfg->type     = rule_type_regex;
        rcfg->matchstr = strdup(cfg_getstr(cfg, "uri-rmatch"));
    } else {
        fprintf(stderr, "Rule %s has no match statement!\n", rname);
        exit(EXIT_FAILURE);
    }

    rcfg->lb_method      = lbstr_to_lbtype(cfg_getstr(cfg, "lb-method"));
    rcfg->headers        = headers_cfg_parse(cfg_getsec(cfg, "headers"));
    rcfg->passthrough    = cfg_getbool(cfg, "passthrough");
    rcfg->allow_redirect = cfg_getbool(cfg, "allow-redirect");

    if (cfg_getopt(cfg, "upstream-read-timeout")) {
        rcfg->up_read_timeout.tv_sec  = cfg_getnint(cfg, "upstream-read-timeout", 0);
        rcfg->up_read_timeout.tv_usec = cfg_getnint(cfg, "upstream-read-timeout", 1);
        rcfg->has_up_read_timeout     = 1;
    }

    if (cfg_getopt(cfg, "upstream-write-timeout")) {
        rcfg->up_write_timeout.tv_sec  = cfg_getnint(cfg, "upstream-write-timeout", 0);
        rcfg->up_write_timeout.tv_usec = cfg_getnint(cfg, "upstream-write-timeout", 1);
        rcfg->has_up_write_timeout     = 1;
    }

    if ((ratelimit_cfg = cfg_getsec(cfg, "rate-limit"))) {
        rcfg->ratelim_cfg = malloc(sizeof(ratelimit_cfg_t));

        rcfg->ratelim_cfg->read_rate = cfg_getint(ratelimit_cfg, "read");
        rcfg->ratelim_cfg->write_rate = cfg_getint(ratelimit_cfg, "read");
    }

    for (i = 0; i < cfg_size(cfg, "downstreams"); i++) {
        lztq_elem * elem;
        char      * ds_name;

        ds_name = strdup(cfg_getnstr(cfg, "downstreams", i));
        assert(ds_name != NULL);

        elem    = lztq_append(rcfg->downstreams, ds_name, strlen(ds_name), free);
        assert(elem != NULL);
    }

    if (rcfg->allow_redirect != 0 && cfg_size(cfg, "redirect-filter")) {
        /*
         * if the redirect option is enabled, optionally an administrator can
         * add a list of allowed hosts it may communicate with.
         */
        int n_filters;

        n_filters = cfg_size(cfg, "redirect-filter");
        assert(n_filters > 0);

        rcfg->redirect_filter = lztq_new();
        assert(rcfg->redirect_filter != NULL);

        for (i = 0; i < n_filters; i++) {
            lztq_elem * elem;
            char      * host_ent;

            host_ent = strdup(cfg_getnstr(cfg, "redirect-filter", i));
            assert(host_ent != NULL);

            elem     = lztq_append(rcfg->redirect_filter, host_ent,
                                   strlen(host_ent), free);
            assert(elem != NULL);
        }
    }

    return rcfg;
} /* rule_cfg_parse */

/**
 * @brief parses a downstream {} config entry from a server { } config.
 *
 * @param cfg
 *
 * @return
 */
downstream_cfg_t *
downstream_cfg_parse(cfg_t * cfg) {
    downstream_cfg_t * dscfg;

    assert(cfg != NULL);

    dscfg                        = downstream_cfg_new();
    assert(dscfg != NULL);

    dscfg->name                  = strdup(cfg_title(cfg));
    dscfg->enabled               = cfg_getbool(cfg, "enabled");
    dscfg->host                  = strdup(cfg_getstr(cfg, "addr"));
    dscfg->port                  = cfg_getint(cfg, "port");
    dscfg->n_connections         = cfg_getint(cfg, "connections");
    dscfg->high_watermark        = cfg_getint(cfg, "high-watermark");

    dscfg->read_timeout.tv_sec   = cfg_getnint(cfg, "read-timeout", 0);
    dscfg->read_timeout.tv_usec  = cfg_getnint(cfg, "read-timeout", 1);
    dscfg->write_timeout.tv_sec  = cfg_getnint(cfg, "write-timeout", 0);
    dscfg->write_timeout.tv_usec = cfg_getnint(cfg, "write-timeout", 1);
    dscfg->retry_ival.tv_sec     = cfg_getnint(cfg, "retry", 0);
    dscfg->retry_ival.tv_usec    = cfg_getnint(cfg, "retry", 1);

    if (dscfg->enabled == true) {
        _rusage.total_num_connections += dscfg->n_connections;
    }

    return dscfg;
}

vhost_cfg_t *
vhost_cfg_parse(cfg_t * cfg) {
    vhost_cfg_t * vcfg;
    cfg_t       * log_cfg;
    cfg_t       * req_log_cfg;
    cfg_t       * err_log_cfg;
    cfg_t       * hdr_cfg;
    cfg_t       * default_rule_cfg;
    cfg_t       * ratelimit_cfg;
    int           i;
    int           res;

    vcfg              = vhost_cfg_new();
    assert(vcfg != NULL);

    vcfg->server_name = strdup(cfg_title(cfg));
    vcfg->ssl_cfg     = ssl_cfg_parse(cfg_getsec(cfg, "ssl"));

    if ((ratelimit_cfg = cfg_getsec(cfg, "rate-limit"))) {
        vcfg->ratelim_cfg = malloc(sizeof(ratelimit_cfg_t));
        vcfg->ratelim_cfg->read_rate = cfg_getint(ratelimit_cfg, "read");
        vcfg->ratelim_cfg->write_rate = cfg_getint(ratelimit_cfg, "read");
    }


    for (i = 0; i < cfg_size(cfg, "rule"); i++) {
        lztq_elem  * elem;
        rule_cfg_t * rule;

        if (!(rule = rule_cfg_parse(cfg_getnsec(cfg, "rule", i)))) {
            return NULL;
        }

        rule->parent_vhost_cfg = vcfg;

        elem = lztq_append(vcfg->rule_cfgs, rule, sizeof(rule), rule_cfg_free);
        assert(elem != NULL);
    }

    for (i = 0; i < cfg_size(cfg, "aliases"); i++) {
        lztq_elem * elem;
        char      * name;

        assert(cfg_getnstr(cfg, "aliases", i) != NULL);

        name = strdup(cfg_getnstr(cfg, "aliases", i));
        assert(name != NULL);

        elem = lztq_append(vcfg->aliases, name, strlen(name), free);
        assert(elem != NULL);
    }

    if (cfg_size(cfg, "strip-headers")) {
        vcfg->strip_hdrs = lztq_new();
        assert(vcfg->strip_hdrs != NULL);

        for (i = 0; i < cfg_size(cfg, "strip-headers"); i++) {
            lztq_elem * elem;
            char      * hdr_name;

            assert(cfg_getnstr(cfg, "strip-headers", i) != NULL);

            hdr_name = strdup(cfg_getnstr(cfg, "strip-headers", i));
            assert(hdr_name != NULL);

            elem     = lztq_append(vcfg->strip_hdrs, hdr_name, strlen(hdr_name), free);
            assert(elem != NULL);
        }
    }


    log_cfg = cfg_getsec(cfg, "logging");
    hdr_cfg = cfg_getsec(cfg, "headers");

    if (log_cfg) {
        vcfg->req_log = logger_cfg_parse(cfg_getsec(log_cfg, "request"));
        vcfg->err_log = logger_cfg_parse(cfg_getsec(log_cfg, "error"));
    }

    if (hdr_cfg) {
        vcfg->headers = headers_cfg_parse(hdr_cfg);
    }

    return vcfg;
} /* vhost_cfg_parse */

/**
 * @brief parses a server {} entry from a config.
 *
 * @param cfg
 *
 * @return
 */
server_cfg_t *
server_cfg_parse(cfg_t * cfg) {
    server_cfg_t * scfg;
    cfg_t        * log_cfg;
    cfg_t        * ratelimit_cfg;
    int            i;
    int            res;

    assert(cfg != NULL);

    scfg                          = server_cfg_new();
    assert(scfg != NULL);

    scfg->bind_addr               = strdup(cfg_getstr(cfg, "addr"));
    scfg->bind_port               = cfg_getint(cfg, "port");
    scfg->ssl_cfg                 = ssl_cfg_parse(cfg_getsec(cfg, "ssl"));
    scfg->num_threads             = cfg_getint(cfg, "threads");
    scfg->listen_backlog          = cfg_getint(cfg, "backlog");
    scfg->max_pending             = cfg_getint(cfg, "max-pending");
    scfg->read_timeout.tv_sec     = cfg_getnint(cfg, "read-timeout", 0);
    scfg->read_timeout.tv_usec    = cfg_getnint(cfg, "read-timeout", 1);
    scfg->write_timeout.tv_sec    = cfg_getnint(cfg, "write-timeout", 0);
    scfg->write_timeout.tv_usec   = cfg_getnint(cfg, "write-timeout", 1);
    scfg->pending_timeout.tv_sec  = cfg_getnint(cfg, "pending-timeout", 0);
    scfg->pending_timeout.tv_usec = cfg_getnint(cfg, "pending-timeout", 1);
    scfg->high_watermark          = cfg_getint(cfg, "high-watermark");

    if (cfg_getbool(cfg, "disable-server-nagle") == cfg_true) {
        scfg->disable_server_nagle = 1;
    }

    if (cfg_getbool(cfg, "disable-client-nagle") == cfg_true) {
        scfg->disable_client_nagle = 1;
    }

    if (cfg_getbool(cfg, "disable-downstream-nagle") == cfg_true) {
        scfg->disable_downstream_nagle = 1;
    }

    if ((log_cfg = cfg_getsec(cfg, "logging"))) {
        scfg->req_log_cfg = logger_cfg_parse(cfg_getsec(log_cfg, "request"));
        scfg->err_log_cfg = logger_cfg_parse(cfg_getsec(log_cfg, "error"));
    }

    if ((ratelimit_cfg = cfg_getsec(cfg, "rate-limit"))) {
        scfg->ratelim_cfg = malloc(sizeof(ratelimit_cfg_t));
        scfg->ratelim_cfg->read_rate = cfg_getint(ratelimit_cfg, "read");
        scfg->ratelim_cfg->write_rate = cfg_getint(ratelimit_cfg, "read");
    }

    /* parse and insert all the configured downstreams */
    for (i = 0; i < cfg_size(cfg, "downstream"); i++) {
        lztq_elem        * elem;
        downstream_cfg_t * dscfg;

        dscfg = downstream_cfg_parse(cfg_getnsec(cfg, "downstream", i));
        assert(dscfg != NULL);

        elem  = lztq_append(scfg->downstreams, dscfg, sizeof(dscfg), downstream_cfg_free);
        assert(elem != NULL);
    }

    for (i = 0; i < cfg_size(cfg, "vhost"); i++) {
        lztq_elem   * elem;
        vhost_cfg_t * vcfg;

        vcfg = vhost_cfg_parse(cfg_getnsec(cfg, "vhost", i));
        assert(vcfg != NULL);

        vcfg->parent_server_cfg = scfg;

        elem = lztq_append(scfg->vhosts, vcfg, sizeof(vcfg), vhost_cfg_free);
        assert(elem != NULL);
    }

    _rusage.total_num_threads += scfg->num_threads;
    _rusage.total_max_pending += scfg->max_pending;

    return scfg;
} /* server_cfg_parse */

static rproxy_cfg_t *
rproxy_cfg_parse_(cfg_t * cfg) {
    rproxy_cfg_t * rpcfg;
    int            i;

    assert(cfg != NULL);

    rpcfg = rproxy_cfg_new();
    assert(rpcfg != NULL);

    if (cfg_getstr(cfg, "user")) {
        rpcfg->user = strdup(cfg_getstr(cfg, "user"));
    }

    if (cfg_getstr(cfg, "group")) {
        rpcfg->group = strdup(cfg_getstr(cfg, "group"));
    }

    if (cfg_getstr(cfg, "rootdir")) {
        rpcfg->rootdir = strdup(cfg_getstr(cfg, "rootdir"));
    }

    rpcfg->max_nofile = cfg_getint(cfg, "max-nofile");
    rpcfg->daemonize  = cfg_getbool(cfg, "daemonize");

    for (i = 0; i < cfg_size(cfg, "server"); i++) {
        lztq_elem    * elem;
        server_cfg_t * scfg;

        scfg = server_cfg_parse(cfg_getnsec(cfg, "server", i));
        assert(scfg != NULL);

        scfg->rproxy_cfg = rpcfg;

        elem = lztq_append(rpcfg->servers, scfg, sizeof(scfg), server_cfg_free);
        assert(elem != NULL);
    }

    /* set our rusage settings from the global one */
    memcpy(&rpcfg->rusage, &_rusage, sizeof(rproxy_rusage_t));

    return rpcfg;
} /* rproxy_cfg_parse_ */

rproxy_cfg_t *
rproxy_cfg_parse(const char * filename) {
    rproxy_cfg_t * rp_cfg;
    cfg_t        * cfg;

    if (!filename) {
        return NULL;
    }

    if (!(cfg = cfg_init(rproxy_opts, CFGF_NOCASE))) {
        return NULL;
    }

    if (cfg_parse(cfg, filename) != 0) {
        cfg_free(cfg);
        return NULL;
    }

    rp_cfg = rproxy_cfg_parse_(cfg);
    cfg_free(cfg);

    return rp_cfg;
}

