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

#include "rproxy.h"

static cfg_opt_t ssl_opts[] = {
    CFG_BOOL("enabled",           cfg_false,                   CFGF_NONE),
    CFG_STR_LIST("protocols-on",  "{ALL}",                     CFGF_NONE),
    CFG_STR_LIST("protocols-off", NULL,                        CFGF_NONE),
    CFG_STR("cert",               NULL,                        CFGF_NONE),
    CFG_STR("key",                NULL,                        CFGF_NONE),
    CFG_STR("ca",                 NULL,                        CFGF_NONE),
    CFG_STR("capath",             NULL,                        CFGF_NONE),
    CFG_STR("ciphers",            "RC4+RSA:HIGH:+MEDIUM:+LOW", CFGF_NONE),
    CFG_BOOL("verify-peer",       cfg_false,                   CFGF_NONE),
    CFG_BOOL("enforce-peer-cert", cfg_false,                   CFGF_NONE),
    CFG_INT("verify-depth",       0,                           CFGF_NONE),
    CFG_INT("context-timeout",    172800,                      CFGF_NONE),
    CFG_BOOL("cache-enabled",     cfg_true,                    CFGF_NONE),
    CFG_INT("cache-timeout",      1024,                        CFGF_NONE),
    CFG_INT("cache-size",         65535,                       CFGF_NONE),
    CFG_END()
};

static cfg_opt_t log_opts[] = {
    CFG_BOOL("enabled", cfg_true,                    CFGF_NONE),
    CFG_STR("output",   "file:/dev/stdout",          CFGF_NONE),
    CFG_INT("level",    0,                           CFGF_NONE),
    CFG_STR("format",   "{SRC} {HOST} {URI} {HOST}", CFGF_NONE),
    CFG_END()
};

static cfg_opt_t logging_opts[] = {
    CFG_SEC("request", log_opts, CFGF_NONE),
    CFG_SEC("error",   log_opts, CFGF_NONE),
    CFG_END()
};

static cfg_opt_t downstream_opts[] = {
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

/* uri match options all share a commen set of configuration options, the only
 * difference is the hidden 'match-type' option is set per cfg_opt_t
 */
#define CFG_URI_MATCH_OPTS()                                      \
    CFG_STR_LIST("downstreams", NULL, CFGF_NODEFAULT),            \
    CFG_STR("lb-method", "rtt", CFGF_NONE),                       \
    CFG_STR("rewrite", NULL, CFGF_NONE),                          \
    CFG_SEC("headers", headers_opts, CFGF_NONE),                  \
    CFG_INT_LIST("upstream-read-timeout", NULL, CFGF_NODEFAULT),  \
    CFG_INT_LIST("upstream-write-timeout", NULL, CFGF_NODEFAULT), \
    CFG_BOOL("passthrough", cfg_false, CFGF_NONE)

static cfg_opt_t rule_exact_opts[] = {
    CFG_INT("type",       rule_type_exact, CFGF_NONE),
    CFG_URI_MATCH_OPTS(),
    CFG_END()
};

static cfg_opt_t rule_regex_opts[] = {
    CFG_INT("type",       rule_type_regex, CFGF_NONE),
    CFG_URI_MATCH_OPTS(),
    CFG_END()
};

static cfg_opt_t rule_glob_opts[] = {
    CFG_INT("type",       rule_type_glob, CFGF_NONE),
    CFG_URI_MATCH_OPTS(),
    CFG_END()
};

static cfg_opt_t vhost_opts[] = {
    CFG_SEC("ssl",           ssl_opts,        CFGF_NONE),
    CFG_SEC("if-uri-match",  rule_exact_opts, CFGF_TITLE | CFGF_MULTI | CFGF_NO_TITLE_DUPES),
    CFG_SEC("if-uri-rmatch", rule_regex_opts, CFGF_TITLE | CFGF_MULTI | CFGF_NO_TITLE_DUPES),
    CFG_SEC("if-uri-gmatch", rule_glob_opts,  CFGF_TITLE | CFGF_MULTI | CFGF_NO_TITLE_DUPES),
    CFG_STR_LIST("aliases",  NULL,            CFGF_NONE),
    CFG_SEC("logging",       logging_opts,    CFGF_NONE),
    CFG_END()
};

static cfg_opt_t server_opts[] = {
    CFG_STR("addr",                 "127.0.0.1",     CFGF_NONE),
    CFG_INT("port",                 8080,            CFGF_NONE),
    CFG_INT("threads",              4,               CFGF_NONE),
    CFG_INT_LIST("read-timeout",    "{ 0, 0 }",      CFGF_NONE),
    CFG_INT_LIST("write-timeout",   "{ 0, 0 }",      CFGF_NONE),
    CFG_INT_LIST("pending-timeout", "{ 0, 0 }",      CFGF_NONE),
    CFG_INT("max-pending",          0,               CFGF_NONE),
    CFG_INT("backlog",              1024,            CFGF_NONE),
    CFG_SEC("downstream",           downstream_opts, CFGF_MULTI | CFGF_TITLE | CFGF_NO_TITLE_DUPES),
    CFG_SEC("vhost",                vhost_opts,      CFGF_MULTI | CFGF_TITLE | CFGF_NO_TITLE_DUPES),
    CFG_SEC("ssl",                  ssl_opts,        CFGF_NONE),
    CFG_END()
};

static cfg_opt_t rproxy_opts[] = {
    CFG_BOOL("daemonize", cfg_false,   CFGF_NONE),
    CFG_STR("rootdir",    "/tmp",      CFGF_NONE),
    CFG_STR("user",       NULL,        CFGF_NONE),
    CFG_STR("group",      NULL,        CFGF_NONE),
    CFG_INT("max-nofile", 1024,        CFGF_NONE),
    CFG_SEC("server",     server_opts, CFGF_MULTI),
    CFG_END()
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

    cfg            = calloc(sizeof(vhost_cfg_t), 1);
    cfg->rule_cfgs = lztq_new();
    cfg->rules     = lztq_new();
    cfg->aliases   = lztq_new();

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

    assert(cfg != NULL);

    hcfg = headers_cfg_new();
    assert(hcfg != NULL);

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
    int          i;

    assert(cfg != NULL);

    rcfg              = rule_cfg_new();
    assert(cfg != NULL);

    rcfg->type        = cfg_getint(cfg, "type");
    rcfg->matchstr    = strdup(cfg_title(cfg));
    rcfg->lb_method   = lbstr_to_lbtype(cfg_getstr(cfg, "lb-method"));
    rcfg->headers     = headers_cfg_parse(cfg_getsec(cfg, "headers"));
    rcfg->passthrough = cfg_getbool(cfg, "passthrough");

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

    for (i = 0; i < cfg_size(cfg, "downstreams"); i++) {
        lztq_elem * elem;
        char      * ds_name;

        ds_name = strdup(cfg_getnstr(cfg, "downstreams", i));
        assert(ds_name != NULL);

        elem    = lztq_append(rcfg->downstreams, ds_name, strlen(ds_name), free);
        assert(elem != NULL);
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

    return dscfg;
}

static int
parse_rule_type_and_append(vhost_cfg_t * vhost, cfg_t * cfg, const char * name) {
    lztq * list;
    int    i;

    assert(vhost != NULL);
    assert(cfg != NULL);
    assert(name != NULL);

    list = vhost->rule_cfgs;
    assert(list != NULL);

    for (i = 0; i < cfg_size(cfg, name); i++) {
        lztq_elem  * elem;
        rule_cfg_t * rule;

        if (!(rule = rule_cfg_parse(cfg_getnsec(cfg, name, i)))) {
            return -1;
        }

        elem = lztq_append(list, rule, sizeof(rule), rule_cfg_free);
        assert(elem != NULL);
    }

    return i;
}

vhost_cfg_t *
vhost_cfg_parse(cfg_t * cfg) {
    vhost_cfg_t * vcfg;
    int           i;
    int           res;

    vcfg              = vhost_cfg_new();
    assert(vcfg != NULL);

    vcfg->server_name = strdup(cfg_title(cfg));
    vcfg->ssl_cfg     = ssl_cfg_parse(cfg_getsec(cfg, "ssl"));

    res = parse_rule_type_and_append(vcfg, cfg, "if-uri-match");
    assert(res >= 0);

    res = parse_rule_type_and_append(vcfg, cfg, "if-uri-rmatch");
    assert(res >= 0);

    res = parse_rule_type_and_append(vcfg, cfg, "if-uri-gmatch");
    assert(res >= 0);

    for (i = 0; i < cfg_size(cfg, "aliases"); i++) {
        lztq_elem * elem;
        char      * name;

        assert(cfg_getnstr(cfg, "aliases", i) != NULL);

        name = strdup(cfg_getnstr(cfg, "aliases", i));
        assert(name != NULL);

        elem = lztq_append(vcfg->aliases, name, strlen(name), free);
        assert(elem != NULL);
    }

    return vcfg;
}

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

        elem = lztq_append(scfg->vhosts, vcfg, sizeof(vcfg), vhost_cfg_free);
        assert(elem != NULL);
    }

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

        elem = lztq_append(rpcfg->servers, scfg, sizeof(scfg), server_cfg_free);
        assert(elem != NULL);
    }

    return rpcfg;
}

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

