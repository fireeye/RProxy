#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "rproxy.h"
#include "regress.h"

static rproxy_cfg_t * rp_cfg = NULL;

static void
_cfg_parse_file(void * ptr) {
    rp_cfg = rproxy_cfg_parse_file("test/unit/regress_cfg.cfg");

    tt_assert(rp_cfg != NULL);
end:
    return;
}

static void
_cfg_headers_check_validity(headers_cfg_t * cfg,
                            bool            x_forwarded_for,
                            bool            x_ssl_subject,
                            bool            x_ssl_issuer,
                            bool            x_ssl_notbefore,
                            bool            x_ssl_notafter,
                            bool            x_ssl_serial,
                            bool            x_ssl_cipher,
                            bool            x_ssl_certificate) {
    tt_assert(cfg->x_forwarded_for == x_forwarded_for);
    tt_assert(cfg->x_ssl_subject == x_ssl_subject);
    tt_assert(cfg->x_ssl_issuer == x_ssl_issuer);
    tt_assert(cfg->x_ssl_notbefore == x_ssl_notbefore);
    tt_assert(cfg->x_ssl_notafter == x_ssl_notafter);
    tt_assert(cfg->x_ssl_serial == x_ssl_serial);
    tt_assert(cfg->x_ssl_cipher == x_ssl_cipher);
    tt_assert(cfg->x_ssl_certificate == x_ssl_certificate);

end:
    return;
}

static void
_cfg_logger_check_validity(logger_cfg_t * cfg, logger_type type,
                           const char * filename,
                           const char * errorlog,
                           const char * logfmt) {
    tt_assert(cfg->type == type);
    tt_assert(strcmp(cfg->filename, filename) == 0);
    tt_assert(strcmp(cfg->errorlog, errorlog) == 0);
    tt_assert(strcmp(cfg->format, logfmt) == 0);

end:
    return;
}

static void
_cfg_rewrite_check_validity(rewrite_cfg_t * cfg, const char * src, const char * dst) {
    tt_assert(strcmp(cfg->src, src) == 0);
    tt_assert(strcmp(cfg->dst, dst) == 0);

end:
    return;
}

static void
_cfg_server_check_validity(void * ptr) {
    server_cfg_t * serv_cfg;

    int            num_servers = 0;

    tt_assert(rp_cfg != NULL);

    TAILQ_FOREACH(serv_cfg, &rp_cfg->servers, next) {
        num_servers++;
    }

    tt_assert(num_servers == 2);

    num_servers = 0;

    TAILQ_FOREACH(serv_cfg, &rp_cfg->servers, next) {
        rewrite_cfg_t * rw_cfg;
        int             num_rewrites = 0;

        switch (num_servers++) {
            case 0:
                tt_assert(strcmp(serv_cfg->bind_addr, "127.0.0.1") == 0);
                tt_assert(serv_cfg->bind_port == 8081);
                tt_assert(serv_cfg->num_threads == 1);
                tt_assert(serv_cfg->read_timeout == 10);
                tt_assert(serv_cfg->write_timeout == 10);
                tt_assert(serv_cfg->pending_timeout == 5);
                tt_assert(serv_cfg->backlog == 1024);
                tt_assert(serv_cfg->ssl != NULL);
                tt_assert(serv_cfg->headers != NULL);

                _cfg_headers_check_validity(serv_cfg->headers,
                                            true, true, true, false,
                                            true, true, true, true);
                _cfg_logger_check_validity(serv_cfg->logger,
                                           logger_type_file,
                                           "./rproxy.log",
                                           "./rproxy_error.log",
                                           "{SRC} {PROXY} [{TS}] \"{METH} {URI} {PROTO}\" - {STATUS} - \"{REF}\" - \"{UA}\" - \"{HOST}\"");

                TAILQ_FOREACH(rw_cfg, &serv_cfg->rewrites, next) {
                    num_rewrites++;
                }

                tt_assert(num_rewrites == 2);
                num_rewrites = 0;

                TAILQ_FOREACH(rw_cfg, &serv_cfg->rewrites, next) {
                    switch (num_rewrites++) {
                        case 0:
                            _cfg_rewrite_check_validity(rw_cfg, "^(/dir/).*", "/");
                            break;
                        case 1:
                            _cfg_rewrite_check_validity(rw_cfg, "^(/a/b/).*", "/test/");
                            break;
                    }
                }

                break;
        } /* switch */
    }


end:
    return;
}         /* _cfg_server_check_validity */

struct testcase_t cfg_testcases[] = {
    { "parse-file",            _cfg_parse_file,            0, NULL, NULL },
    { "server-check-validity", _cfg_server_check_validity, 0, NULL, NULL },
    END_OF_TESTCASES
};

