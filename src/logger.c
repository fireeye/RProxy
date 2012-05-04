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

struct {
    logger_argtype type;
    const char   * str;
} logger_argtype_strmap[] = {
    { logger_argtype_src,       "{SRC}"      },
    { logger_argtype_proxy,     "{PROXY}"    },
    { logger_argtype_ds_sport,  "{DS_SPORT}" },
    { logger_argtype_us_sport,  "{US_SPORT}" },
    { logger_argtype_ts,        "{TS}"       },
    { logger_argtype_ua,        "{UA}"       },
    { logger_argtype_meth,      "{METH}"     },
    { logger_argtype_uri,       "{URI}"      },
    { logger_argtype_proto,     "{PROTO}"    },
    { logger_argtype_status,    "{STATUS}"   },
    { logger_argtype_ref,       "{REF}"      },
    { logger_argtype_host,      "{HOST}"     },
    { logger_argtype_us_hdrval, "{US_HDR}:"  },
    { logger_argtype_ds_hdrval, "{DS_HDR}:"  },
    { logger_argtype_printable, NULL         },
};

void
logger_log_request_tostr(logger_t * logger, request_t * request, evbuf_t * buf) {
    logger_arg_t       * arg;
    evhtp_request_t    * upstream_r;
    evhtp_connection_t * upstream_c;
    downstream_c_t     * downstream_c;
    downstream_t       * downstream;
    struct sockaddr_in * sin;
    int                  sres;
    char                 tmp[256];

    if (!logger) {
        return;
    }

    if (!request) {
        return;
    }

    if (!buf) {
        return;
    }

    if (!(upstream_r = request->upstream_request)) {
        return;
    }

    if (!(upstream_c = upstream_r->conn)) {
        return;
    }

    if (!(downstream_c = request->downstream_conn)) {
        return;
    }

    if (!(downstream = downstream_c->parent)) {
        return;
    }

    TAILQ_FOREACH(arg, &logger->args, next) {
        switch (arg->type) {
            case logger_argtype_us_hdrval:
                if (arg->data == NULL) {
                    evbuffer_add(buf, "-", 1);
                } else {
                    const char * hdr_val;

                    hdr_val = evhtp_header_find(upstream_r->headers_in, (const char *)arg->data);

                    if (hdr_val == NULL) {
                        evbuffer_add(buf, "-", 1);
                    } else {
                        evbuffer_add(buf, hdr_val, strlen(hdr_val));
                    }
                }
                break;
            case logger_argtype_ds_hdrval:
                if (arg->data == NULL) {
                    evbuffer_add(buf, "-", 1);
                } else {
                    const char * hdr_val;

                    hdr_val = evhtp_header_find(upstream_r->headers_out, (const char *)arg->data);

                    if (hdr_val == NULL) {
                        evbuffer_add(buf, "-", 1);
                    } else {
                        evbuffer_add(buf, hdr_val, strlen(hdr_val));
                    }
                }
                break;
            case logger_argtype_ds_sport:
                evbuffer_add_printf(buf, "%d", downstream_c->sport);
                break;
            case logger_argtype_us_sport:
                sin = (struct sockaddr_in *)upstream_c->saddr;

                evbuffer_add_printf(buf, "%d", ntohs(sin->sin_port));
                break;
            case logger_argtype_src:
                /* log the upstreams IP address */
                sin = (struct sockaddr_in *)upstream_c->saddr;

                evutil_inet_ntop(AF_INET, &sin->sin_addr, tmp, sizeof(tmp));
                evbuffer_add(buf, tmp, strlen(tmp));
                break;
            case logger_argtype_proxy:
                /* log the downstreams host and port information */
                sres = snprintf(tmp, sizeof(tmp), "%s:%d",
                                downstream->config->host,
                                downstream->config->port);

                if (sres >= sizeof(tmp) || sres < 0) {
                    /* overflow condition, shouldn't ever get here */
                    logger_log_error(logger, "[CRIT] overflow in log_request!\n");
                    exit(EXIT_FAILURE);
                }

                evbuffer_add(buf, tmp, strlen(tmp));
                break;
            case logger_argtype_ts:
            {
                /* log an RFC compliant HTTP log timestamp */
                time_t      t;
                struct tm * tmtmp;

                t     = time(NULL);
                tmtmp = localtime(&t);

                strftime(tmp, sizeof(tmp), "%d/%b/%Y:%X %z", tmtmp);
                evbuffer_add(buf, tmp, strlen(tmp));
            }
            break;
            case logger_argtype_meth:
                /* log the method of the request */
                evbuffer_add(buf, htparser_get_methodstr(upstream_c->parser),
                             strlen(htparser_get_methodstr(upstream_c->parser)));
                break;
            case logger_argtype_uri:
                /* log the URI requested by the upstream */
                if (upstream_r->uri && upstream_r->uri->path &&
                    upstream_r->uri->path->full) {
                    evbuffer_add(buf, upstream_r->uri->path->full,
                                 strlen(upstream_r->uri->path->full));
                } else {
                    evbuffer_add(buf, "-", 1);
                }
                break;
            case logger_argtype_proto:
                sres = snprintf(tmp, sizeof(tmp), "HTTP/%d.%d",
                                htparser_get_major(upstream_c->parser),
                                htparser_get_minor(upstream_c->parser));

                if (sres >= sizeof(tmp) || sres < 0) {
                    /* overflow condition, shouldn't get here */
                    logger_log_error(logger, "[CRIT] overflow in log_request!\n");
                    exit(EXIT_FAILURE);
                }

                evbuffer_add(buf, tmp, strlen(tmp));
                break;
            case logger_argtype_status:
                sres = snprintf(tmp, sizeof(tmp), "%d",
                                htparser_get_status(request->parser));

                if (sres >= sizeof(tmp) || sres < 0) {
                    /* overflow condition, shouldn't get here */
                    logger_log_error(logger, "[CRIT] overflow in log_request!\n");
                    exit(EXIT_FAILURE);
                }

                evbuffer_add(buf, tmp, strlen(tmp));
                break;
            case logger_argtype_ref:
            {
                char * ref_str;

                ref_str = (char *)evhtp_header_find(upstream_r->headers_in, "referrer");

                if (!ref_str) {
                    ref_str = "-";
                }

                evbuffer_add(buf, ref_str, strlen(ref_str));
            }
            break;
            case logger_argtype_ua:
            {
                char * ua_str;

                ua_str = (char *)evhtp_header_find(upstream_r->headers_in, "user-agent");

                if (!ua_str) {
                    ua_str = "-";
                }

                evbuffer_add(buf, ua_str, strlen(ua_str));
            }
            break;
            case logger_argtype_host:
            {
                char * h_str;

                h_str = (char *)evhtp_header_find(upstream_r->headers_in, "host");

                if (!h_str) {
                    h_str = "-";
                }

                evbuffer_add(buf, h_str, strlen(h_str));
            }
            break;
            case logger_argtype_printable:
                evbuffer_add(buf, arg->data, strlen(arg->data));
                break;
        } /* switch */
    }
}         /* logger_log_request_tostr */

void
logger_log_errorf(logger_t * logger, char * fmt, ...) {
    va_list ap;

    if (logger == NULL) {
        return;
    }

    va_start(ap, fmt);
    vfprintf(logger->errorlog, fmt, ap);
    va_end(ap);

    fprintf(logger->errorlog, "\n");
    fflush(logger->errorlog);
}

void
logger_log_request_errorf(logger_t * logger, request_t * request, char * fmt, ...) {
    va_list   ap;
    evbuf_t * buf;

    if (!logger) {
        return;
    }

    if (!(buf = evbuffer_new())) {
        logger_log_error(logger,
                         "[CRIT] Could not create new evbuffer! %s\n",
                         strerror(errno));
        exit(EXIT_FAILURE);
    }

    logger_log_request_tostr(logger, request, buf);
    evbuffer_add(buf, "\0", 1);

    /* Write the error text first */
    va_start(ap, fmt);
    vfprintf(logger->errorlog, fmt, ap);
    va_end(ap);

    /* Write the request str */
    fprintf(logger->errorlog, ", %s\n", evbuffer_pullup(buf, -1));
    evbuffer_free(buf);
}         /* logger_log_request_error */

void
logger_log_request(logger_t * logger, request_t * request) {
    evbuf_t * buf;

    if (!logger) {
        return;
    }

    if (!(buf = evbuffer_new())) {
        logger_log_error(logger,
                         "[CRIT] Could not create new evbuffer! %s\n",
                         strerror(errno));
        exit(EXIT_FAILURE);
    }

    logger_log_request_tostr(logger, request, buf);

    evbuffer_add(buf, "\0", 1);
    logger_write(logger, evbuffer_pullup(buf, -1));

    evbuffer_free(buf);
}         /* logger_log_request */

logger_argtype
logger_argtype_fromstr(const char * str, int * arglen) {
    int i;

    for (i = 0; logger_argtype_strmap[i].str; i++) {
        const char   * s = logger_argtype_strmap[i].str;
        logger_argtype t = logger_argtype_strmap[i].type;

        if (!strncasecmp(s, str, strlen(s))) {
            *arglen = strlen(s);

            return t;
        }
    }

    return -1;
}

logger_arg_t *
logger_arg_new(logger_argtype type) {
    logger_arg_t * a;

    if (type <= logger_argtype_nil) {
        return NULL;
    }

    if (!(a = calloc(sizeof(logger_arg_t), 1))) {
        return NULL;
    }

    a->type = type;

    return a;
}

int
logger_arg_addchar(logger_arg_t * arg, const char c) {
    if (arg == NULL) {
        return -1;
    }

    if (arg->data == NULL) {
        if (!(arg->data = calloc(8, 1))) {
            return -1;
        }

        arg->len  = 8;
        arg->used = 0;
    }

    if ((arg->used + 2) >= arg->len) {
        if (!(arg->data = realloc(arg->data, arg->len + 16))) {
            return -1;
        }

        arg->len += 16;
    }

    arg->data[arg->used++] = c;
    arg->data[arg->used]   = '\0';

    return 0;
}

void *
logger_syslog_open(void * largs) {
    int facility;

    if (largs == NULL) {
        facility = LOG_LOCAL7;
    } else {
        facility = *((int *)(largs));
    }

    openlog(NULL, LOG_NDELAY | LOG_PID, facility);

    return largs;
}

size_t
logger_syslog_write(const char * str, void * arg) {
    if (str == NULL) {
        return 0;
    }

    syslog(LOG_INFO, "%s", str);

    return strlen(str);
}

void
logger_syslog_close(void * arg) {
    closelog();
}

void *
logger_file_open(void * largs) {
    const char * file;
    FILE       * fp;

    if (!(file = largs)) {
        return (void *)stdout;
    }

    if (!(fp = fopen(file, "a+"))) {
        fprintf(stderr, "Could not open file %s: %s\n",
                file, strerror(errno));
        exit(EXIT_FAILURE);
    }

    return (void *)fp;
}

size_t
logger_file_write(const char * str, void * arg) {
    FILE * fp;
    size_t len;

    if (!str) {
        return 0;
    }

    if (!(fp = arg)) {
        return 0;
    }

    len  = fwrite((void *)str, strlen(str), 1, fp);
    len += fwrite("\n", 1, 1, fp);

    fflush(fp);

    return len;
}

void
logger_file_close(void * arg) {
    FILE * fp;

    if (!(fp = arg)) {
        return;
    }

    fclose(fp);
    return;
}

void *
logger_open(logger_t * logger) {
    void * largs;

    if (!logger) {
        return NULL;
    }

    switch (logger->config->type) {
        case logger_type_file:
            largs = logger->config->filename;
            break;
        case logger_type_syslog:
            largs = &logger->config->syslog_facility;
            break;
        default:
            largs = NULL;
            break;
    }

    if (logger->fns.logger_open) {
        logger->fnarg = (logger->fns.logger_open)(largs);
    }

    return logger->fnarg;
}

size_t
logger_write(logger_t * logger, const char * str) {
    if (logger && logger->fns.logger_write) {
        return (logger->fns.logger_write)(str, logger->fnarg);
    }

    return 0;
}

void
logger_close(logger_t * logger) {
    if (logger->fns.logger_close) {
        return (logger->fns.logger_close)(logger->fnarg);
    }
}

logger_t *
logger_init(logger_cfg_t * c) {
    logger_t   * logger;
    const char * strp;

    if (c == NULL) {
        return NULL;
    }

    if (!(logger = calloc(sizeof(logger_t), 1))) {
        return NULL;
    }

    logger->config = c;

    TAILQ_INIT(&logger->args);

    switch (c->type) {
        case logger_type_file:
            logger->fns.logger_open  = logger_file_open;
            logger->fns.logger_write = logger_file_write;
            logger->fns.logger_close = logger_file_close;
            break;
        case logger_type_syslog:
            logger->fns.logger_open  = logger_syslog_open;
            logger->fns.logger_write = logger_syslog_write;
            logger->fns.logger_close = logger_syslog_close;
            break;
        case logger_type_fd:
            break;
        default:
            break;
    }

    for (strp = c->format; *strp != '\0'; strp++) {
        logger_arg_t * larg   = NULL;
        int            insert = 0;

        if (*strp == '{') {
            int            arglen;
            logger_argtype type;

            if ((type = logger_argtype_fromstr(strp, &arglen)) < 0) {
                return NULL;
            }

            if (!(larg = logger_arg_new(type))) {
                return NULL;
            }

            strp  += arglen - 1;
            insert = 1;

            if (type == logger_argtype_us_hdrval || type == logger_argtype_ds_hdrval) {
                if (*strp++ != ':') {
                    printf("Log format error\n");
                    return NULL;
                }

                if (*strp++ != '\'') {
                    printf("Log format error\n");
                    return NULL;
                }

                while (1) {
                    if (*strp != '\'') {
                        logger_arg_addchar(larg, *strp++);
                    } else {
                        break;
                    }
                }
            }
        } else {
            if (TAILQ_EMPTY(&logger->args)) {
                larg = NULL;
            } else {
                larg = TAILQ_LAST(&logger->args, logger_args);
            }

            if (!larg || larg->type != logger_argtype_printable) {
                if (!(larg = logger_arg_new(logger_argtype_printable))) {
                    return NULL;
                }

                insert = 1;
            }

            if (logger_arg_addchar(larg, *strp) != 0) {
                return NULL;
            }
        }

        if (insert > 0) {
            TAILQ_INSERT_TAIL(&logger->args, larg, next);
        }
    }

    /* open error log */
    if (c->errorlog == NULL) {
        logger->errorlog = stderr;
    } else {
        logger->errorlog = fopen(c->errorlog, "a+");

        if (logger->errorlog == NULL) {
            fprintf(stderr, "Could not open errorlog %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    return logger;
}     /* logger_init */

