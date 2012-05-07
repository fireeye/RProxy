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
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/resource.h>

#ifdef USE_MALLOPT
#include <malloc.h>
#endif

#ifndef NO_RLIMITS
#include <sys/time.h>
#include <sys/resource.h>
#endif

#include "rproxy.h"

static void rproxy_process_pending(int, short, void *);

int
append_ssl_x_headers(headers_cfg_t * headers_cfg, evhtp_request_t * upstream_req) {
    evhtp_headers_t * headers;
    x509_ext_cfg_t  * x509_ext_cfg;

    evhtp_ssl_t     * ssl;

    if (!headers_cfg || !upstream_req) {
        return -1;
    }

    if (!(ssl = upstream_req->conn->ssl)) {
        return 0;
    }

    if (!(headers = upstream_req->headers_in)) {
        return -1;
    }

    if (headers_cfg->x_ssl_subject == true) {
        unsigned char * subj_str;

        evhtp_kv_rm_and_free(headers, evhtp_kvs_find_kv(headers, "X-SSL-Subject"));

        if ((subj_str = ssl_subject_tostr(ssl))) {
            evhtp_headers_add_header(headers,
                                     evhtp_header_new("X-SSL-Subject", subj_str, 0, 1));

            free(subj_str);
        }
    }

    if (headers_cfg->x_ssl_issuer == true) {
        unsigned char * issr_str;

        evhtp_kv_rm_and_free(headers, evhtp_kvs_find_kv(headers, "X-SSL-Issuer"));

        if ((issr_str = ssl_issuer_tostr(ssl))) {
            evhtp_headers_add_header(headers,
                                     evhtp_header_new("X-SSL-Issuer", issr_str, 0, 1));

            free(issr_str);
        }
    }

    if (headers_cfg->x_ssl_notbefore == true) {
        unsigned char * nbf_str;

        evhtp_kv_rm_and_free(headers, evhtp_kvs_find_kv(headers, "X-SSL-Notbefore"));

        if ((nbf_str = ssl_notbefore_tostr(ssl))) {
            evhtp_headers_add_header(headers,
                                     evhtp_header_new("X-SSL-Notbefore", nbf_str, 0, 1));

            free(nbf_str);
        }
    }

    if (headers_cfg->x_ssl_notafter == true) {
        unsigned char * naf_str;

        evhtp_kv_rm_and_free(headers, evhtp_kvs_find_kv(headers, "X-SSL-Notafter"));

        if ((naf_str = ssl_notafter_tostr(ssl))) {
            evhtp_headers_add_header(headers,
                                     evhtp_header_new("X-SSL-Notafter", naf_str, 0, 1));

            free(naf_str);
        }
    }

    if (headers_cfg->x_ssl_serial == true) {
        unsigned char * ser_str;

        evhtp_kv_rm_and_free(headers, evhtp_kvs_find_kv(headers, "X-SSL-Serial"));

        if ((ser_str = ssl_serial_tostr(ssl))) {
            evhtp_headers_add_header(headers,
                                     evhtp_header_new("X-SSL-Serial", ser_str, 0, 1));

            free(ser_str);
        }
    }

    if (headers_cfg->x_ssl_cipher == true) {
        unsigned char * cip_str;

        evhtp_kv_rm_and_free(headers, evhtp_kvs_find_kv(headers, "X-SSL-Cipher"));

        if ((cip_str = ssl_cipher_tostr(ssl))) {
            evhtp_headers_add_header(headers,
                                     evhtp_header_new("X-SSL-Cipher", cip_str, 0, 1));

            free(cip_str);
        }
    }

    if (headers_cfg->x_ssl_certificate == true) {
        unsigned char * cert_str;

        evhtp_kv_rm_and_free(headers, evhtp_kvs_find_kv(headers, "X-SSL-Certificate"));

        if ((cert_str = ssl_cert_tostr(ssl))) {
            evhtp_headers_add_header(headers,
                                     evhtp_header_new("X-SSL-Certificate", cert_str, 0, 1));

            free(cert_str);
        }
    }

    {
        lztq_elem * x509_elem;
        lztq_elem * x509_save;

        for (x509_elem = lztq_first(headers_cfg->x509_exts); x509_elem; x509_elem = x509_save) {
            unsigned char * ext_str;

            x509_ext_cfg = lztq_elem_data(x509_elem);
            assert(x509_ext_cfg != NULL);

            if ((ext_str = ssl_x509_ext_tostr(ssl, x509_ext_cfg->oid))) {
                evhtp_headers_add_header(headers,
                                         evhtp_header_new(x509_ext_cfg->name, ext_str, 0, 1));
                free(ext_str);
            }

            x509_save = lztq_next(x509_elem);
        }
    }

    return 0;
} /* append_ssl_x_headers */

int
append_x_headers(headers_cfg_t * headers_cfg, evhtp_request_t * upstream_req) {
    evhtp_headers_t * headers;
    char              tmp1[1024];
    char              tmp2[1024];

    if (!headers_cfg || !upstream_req) {
        return -1;
    }

    if (!(headers = upstream_req->headers_in)) {
        return -1;
    }

    if (headers_cfg->x_forwarded_for == true) {
        struct sockaddr * sa;
        void            * src;
        char            * fmt;
        unsigned short    port;
        int               sres;

        src = NULL;
        sa  = upstream_req->conn->saddr;

        if (sa->sa_family == AF_INET) {
            src  = &(((struct sockaddr_in *)sa)->sin_addr);
            port = ntohs(((struct sockaddr_in *)sa)->sin_port);
            fmt  = "%s:%hu";
        } else if (sa->sa_family == AF_INET6) {
            src  = &(((struct sockaddr_in6 *)sa)->sin6_addr);
            port = ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
            fmt  = "[%s]:%hu";
        }

        if (!src || !evutil_inet_ntop(sa->sa_family, src, tmp1, sizeof(tmp1))) {
            return -1;
        }

        sres = snprintf(tmp2, sizeof(tmp2), fmt, tmp1, port);

        if (sres < 0 || sres >= sizeof(tmp2)) {
            return -1;
        }

        evhtp_kv_rm_and_free(headers, evhtp_kvs_find_kv(headers, "X-Forwarded-For"));

        evhtp_headers_add_header(headers,
                                 evhtp_header_new("X-Forwarded-For", tmp2, 0, 1));
    }

    if (upstream_req->conn->ssl) {
        if (append_ssl_x_headers(headers_cfg, upstream_req) < 0) {
            return -1;
        }
    }

    return 0;
} /* append_x_headers */

int
write_header_to_evbuffer(evhtp_header_t * header, void * arg) {
    evbuf_t * buf;

    buf = arg;
    assert(buf != NULL);

    evbuffer_add(buf, header->key, header->klen);
    evbuffer_add(buf, ": ", 2);
    evbuffer_add(buf, header->val, header->vlen);
    evbuffer_add(buf, "\r\n", 2);
    return 0;
}

evhtp_res
send_upstream_headers(evhtp_request_t * upstream_req, evhtp_headers_t * hdrs, void * arg) {
    /* evhtp has parsed the inital request (request + headers). From this
     * request generate a proper request which can be pipelined to the
     * downstream connection
     */
    request_t      * request;
    rproxy_t       * rproxy;
    evhtp_header_t * connection_hdr;
    evbuf_t        * buf;
    char           * query_args;

    assert(arg != NULL);

    request = arg;
    rproxy  = request->rproxy;
    assert(rproxy != NULL);

    if (request->pending == 1) {
        printf("break HERE pending == 1\n");
        abort();
    }

    if (!request->downstream_conn->connection) {
#if 0
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] send_upstream_headers() request->downstream_conn->connection == NULL");
#endif
        return EVHTP_RES_ERROR;
    }

    /* Add X-Headers to the request if applicable */
    if (append_x_headers(request->rule->config->headers, upstream_req) < 0) {
#if 0
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] send_upstream_headers() append_x_headers < 0");
#endif
        return EVHTP_RES_ERROR;
    }

    /* checks to determine of the upstream request is set to a
     * non keep-alive state, and if it is it magically converts
     * it to a keep-alive request to send to the downstream so
     * the connection remains open
     */
    switch (upstream_req->proto) {
        case EVHTP_PROTO_10:
            if (upstream_req->keepalive > 0) {
                break;
            }

            /* upstream request is HTTP/1.0 with no keep-alive header,
             * to keep our connection alive to the downstream we insert
             * a Connection: Keep-Alive header
             */

            if ((connection_hdr = evhtp_headers_find_header(hdrs, "Connection"))) {
                evhtp_header_rm_and_free(hdrs, connection_hdr);
            }

            connection_hdr = evhtp_header_new("Connection", "Keep-Alive", 0, 0);

            if (connection_hdr == NULL) {
#if 0
                logger_log_request_error(rproxy->logger, request,
                                         "[CRIT] Could not create new header! %s",
                                         strerror(errno));
#endif
                exit(EXIT_FAILURE);
            }

            evhtp_headers_add_header(hdrs, connection_hdr);
            break;
        case EVHTP_PROTO_11:
            if (upstream_req->keepalive > 0) {
                break;
            }

            /* upstream request is HTTP/1.1 but the Connection: close header was
             * present, so just remove the header to keep downstream connection
             * alive.
             */

            const char * v = evhtp_kv_find(hdrs, "Connection");

            connection_hdr = evhtp_headers_find_header(hdrs, "Connection");

            if (!strcasecmp(v, "close")) {
                upstream_req->keepalive = 0;
            }

            evhtp_header_rm_and_free(hdrs, connection_hdr);
            break;
        default:
#if 0
            logger_log_request_error(rproxy->logger, request,
                                     "[ERROR] send_upstream_headers() unknown proto %d", upstream_req->proto);
#endif
            return EVHTP_RES_ERROR;
    } /* switch */

    if (upstream_req->uri && upstream_req->uri->query_raw) {
        query_args = upstream_req->uri->query_raw;
    } else {
        query_args = "";
    }

    if (*query_args == '?') {
        query_args++;
    }

    if (!(buf = evbuffer_new())) {
#if 0
        logger_log_request_error(rproxy->logger, request,
                                 "[CRIT] Could not create new evbuffer! %s",
                                 strerror(errno));
#endif
        exit(EXIT_FAILURE);
    }

    evbuffer_add_printf(buf, "%s %s%s%s HTTP/%d.%d\r\n",
                        htparser_get_methodstr(upstream_req->conn->parser),
                        upstream_req->uri->path->full,
                        *query_args ? "?" : "", query_args,
                        htparser_get_major(upstream_req->conn->parser),
                        htparser_get_minor(upstream_req->conn->parser));

    evhtp_headers_for_each(hdrs, write_header_to_evbuffer, buf);

    evbuffer_add(buf, "\r\n", 2);
    bufferevent_write_buffer(request->downstream_conn->connection, buf);
    evbuffer_free(buf);

    return EVHTP_RES_OK;
} /* send_upstream_headers */

evhtp_res
send_upstream_body(evhtp_request_t * upstream_req, evbuf_t * buf, void * arg) {
    /* stream upstream request body to the downstream server */
    request_t      * request;
    rproxy_t       * rproxy;
    downstream_c_t * ds_conn;

    request = arg;
    assert(request != NULL);

    rproxy  = request->rproxy;
    assert(rproxy != NULL);

    if (!upstream_req || !buf) {
#if 0
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] send_upstream_body() upstream_req = %p, buf = %p", upstream_req, buf);
#endif
        return EVHTP_RES_FATAL;
    }

    if (!(ds_conn = request->downstream_conn)) {
#if 0
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] send_upstream_body() downstream_conn == NULL");
#endif
        return EVHTP_RES_FATAL;
    }

    if (!ds_conn->connection || request->error > 0) {
#if 0
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] send_upstream_body() conn->connection = %p, request->error == %d",
                                 ds_conn->connection, request->error);
#endif
        evbuffer_drain(buf, -1);

        return EVHTP_RES_ERROR;
    }

    bufferevent_write_buffer(ds_conn->connection, buf);

    if (ds_conn->parent->config->high_watermark > 0) {
        if (evbuffer_get_length(bufferevent_get_output(ds_conn->connection)) >= ds_conn->parent->config->high_watermark) {
            request->hit_highwm = 1;
#ifdef RPROXY_DEBUG
            printf("Hit high-watermark %zu: %zu in output\n",
                   ds_conn->parent->config->high_watermark,
                   evbuffer_get_length(bufferevent_get_output(ds_conn->connection)));
#endif
            evhtp_request_pause(upstream_req);
            return EVHTP_RES_PAUSE;
        }
    }

    return EVHTP_RES_OK;
} /* send_upstream_body */

evhtp_res
send_upstream_new_chunk(evhtp_request_t * upstream_req, uint64_t len, void * arg) {
    request_t      * request;
    rproxy_t       * rproxy;
    downstream_c_t * ds_conn;

    request = arg;
    assert(request != NULL);

    rproxy  = request->rproxy;
    assert(rproxy != NULL);

    if (!upstream_req) {
#if 0
        logger_log_error(rproxy->logger,
                         "[ERROR] send_upstream_new_chunk() upstream_req == NULL");
#endif
        return EVHTP_RES_FATAL;
    }

    if (!(ds_conn = request->downstream_conn)) {
#if 0
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] send_upstream_new_chunk() request->downstream_conn == NULL");
#endif
        return EVHTP_RES_FATAL;
    }

    if (!ds_conn->connection || request->error > 0) {
#if 0
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] send_upstream_new_chunk() conn->connection = %p, request->error = %d",
                                 ds_conn->connection, request->error);
#endif
        return EVHTP_RES_ERROR;
    }

    evbuffer_add_printf(bufferevent_get_output(ds_conn->connection),
                        "%x\r\n", (unsigned int)len);

    return EVHTP_RES_OK;
} /* send_upstream_new_chunk */

evhtp_res
send_upstream_chunk_done(evhtp_request_t * upstream_req, void * arg) {
    request_t      * request;
    rproxy_t       * rproxy;
    downstream_c_t * ds_conn;

    assert(arg != NULL);

    request = arg;
    rproxy  = request->rproxy;
    ds_conn = request->downstream_conn;

    if (!ds_conn->connection || request->error > 0) {
#if 0
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] send_upstream_chunk_done() conn->connection = %p, request->error = %d",
                                 ds_conn->connection, request->error);
#endif
        return EVHTP_RES_ERROR;
    }

    bufferevent_write(ds_conn->connection, "\r\n", 2);
    return EVHTP_RES_OK;
}

evhtp_res
send_upstream_chunks_done(evhtp_request_t * upstream_req, void * arg) {
    request_t      * request;
    rproxy_t       * rproxy;
    downstream_c_t * ds_conn;

    assert(arg != NULL);

    request = arg;
    rproxy  = request->rproxy;
    ds_conn = request->downstream_conn;

    if (!ds_conn->connection || request->error > 0) {
#if 0
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] send_upstream_chunks_done() conn->connection = %p, request->error = %d",
                                 ds_conn->connection, request->error);
#endif
        return EVHTP_RES_ERROR;
    }

    bufferevent_write(ds_conn->connection, "0\r\n\r\n", 5);
    return EVHTP_RES_OK;
}

evhtp_res
upstream_fini(evhtp_request_t * upstream_req, void * arg) {
    request_t      * request;
    rproxy_t       * rproxy;
    downstream_c_t * ds_conn;
    downstream_t   * downstream;
    int              res;

    assert(arg != NULL);

    request = arg;
    rproxy  = request->rproxy;
    assert(rproxy != NULL);

    /* if this downstream request is still pending, remove it from the queue */
    if (request->pending) {
        TAILQ_REMOVE(&rproxy->pending, request, next);
        rproxy->n_pending -= 1;
        request_free(request);
        return EVHTP_RES_OK;
    }

    ds_conn = request->downstream_conn;
    assert(ds_conn != NULL);

    if (REQUEST_HAS_ERROR(request)) {
#if 0
        logger_log_request_error(rproxy->logger, request, "[CRIT] we should never get here!");
#endif
        downstream_connection_set_down(ds_conn);
    } else {
        downstream_connection_set_idle(ds_conn);
    }

    request_free(request);

    return EVHTP_RES_OK;
} /* upstream_fini */

/**
 * @brief called when an upstream socket encounters an error.
 *
 * @param upstream_req
 * @param arg
 */
static void
upstream_error(evhtp_request_t * upstream_req, short events, void * arg) {
    request_t      * request;
    rproxy_t       * rproxy;
    downstream_c_t * ds_conn;

    request = arg;
    assert(request != NULL);

    rproxy  = request->rproxy;
    assert(rproxy != NULL);

    evhtp_unset_all_hooks(&upstream_req->hooks);

#if 0
    logger_log_error(rproxy->logger, "[WARN] client aborted error = %x", events);
#endif

    if (request->pending) {
        /* upstream encountered socket error while still in a pending state */
        assert(request->downstream_conn == NULL);

        TAILQ_REMOVE(&rproxy->pending, request, next);
        rproxy->n_pending -= 1;
        request_free(request);
        return;
    }

    request->upstream_err = 1;

    ds_conn = request->downstream_conn;
    assert(ds_conn != NULL);

    if (!request->reading) {
        /* since we are not currently dealing with data being parsed by
         * downstream_connection_readcb, we must do all the resource cleanup
         * here.
         */

        if (request->done) {
            /* the request was completely finished, so we can safely set the
             * downstream as idle.
             */
#if 0
            logger_log_request_error(rproxy->logger, request,
                                     "[WARN] request completed, client aborted");
#endif
            downstream_connection_set_idle(ds_conn);
        } else {
            /* request never completed, set the connection to down */
#if 0
            logger_log_request_error(rproxy->logger, request,
                                     "[WARN] request incomplete, client aborted");
#endif
            downstream_connection_set_down(ds_conn);
        }

        request_free(request);
    }
} /* upstream_error */

/**
 * @brief allocates a new downstream_t, and appends it to the
 *        rproxy->downstreams list. This is callback for the
 *        lztq_for_each function from rproxy_thread_init().
 *
 * @param elem
 * @param arg
 *
 * @return
 */
static int
add_downstream(lztq_elem * elem, void * arg) {
    rproxy_t         * rproxy = arg;
    downstream_cfg_t * ds_cfg = lztq_elem_data(elem);
    downstream_t     * downstream;
    lztq_elem        * nelem;

    assert(rproxy != NULL);
    assert(ds_cfg != NULL);

    downstream = downstream_new(rproxy, ds_cfg);
    assert(downstream != NULL);

    nelem      = lztq_append(rproxy->downstreams, downstream,
                             sizeof(downstream), downstream_free);
    assert(nelem != NULL);

    return 0;
}

/**
 * @brief creates n connections to the server information contained in a
 *        downstream_t instance. This is the callback for the lztq_for_each
 *        function from rproxy_thread_init() (after the downstream list has been
 *        created.
 *
 * @param elem
 * @param arg
 *
 * @return
 */
static int
start_downstream(lztq_elem * elem, void * arg) {
    evbase_t     * evbase     = arg;
    downstream_t * downstream = lztq_elem_data(elem);

    assert(evbase != NULL);
    assert(downstream != NULL);

    return downstream_connection_init(evbase, downstream);
}

/**
 * @brief match up names in the list of downstream_cfg_t's in rule_cfg->downstreams
 *        to the downstream_t's in the rproxy->downstreams list. If found,
 *        create a rule_t and appends it to the rproxy->rules list.
 *
 * @param elem
 * @param arg
 *
 * @return
 */
static int
associate_rule_with_downstreams(lztq_elem * elem, void * arg) {
    rproxy_t   * rproxy   = arg;
    rule_cfg_t * rule_cfg = lztq_elem_data(elem);
    lztq_elem  * name_elem;
    lztq_elem  * name_elem_temp;
    rule_t     * rule;

    assert(rproxy != NULL);
    assert(rule_cfg != NULL);

    rule              = calloc(sizeof(rule_t), 1);
    assert(rule != NULL);

    rule->rproxy      = rproxy;
    rule->config      = rule_cfg;

    rule->downstreams = lztq_new();
    assert(rule->downstreams != NULL);

    /* for each string in the rule_cfg's downstreams section, find the matching
     * downstream_t and append it.
     */
    for (name_elem = lztq_first(rule_cfg->downstreams); name_elem != NULL; name_elem = name_elem_temp) {
        const char   * ds_name = lztq_elem_data(name_elem);
        downstream_t * ds;
        lztq_elem    * nelem;

        assert(ds_name != NULL);

        if (!(ds = downstream_find_by_name(rproxy->downstreams, ds_name))) {
            /* could not find a downstream_t which has this name! */
            return -1;
        }

        nelem          = lztq_append(rule->downstreams, ds, sizeof(ds), NULL);
        assert(nelem != NULL);

        name_elem_temp = lztq_next(name_elem);
    }

    lztq_append(rproxy->rules, rule, sizeof(rule), NULL);

    return 0;
} /* associate_rule_with_downstreams */

static rule_t *
find_rule_from_cfg(rule_cfg_t * rule_cfg, lztq * rules) {
    lztq_elem * rule_elem;
    lztq_elem * rule_elem_temp;

    for (rule_elem = lztq_first(rules); rule_elem != NULL; rule_elem = rule_elem_temp) {
        rule_t * rule = lztq_elem_data(rule_elem);

        if (rule->config == rule_cfg) {
            return rule;
        }

        rule_elem_temp = lztq_next(rule_elem);
    }

    return NULL;
}

/**
 * @brief Called when an upstream request is in the pending queue and the
 *        configured timeout has been reached.
 *
 * @param fd
 * @param what
 * @param arg
 */
static void
downstream_pending_timeout(evutil_socket_t fd, short what, void * arg) {
    request_t       * ds_req;
    rproxy_t        * rproxy;
    evhtp_request_t * up_req;

    ds_req = arg;
    assert(ds_req != NULL);

    rproxy = ds_req->rproxy;
    assert(rproxy != NULL);

    up_req = ds_req->upstream_request;
    assert(up_req != NULL);

    /* unset all hooks except for the fini, evhtp_send_reply() will call the
     * fini function after the 503 message has been delivered */
    evhtp_unset_hook(&up_req->hooks, evhtp_hook_on_headers);
    evhtp_unset_hook(&up_req->hooks, evhtp_hook_on_new_chunk);
    evhtp_unset_hook(&up_req->hooks, evhtp_hook_on_chunk_complete);
    evhtp_unset_hook(&up_req->hooks, evhtp_hook_on_chunks_complete);
    evhtp_unset_hook(&up_req->hooks, evhtp_hook_on_read);
    evhtp_unset_hook(&up_req->hooks, evhtp_hook_on_error);

    up_req->keepalive = 0;

    evhtp_headers_add_header(up_req->headers_out, evhtp_header_new("Connection", "close", 0, 0));
    evhtp_send_reply(up_req, 503);
}

/**
 * @brief Before accepting an upstream connection, evhtp will call this function
 *        which will check whether we have hit our max-pending limits, and if so,
 *        inform evhtp to not accept().
 *
 * @param up_conn
 * @param arg
 *
 * @return
 */
evhtp_res
upstream_pre_accept(evhtp_connection_t * up_conn, void * arg) {
    rproxy_t * rproxy;

    if (!(rproxy = evthr_get_aux(up_conn->thread))) {
        return EVHTP_RES_FATAL;
    }

    if (rproxy->server_cfg->max_pending <= 0) {
        /* configured with unlimited pending */
        return EVHTP_RES_OK;
    }

    /* check to see if we have too many pending requests, and if so, drop this
     * connection.
     */
    if ((rproxy->n_pending + 1) > rproxy->server_cfg->max_pending) {
#ifdef RPROXY_DEBUG
        printf("Dropped connection, too many pending requests\n");
#endif
        return EVHTP_RES_ERROR;
    }

    return EVHTP_RES_OK;
}

evhtp_res
upstream_request_start(evhtp_request_t * up_req, evhtp_path_t * path, void * arg) {
    /* This function is called whenever evhtp has matched a rule on a request.
     *
     * Once the downstream request has been initialized and setup, this function
     * will *NOT* immediately start processing the request. This is because a
     * downstream connection may not be available at the time this function is
     * called.
     *
     * Instead, the request is placed in a pending request queue where this
     * queue is processed once downstream_connection_set_idle() has signaled the
     * process_pending event handler that a downstream connection is available.
     *
     * The return value of this function, EVHTP_RES_PAUSE, informs the evhtp
     * backend to suspend reading on the socket on the upstream until
     * process_pending successfully finds an idle downstream connection. From
     * there the upstream request is resumed.
     *
     * TL;DNR: upstream request is not immediately processed, but placed in a
     *         pending queue until a downstream connection becomes available.
     */
    rule_cfg_t         * rule_cfg   = NULL;
    rule_t             * rule       = NULL;
    rproxy_t           * rproxy     = NULL;
    request_t          * ds_req     = NULL;
    server_cfg_t       * serv_cfg   = NULL;
    evhtp_connection_t * up_conn    = NULL;
    struct timeval     * pending_tv = NULL;

    /* the rproxy structure is contained within the evthr's aux var */
    if (!(rproxy = evthr_get_aux(up_req->conn->thread))) {
        return EVHTP_RES_FATAL;
    }

    if (!(rule_cfg = arg)) {
        return EVHTP_RES_FATAL;
    }

    /* find the rule_t from rproxy->rules which matches the rule_cfg so that we
     * can use the proper downstream when this upstream request is serviced.
     */
    if (!(rule = find_rule_from_cfg(rule_cfg, rproxy->rules))) {
        return EVHTP_RES_FATAL;
    }

    serv_cfg                 = rproxy->server_cfg;
    assert(serv_cfg != NULL);

    ds_req                   = request_new(rproxy);
    assert(ds_req != NULL);

    up_conn                  = evhtp_request_get_connection(up_req);
    assert(up_conn != NULL);

    ds_req->upstream_request = up_req;
    ds_req->rule             = rule;
    ds_req->pending          = 1;
    rproxy->n_pending       += 1;

    /* if a rule has an upstream-[read|write]-timeout config set, we will set a
     * upstream connection-specific timeout that overrides the global one.
     */
    if (rule_cfg->has_up_read_timeout || rule_cfg->has_up_write_timeout) {
        evhtp_connection_set_timeouts(up_conn,
                                      &rule_cfg->up_read_timeout,
                                      &rule_cfg->up_write_timeout);
    }

    if (serv_cfg->pending_timeout.tv_sec || serv_cfg->pending_timeout.tv_usec) {
        /* a pending timeout has been configured, so set an evtimer to trigger
         * if this upstream request remains in the pending queue for that amount
         * of time.
         */
        ds_req->pending_ev = evtimer_new(rproxy->evbase, downstream_pending_timeout, ds_req);
        assert(ds_req->pending_ev != NULL);

        evtimer_add(ds_req->pending_ev, &serv_cfg->pending_timeout);
    }

    /* Since this is called after a path match, we set upstream request
     * specific evhtp hooks specific to this request. This is done in order
     * to stream the upstream data directly to the downstream and allow for
     * the modification of the request made to the downstream.
     */

    /* call this function once all headers from the upstream have been parsed */
    evhtp_set_hook(&up_req->hooks, evhtp_hook_on_headers,
                   send_upstream_headers, ds_req);

    evhtp_set_hook(&up_req->hooks, evhtp_hook_on_new_chunk,
                   send_upstream_new_chunk, ds_req);

    evhtp_set_hook(&up_req->hooks, evhtp_hook_on_chunk_complete,
                   send_upstream_chunk_done, ds_req);

    evhtp_set_hook(&up_req->hooks, evhtp_hook_on_chunks_complete,
                   send_upstream_chunks_done, ds_req);

    /* call this function if the upstream request contains a body */
    evhtp_set_hook(&up_req->hooks, evhtp_hook_on_read,
                   send_upstream_body, ds_req);

    /* call this function after the upstream request has been marked as complete
     */
    evhtp_set_hook(&up_req->hooks, evhtp_hook_on_request_fini,
                   upstream_fini, ds_req);

    /* call this function if the upstream request encounters a socket error */
    evhtp_set_hook(&up_req->hooks, evhtp_hook_on_error,
                   upstream_error, ds_req);

    /* insert this request into our pending queue and signal processor event */
    TAILQ_INSERT_TAIL(&rproxy->pending, ds_req, next);
    event_active(rproxy->request_ev, EV_WRITE, 1);

    /* tell evhtp to stop reading from the upstream socket */
    return EVHTP_RES_PAUSE;
} /* upstream_request_start */

/**
 * @brief the evthr init callback. Setup rproxy event base and initialize
 *         downstream connections.
 *
 * @param htp
 * @param thr
 * @param arg
 */
void
rproxy_thread_init(evhtp_t * htp, evthr_t * thr, void * arg) {
    evbase_t     * evbase;
    rproxy_t     * rproxy;
    server_cfg_t * server_cfg;
    int            res;

    assert(htp != NULL);
    assert(thr != NULL);

    server_cfg          = arg;
    assert(server_cfg != NULL);

    evbase              = evthr_get_base(thr);
    assert(evbase != NULL);

    rproxy              = calloc(sizeof(rproxy_t), 1);
    assert(rproxy != NULL);

    rproxy->downstreams = lztq_new();
    rproxy->rules       = lztq_new();

    assert(rproxy->downstreams != NULL);
    assert(rproxy->rules != NULL);

    /* init our pending request tailq */
    TAILQ_INIT(&rproxy->pending);

    rproxy->server_cfg = server_cfg;
    rproxy->evbase     = evbase;
    rproxy->htp        = htp;

    /* create a downstream_t instance for each configured downstream */
    res = lztq_for_each(server_cfg->downstreams, add_downstream, rproxy);
    assert(res == 0);

    /* enable the pending request processing event, this event is triggered
     * whenever a downstream connection becomes available.
     */
    rproxy->request_ev = event_new(evbase, -1, EV_READ | EV_PERSIST,
                                   rproxy_process_pending, rproxy);
    assert(rproxy->request_ev != NULL);

    /* set aux data argument to this threads specific rproxy_t structure */
    evthr_set_aux(thr, rproxy);

    /* start all of our downstream connections */
    res = lztq_for_each(rproxy->downstreams, start_downstream, evbase);
    assert(res == 0);

    /* Create a rule_t structure from each rule_cfg_t. The logic is as follows:
     *
     * Assume a configuration like the following:
     *
     * downstream ds_01 {
     *    addr = 127.0.0.1
     *    port = 8080
     * }
     *
     * downstream ds_02 {
     *    addr = 127.0.0.1
     *    port = 8081
     * }
     *
     * rules {
     *   if-uri-match '/blah' {
     *     downstreams = { "ds_01", "ds_02" }
     *   }
     * }
     *
     * the single rule here will use a connection from both "ds_01" and "ds_02"
     * to service a request if it matches.
     *
     * Since the rproxy_t structure will be available by our request callback
     * (via the evthr_t's aux data), we create rule_t structures containing a list of
     * downstream_t pointers that would service the request and append it to
     * rproxy->rules.
     *
     * The userdata argument passed to the request callback is a rule_cfg_t (as
     * defined in add_callback_rule()). It is now up to the request callback to
     * match the rule_cfg_t to the rule_t within the rproxy->rules list.
     *
     */
    res = lztq_for_each(server_cfg->rules, associate_rule_with_downstreams, rproxy);
    assert(res == 0);

    return;
} /* rproxy_thread_init */

/**
 * @brief Set an evhtp callback based on information in a single rule_cfg_t
 *        structure. Based on the rule type, we either use set_cb, set_regex_cb,
 *        or set_glob_cb. Only one real callback set is an on_path hook.
 *
 * @param elem
 * @param arg
 *
 * @return
 */
static int
add_callback_rule(lztq_elem * elem, void * arg) {
    evhtp_t          * htp  = arg;
    rule_cfg_t       * rule = lztq_elem_data(elem);
    evhtp_callback_t * cb   = NULL;

    switch (rule->type) {
        case rule_type_exact:
            cb = evhtp_set_cb(htp, rule->matchstr, NULL, rule);
            break;
        case rule_type_regex:
            cb = evhtp_set_regex_cb(htp, rule->matchstr, NULL, rule);
            break;
        case rule_type_glob:
            cb = evhtp_set_glob_cb(htp, rule->matchstr, NULL, rule);
            break;
    }

    assert(cb != NULL);

    /* if one of the callbacks matches, upstream_request_start will be called
     * with the argument of this rule_cfg_t
     */
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_path,
                   upstream_request_start, rule);

    return 0;
}

int
rproxy_init(evbase_t * evbase, rproxy_cfg_t * cfg) {
    lztq_elem * serv_elem;
    lztq_elem * serv_temp;

    assert(evbase != NULL);
    assert(cfg != NULL);

    /* iterate over each server_cfg, and set up evhtp stuff */
    for (serv_elem = lztq_first(cfg->servers); serv_elem != NULL; serv_elem = serv_temp) {
        struct timeval * tv_read  = NULL;
        struct timeval * tv_write = NULL;
        evhtp_t        * htp;
        server_cfg_t   * server;

        server = lztq_elem_data(serv_elem);
        assert(server != NULL);

        /* create a new evhtp base structure for just this server */
        htp    = evhtp_new(evbase, NULL);
        assert(htp != NULL);

        /* create a pre-accept callback which will disconnect the client
         * immediately if the max-pending request queue is over the configured
         * limit.
         */
        evhtp_set_pre_accept_cb(htp, upstream_pre_accept, NULL);

        /* for each rule, ccreate a evhtp callback with the defined type */
        lztq_for_each(server->rules, add_callback_rule, htp);

        if (server->ssl_cfg) {
            /* enable SSL support on this server */
            evhtp_ssl_init(htp, server->ssl_cfg);
        }

        /* if configured, set our upstream connection's read/write timeouts */
        if (server->read_timeout.tv_sec || server->read_timeout.tv_usec) {
            tv_read = &server->read_timeout;
        }

        if (server->write_timeout.tv_sec || server->write_timeout.tv_usec) {
            tv_write = &server->write_timeout;
        }

        if (tv_read || tv_write) {
            evhtp_set_timeouts(htp, tv_read, tv_write);
        }

        /* use a worker thread pool for connections, and for each
         * thread that is initialized call the rproxy_thread_init
         * function. rproxy_thread_init will create a new rproxy_t
         * instance for each of the threads
         */
        evhtp_use_threads(htp, rproxy_thread_init,
                          server->num_threads, server);

        if (evhtp_bind_socket(htp,
                              server->bind_addr,
                              server->bind_port,
                              server->listen_backlog) < 0) {
            fprintf(stderr, "[ERROR] unable to bind to %s:%d (%s)\n",
                    server->bind_addr,
                    server->bind_port,
                    strerror(errno));
            exit(-1);
        }

        serv_temp = lztq_next(serv_elem);
    }

    return 0;
}     /* rproxy_init */

static void
rproxy_process_pending(int fd, short which, void * arg) {
    rproxy_t  * rproxy;
    request_t * request;
    request_t * save;
    int         res;

    rproxy = arg;
    assert(rproxy != NULL);

    for (request = TAILQ_FIRST(&rproxy->pending); request; request = save) {
        save = TAILQ_NEXT(request, next);

        if (!(request->downstream_conn = downstream_connection_get(request->rule))) {
            continue;
        }

        /* set the connection to an active state so that other pending requests
         * do not get this same downstream connection.
         */
        res = downstream_connection_set_active(request->downstream_conn);
        assert(res >= 0);

        /* remove this request from the pending queue */
        TAILQ_REMOVE(&rproxy->pending, request, next);

        request->downstream_conn->request = request;
        request->pending   = 0;
        rproxy->n_pending -= 1;

        if (request->pending_ev != NULL) {
            /* delete the pending timer so that it does not trigger */
            evtimer_del(request->pending_ev);
        }


        /* since the upstream request processing has been paused, we must
         * unpause it to process it.
         */
        evhtp_request_resume(request->upstream_request);
    }
}

static void
rproxy_dropperms(const char * user, const char * group) {
    if (group) {
        struct group * grp;

        if (!(grp = getgrnam(group))) {
            fprintf(stderr, "No such group '%s'\n", group);
            exit(1);
        }

        if (setgid(grp->gr_gid) != 0) {
            fprintf(stderr, "Could not grp perm to '%s' (%s)\n",
                    group, strerror(errno));
            exit(1);
        }
    }

    if (user) {
        struct passwd * usr;

        if (!(usr = getpwnam(user))) {
            fprintf(stderr, "No such user '%s'\n", user);
            exit(1);
        }

        if (seteuid(usr->pw_uid) != 0) {
            fprintf(stderr, "Could not usr perm to '%s' (%s)\n",
                    user, strerror(errno));
            exit(1);
        }
    }
}

int
rproxy_daemonize(char * root, int noclose) {
    int fd;

    switch (fork()) {
        case -1:
            return -1;
        case 0:
            break;
        default:
            exit(EXIT_SUCCESS);
    }

    if (setsid() == -1) {
        return -1;
    }

    if (root == 0) {
        if (chdir(root) != 0) {
            perror("chdir");
            return -1;
        }
    }

    if (noclose == 0 && (fd = open("/dev/null", O_RDWR, 0)) != -1) {
        if (dup2(fd, STDIN_FILENO) < 0) {
            perror("dup2 stdin");
            return -1;
        }
        if (dup2(fd, STDOUT_FILENO) < 0) {
            perror("dup2 stdout");
            return -1;
        }
        if (dup2(fd, STDERR_FILENO) < 0) {
            perror("dup2 stderr");
            return -1;
        }

        if (fd > STDERR_FILENO) {
            if (close(fd) < 0) {
                perror("close");
                return -1;
            }
        }
    }
    return 0;
} /* daemonize */

int
rproxy_set_rlimits(int nofiles) {
#ifndef NO_RLIMITS
    struct rlimit limit;
    rlim_t        max_nofiles;

    if (nofiles <= 0) {
        return -1;
    }

    if (getrlimit(RLIMIT_NOFILE, &limit) == -1) {
        fprintf(stderr, "Could not obtain curr NOFILE lim: %s\n", strerror(errno));
        return -1;
    }

    if (nofiles > limit.rlim_max) {
        fprintf(stderr, "Unable to set curr NOFILE (requested=%d, sys-limit=%d)\n",
                (int)nofiles, (int)limit.rlim_max);
        fprintf(stderr, "Please make sure your systems limits.conf is set high enough (usually in /etc/security/limits.conf!\n");
        return -1;
    }

    if (nofiles < 10000) {
        fprintf(stderr, "WARNING: %d max-nofiles is very small, this could be bad, lets check...\n", nofiles);

        if (limit.rlim_max >= 10000) {
            fprintf(stderr, "INFO: using %d (your hard-limit) on max-nofiles instead of %d!\n", (int)limit.rlim_max, nofiles);
            nofiles = limit.rlim_max;
        } else {
            fprintf(stderr, "WARN: nope, can't go any higher, you may want to fix this...\n");
        }
    }

    limit.rlim_cur = nofiles;

    if (setrlimit(RLIMIT_NOFILE, &limit) == -1) {
        fprintf(stderr, "Could not set NOFILE lim: %s\n", strerror(errno));
        return -1;
    }

#endif
    return 0;
} /* rproxy_set_rlimits */

int
main(int argc, char ** argv) {
    rproxy_cfg_t * rproxy_cfg;
    evbase_t     * evbase;

    if (argc < 2) {
        printf("RProxy Version: %s (Libevhtp Version: %s, Libevent Version: %s, OpenSSL Version: %s)\n",
               RPROXY_VERSION, EVHTP_VERSION, event_get_version(), SSLeay_version(SSLEAY_VERSION));
        fprintf(stderr, "Usage: %s <config>\n", argv[0]);
        return -1;
    }

    if (!(rproxy_cfg = rproxy_cfg_parse(argv[1]))) {
        fprintf(stderr, "Error parsing file %s\n", argv[1]);
        return -1;
    }

#if 0
#ifdef USE_MALLOPT
    if (rproxy_cfg->mem_trimsz) {
        mallopt(M_TRIM_THRESHOLD, rproxy_cfg->mem_trimsz);
    }
#endif
#endif

    if (rproxy_set_rlimits(rproxy_cfg->max_nofile) < 0) {
        exit(-1);
    }

    if (rproxy_cfg->daemonize == true) {
        if (rproxy_daemonize(rproxy_cfg->rootdir, 1) < 0) {
            exit(-1);
        }
    }

    if (!(evbase = event_base_new())) {
        fprintf(stderr, "Error creating event_base: %s\n", strerror(errno));
        rproxy_cfg_free(rproxy_cfg);
        return -1;
    }

    rproxy_init(evbase, rproxy_cfg);

    if (rproxy_cfg->user || rproxy_cfg->group) {
        rproxy_dropperms(rproxy_cfg->user, rproxy_cfg->group);
    }

    event_base_loop(evbase, 0);

    return 0;
} /* main */

