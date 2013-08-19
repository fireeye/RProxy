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
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "rproxy.h"

void
redir_us_readcb(evbev_t * bev, void * arg) {
    request_t * request = arg;

    bufferevent_write_buffer(request->downstream_bev,
                             bufferevent_get_input(bev));
    return;
}

void
redir_us_eventcb(evbev_t * bev, short events, void * arg) {
    request_t * request = arg;

    bufferevent_free(request->upstream_bev);
    bufferevent_free(request->downstream_bev);

    request_free(request);
}

void
redir_readcb(evbev_t * bev, void * arg) {
    /* data was read from the redir downstream, so we must send this data to the
     * upstream bufferevent.
     */
    request_t * request;

    request = arg;
    assert(request != NULL);

    bufferevent_write_buffer(request->upstream_bev, bufferevent_get_input(bev));
}

void
redir_writecb(evbev_t * bev, void * arg) {
    return;
}

void
redir_eventcb(evbev_t * bev, short events, void * arg) {
    request_t * request;

    request = arg;
    assert(request != NULL);

    if ((events & BEV_EVENT_CONNECTED)) {
        /* we have successfully established a connection to the redir host, so
         * we can re-enable the read side of the upstream bufferevent.
         */
        bufferevent_enable(request->upstream_bev, EV_READ | EV_WRITE);
        return;
    }

    bufferevent_free(request->upstream_bev);
    bufferevent_free(request->downstream_bev);

    request_free(request);
    return;
}

/*****************************************
 * Downstream response parsing functions
 ****************************************/

/**
 * @brief parse a header key from a downstream response.
 *
 * @param p
 * @param data
 * @param len
 *
 * @return 0 on success, -1 on error
 */
static int
proxy_parser_header_key(htparser * p, const char * data, size_t len) {
    request_t       * request;
    rproxy_t        * rproxy;
    evhtp_request_t * upstream_r;
    evhtp_header_t  * hdr;
    char            * key_s;

    assert(p != NULL);

    request = htparser_get_userdata(p);
    assert(request != NULL);

    rproxy  = request->rproxy;
    assert(rproxy != NULL);

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    if (!(upstream_r = request->upstream_request)) {
        request->error = 1;
        return -1;
    }

    if (!(key_s = malloc(len + 1))) {
        exit(EXIT_FAILURE);
    }

    key_s[len]    = '\0';
    memcpy(key_s, data, len);

    hdr           = evhtp_header_key_add(upstream_r->headers_out, key_s, 0);
    hdr->k_heaped = 1;

    return 0;
} /* proxy_parser_header_key */

/**
 * @brief parse a header value from a downstream response.
 *
 * @param p
 * @param data
 * @param len
 *
 * @return 0 on success, -1 on error
 */
static int
proxy_parser_header_val(htparser * p, const char * data, size_t len) {
    request_t       * request;
    rproxy_t        * rproxy;
    evhtp_request_t * upstream_r;
    evhtp_header_t  * hdr;
    char            * val_s;

    assert(p != NULL);

    request = htparser_get_userdata(p);
    assert(request != NULL);

    rproxy  = request->rproxy;
    assert(rproxy != NULL);

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    if (!(upstream_r = request->upstream_request)) {
        request->error = 1;
        return -1;
    }

    if (!(val_s = calloc(len + 1, 1))) {
        exit(EXIT_FAILURE);
    }


    val_s[len]    = '\0';
    memcpy(val_s, data, len);

    hdr           = evhtp_header_val_add(upstream_r->headers_out, val_s, 0);
    hdr->v_heaped = 1;

    return 0;
} /* proxy_parser_header_val */

/**
 * @brief called when the downstream headers have all been processed and starts
 *        the process of streaming the response to the upstream.
 *
 * Once all headers have been parsed from the downstream, this will call the
 * send_reply_start() function, which will start the streaming.
 *
 * @param p
 *
 * @return 0 on success, -1 on error.
 */
static int
proxy_parser_headers_complete(htparser * p) {
    request_t       * request;
    rproxy_t        * rproxy;
    rule_t          * rule;
    evhtp_request_t * upstream_r;
    vhost_t         * vhost;
    evhtp_res         res_code;

    assert(p != NULL);

    request = htparser_get_userdata(p);
    assert(request != NULL);

    rule    = request->rule;
    assert(rule != NULL);

    vhost   = rule->parent_vhost;
    assert(vhost != NULL);

    rproxy  = request->rproxy;
    assert(rproxy != NULL);
    assert(request->pending != 1);

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    if (!(upstream_r = request->upstream_request)) {
        request->error = 1;
        return -1;
    }

    res_code = htparser_get_status(p);

    if (res_code == 377 && rule->config->allow_redirect == true) {
        /* check for a X-Internal-Redirect header, and if found, we make a new
         * connection to the value of this and send the request that way.
         */
        const char * redir_host;

        logger_log_request_error(rproxy->err_log, request,
                                 "server redirect, attempting connection");

        if ((redir_host = evhtp_header_find(upstream_r->headers_out,
                                            "x-internal-redirect"))) {
            evbev_t * conn;
            evbev_t * upstream_bev;
            evbuf_t * request_buf;
            char    * redir_host_cpy;
            char    * hoststr;
            char    * portstr;
            char    * host;
            char    * cp;
            uint16_t  port;

            logger_log(rproxy->err_log, lzlog_info,
                       "found x-internal-redirect header value '%s'", redir_host);

            /*
             * make sure this value of this redirect is allowed if a filter is
             * present.
             */
            if (rule->config->redirect_filter) {
                if (util_glob_match_lztq(rule->config->redirect_filter, redir_host) != 1) {
                    /*
                     * this is not a match, so we remove the x-internal-redirect
                     * header, set the res code to a 401, and continue the
                     * processing.
                     */
                    res_code = 401;
                    evhtp_kv_rm_and_free(upstream_r->headers_out,
                                         evhtp_kvs_find_kv(upstream_r->headers_out,
                                                           "x-internal-redirect"));

                    goto start_reply;
                }
            }

            redir_host_cpy = strdup(redir_host);
            assert(redir_host_cpy != NULL);

            /* parse the hostname:port value into host and port, if no port
             * token is found, it defaults to 80
             */
            cp      = strchr(redir_host_cpy, ':');

            hoststr = redir_host_cpy;
            portstr = "80";

            if (cp) {
                /* found a possible port token */
                portstr = (char *)(cp + 1);
                redir_host_cpy[(int)(portstr - hoststr) - 1] = '\0';
            }

            host = hoststr;
            port = atoi(portstr);

            if (port <= 0) {
                /* invalid port, error this request out */
                request->error = 1;
                free(redir_host_cpy);
                return -1;
            }

            /* set the upstream_err so that downstream_connection_readcb's
             * return from htparser_run will set this downstream to down.
             *
             * TODO: fully process the response so that we don't have
             *      to set the downstream as down.
             */
            request->upstream_err = 1;

            /* we need to set the downstream_connection's request pointer to
             * NULL so that downstream_connection_readcb does not call
             * request_free() on this request_t.
             */
            request->downstream_conn->request = NULL;

            /* generate the request which will be sent to the redir host once it
             * establishes.
             */
            request_buf  = util_request_to_evbuffer(upstream_r);
            assert(request_buf != NULL);

            /* take ownership of the evhtp request bufferevent since this
             * connection will now act as if it is a passthrough socket.
             */
            upstream_bev = evhtp_connection_take_ownership(evhtp_request_get_connection(upstream_r));
            assert(upstream_bev != NULL);

            /* do not enable read side of the bufferevent yet, we do this once
             * the connection has been established to the redir host.
             */
            bufferevent_disable(upstream_bev, EV_READ);

            conn = bufferevent_socket_new(rproxy->evbase, -1,
                                          BEV_OPT_CLOSE_ON_FREE);
            assert(conn != NULL);

            /* TODO: parse the host:port, we just use 6999 as a test right now */
            bufferevent_socket_connect_hostname(conn, rproxy->dns_base,
                                                AF_INET, host, port);

            bufferevent_setcb(conn,
                              redir_readcb,
                              redir_writecb,
                              redir_eventcb, request);
            bufferevent_enable(conn, EV_READ | EV_WRITE);

            bufferevent_write_buffer(conn, request_buf);

            bufferevent_setcb(upstream_bev,
                              redir_us_readcb, NULL,
                              redir_us_eventcb, request);


            request->downstream_bev = conn;

            evbuffer_free(request_buf);
            free(redir_host_cpy);

            /* signal htparser_run to stop executing other callbacks */
            return -1;
        } else {
            logger_log(rproxy->err_log, lzlog_info,
                       "no x-internal-redirect header found!");
        }
    } else {
        if (res_code == 377) {
            logger_log(rproxy->err_log, lzlog_info,
                       "got a redirect, but no matching rule");
        }
    }

start_reply:
    /*
     * if this vhost has been configured to strip headers from the response, do
     * so now.
     */
    if (vhost->config->strip_hdrs) {
        util_rm_headers_via_lztq(vhost->config->strip_hdrs,
                                 upstream_r->headers_out);
    }

    /* downstream headers have been fully parsed, start streaming
     * further data to the upstream
     */
    evhtp_send_reply_start(upstream_r, res_code);

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    /* in the case the original upstream request was a HEAD method,
     * the body of the response will be empty, set the request to done,
     * but return -1 to stop the parsing process.
     */
    if (upstream_r->method == htp_method_HEAD) {
        request->error = 0;
        request->done  = 1;
        return -1;
    }

    return 0;
} /* proxy_parser_headers_complete */

/**
 * @brief called when the downstream parses the start of a new chunk.
 *
 * When the response parser finds the start of a new chunk, this function
 * is called to stream the initial chunk header to the upstream.
 *
 * @param p
 *
 * @return 0 on success, -1 on error.
 */
int
proxy_parser_new_chunk(htparser * p) {
    request_t       * request;
    rproxy_t        * rproxy;
    evhtp_request_t * upstream_r;
    evbuf_t         * buf;

    assert(p != NULL);

    request = htparser_get_userdata(p);
    assert(request != NULL);
    rproxy  = request->rproxy;

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    if (!(upstream_r = request->upstream_request)) {
        request->error = 1;
        return -1;
    }

    if (!(buf = evbuffer_new())) {
        exit(EXIT_FAILURE);
    }

    /* create and send a new chunk line to the upstream */
    evbuffer_add_printf(buf, "%x\r\n",
                        (unsigned int)htparser_get_content_length(p));

    evhtp_send_reply_body(upstream_r, buf);

    evbuffer_free(buf);

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    return 0;
} /* proxy_parser_new_chunk */

/**
 * @brief called when the downstream response parser has completed a single
 *        chunk
 *
 * When a single chunk of a downstream response has been completed, this
 * function is called in order to stream the CRLF to signify an end of a
 * chunk.
 *
 * @param p
 *
 * @return 0 on success, -1 on error.
 */
int
proxy_parser_chunk_complete(htparser * p) {
    /* an entire chunk has been parsed, send the final CRLF to the upstream */
    request_t       * request;
    rproxy_t        * rproxy;
    evhtp_request_t * upstream_r;
    evbuf_t         * buf;

    assert(p != NULL);

    request = htparser_get_userdata(p);
    assert(request != NULL);

    rproxy  = request->rproxy;
    assert(rproxy != NULL);

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    if (!(upstream_r = request->upstream_request)) {
        request->error = 1;
        return -1;
    }

    if (!(buf = evbuffer_new())) {
        exit(EXIT_FAILURE);
    }

    /* add a CRLF to terminate a single chunk */
    evbuffer_add(buf, "\r\n", 2);
    evhtp_send_reply_body(upstream_r, buf);
    evbuffer_free(buf);

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    return 0;
} /* proxy_parser_chunk_complete */

/**
 * @brief called when all chunks have been successfully sent to the upstream.
 *
 * When the downstream has completed sending all chunks, this will stream the
 * terminating chunk to the upstream.
 *
 * @param p
 *
 * @return 0 on success, -1 on error.
 */
int
proxy_parser_chunks_complete(htparser * p) {
    /* all chunks have been parsed, send the terminating 0 and CRLF */
    request_t       * request;
    rproxy_t        * rproxy;
    evhtp_request_t * upstream_r;
    evbuf_t         * buf;

    assert(p != NULL);

    request = htparser_get_userdata(p);
    assert(request != NULL);
    rproxy  = request->rproxy;

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    if (!(upstream_r = request->upstream_request)) {
        request->error = 1;
        return -1;
    }

    if (!(buf = evbuffer_new())) {
        exit(EXIT_FAILURE);
    }

    evbuffer_add(buf, "0\r\n\r\n", 5);
    evhtp_send_reply_body(upstream_r, buf);
    evbuffer_free(buf);

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    return 0;
} /* proxy_parser_chunks_complete */

/**
 * @brief called when a non-chunked downstream response body is parsed
 *
 * When any length of data in a response body is recieved, this will
 * stream the data to the upstream.
 *
 * @param p
 * @param data
 * @param len
 *
 * @return
 */
int
proxy_parser_body(htparser * p, const char * data, size_t len) {
    /* stream parsed body data from the downstream to the upstream */
    request_t       * request;
    rproxy_t        * rproxy;
    evhtp_request_t * upstream_r;
    evbuf_t         * buf;

    assert(p != NULL);

    request = htparser_get_userdata(p);
    assert(request != NULL);

    rproxy  = request->rproxy;
    assert(rproxy != NULL);

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    if (!(upstream_r = request->upstream_request)) {
        request->error = 1;
        return -1;
    }

    if (!(buf = evbuffer_new())) {
        exit(EXIT_FAILURE);
    }

    evbuffer_add(buf, data, len);
    evhtp_send_reply_body(upstream_r, buf);
    evbuffer_free(buf);

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    return 0;
} /* proxy_parser_body */

static int
proxy_parser_fini(htparser * p) {
    request_t       * request;
    rproxy_t        * rproxy;
    evhtp_request_t * upstream_r;

    assert(p != NULL);

    request = htparser_get_userdata(p);
    assert(request != NULL);

    rproxy  = request->rproxy;
    assert(rproxy != NULL);

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    if (!(upstream_r = request->upstream_request)) {
        request->error = 1;
        return -1;
    }

    /* the downstream response has no body data, so we mark the
     * request as done. Otherwise we must wait for the http parser
     * to call our read body callbacks (proxy_parser_*_chunk*() /
     * proxy_parser_body())
     */
    if (!htparser_get_content_pending(request->parser)) {
        request->done = 1;
    }

    return 0;
}

static int
proxy_parser_headers_begin(htparser * p) {
    request_t       * request;
    evhtp_request_t * upstream_r;
    evbuf_t         * buf;
    const char      * res_str;

    assert(p != NULL);

    request = htparser_get_userdata(p);
    assert(request != NULL);

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    if (htparser_get_status(p) >= 200) {
        /* this will be handled in headers_finished */
        return 0;
    }

    if (!(upstream_r = request->upstream_request)) {
        request->error = 1;
        return -1;
    }

    if (!(buf = bufferevent_get_output(evhtp_request_get_bev(upstream_r)))) {
        request->error = 1;
        return -1;
    }

    switch (htparser_get_status(p)) {
        case 100:
            res_str = "Continue";
            break;
        case 101:
            res_str = "Switching Protocols";
            break;
        default:
            res_str = "";
            break;
    }

    evbuffer_add_printf(buf, "HTTP/%d.%d %d %s\r\n\r\n",
                        htparser_get_major(p),
                        htparser_get_minor(p),
                        htparser_get_status(p), res_str);

    return 0;
} /* proxy_parser_headers_begin */

static htparse_hooks proxy_parser_hooks = {
    .on_msg_begin       = NULL,
    .method             = NULL,
    .scheme             = NULL,
    .host               = NULL,
    .port               = NULL,
    .path               = NULL,
    .args               = NULL,
    .uri                = NULL,
    .on_hdrs_begin      = proxy_parser_headers_begin,
    .hdr_key            = proxy_parser_header_key,
    .hdr_val            = proxy_parser_header_val,
    .on_hdrs_complete   = proxy_parser_headers_complete,
    .on_new_chunk       = proxy_parser_new_chunk,
    .on_chunk_complete  = proxy_parser_chunk_complete,
    .on_chunks_complete = proxy_parser_chunks_complete,
    .body               = proxy_parser_body,
    .on_msg_complete    = proxy_parser_fini
};


/**
 * @brief sets a downstream connection to idle and ready to be used.
 *
 * @param connection
 *
 * @return 0 on success, -1 on error.
 */
int
downstream_connection_set_idle(downstream_c_t * connection) {
    downstream_t * downstream;

    if (connection == NULL) {
        return -1;
    }

    if (!(downstream = connection->parent)) {
        return -1;
    }

    switch (connection->status) {
        case downstream_status_active:
            TAILQ_REMOVE(&downstream->active, connection, next);
            downstream->num_active -= 1;
            break;
        case downstream_status_idle:
            TAILQ_REMOVE(&downstream->idle, connection, next);
            downstream->num_idle   -= 1;
            break;
        case downstream_status_down:
            logger_log(downstream->rproxy->err_log, lzlog_info,
                       "%s() downstream proxy:%d -> %s:%d is now UP",
                       __FUNCTION__,
                       connection->sport,
                       downstream->config->host,
                       downstream->config->port);

            downstream->num_down -= 1;

            TAILQ_REMOVE(&downstream->down, connection, next);
            break;
        case downstream_status_nil:
            break;
        default:
            return -1;
    } /* switch */

    /* if the last state was active, we calculate the RTT */
    if (connection->status == downstream_status_active) {
        struct timeval diff;
        struct timeval now;

        evutil_gettimeofday(&now, NULL);
        evutil_timersub(&now, &connection->tv_start, &diff);

        connection->rtt = diff.tv_sec + (diff.tv_usec / 1.0e6);
    }

    TAILQ_INSERT_TAIL(&downstream->idle, connection, next);

    connection->request   = NULL;
    downstream->num_idle += 1;
    connection->status    = downstream_status_idle;

    evtimer_del(connection->retry_timer);

    /* signal the pending request handler that this connection is idle */
    event_active(downstream->rproxy->request_ev, EV_WRITE, 1);

    return 0;
} /* downstream_connection_set_idle */

/**
 * @brief sets a downstream connection down, shutting down sockets and
 *        enabling the retry timer process.
 *
 * @param connection
 *
 * @return 0 on success, -1 on error.
 */
int
downstream_connection_set_down(downstream_c_t * connection) {
    downstream_t * downstream;

    if (connection == NULL) {
        return -1;
    }

    if (!(downstream = connection->parent)) {
        return -1;
    }

    if (connection->status != downstream_status_down) {
        logger_log(downstream->rproxy->err_log, lzlog_info,
                   "%s(): downstream proxy:%d -> %s:%d is down",
                   __FUNCTION__,
                   connection->sport,
                   downstream->config->host,
                   downstream->config->port);
    }

    switch (connection->status) {
        case downstream_status_active:
            TAILQ_REMOVE(&downstream->active, connection, next);
            downstream->num_active -= 1;
            break;
        case downstream_status_idle:
            TAILQ_REMOVE(&downstream->idle, connection, next);
            downstream->num_idle   -= 1;
            break;
        case downstream_status_down:
            downstream->num_down   -= 1;
            TAILQ_REMOVE(&downstream->down, connection, next);
            break;
        case downstream_status_nil:
            break;
        default:
            return -1;
    }

    TAILQ_INSERT_TAIL(&downstream->down, connection, next);

    if (connection->connection) {
        bufferevent_free(connection->connection);
    }

    downstream->num_down  += 1;
    connection->status     = downstream_status_down;
    connection->connection = NULL;
    connection->rtt        = DBL_MAX;
    connection->sport      = 0;

    if (!evtimer_pending(connection->retry_timer, NULL)) {
        evtimer_del(connection->retry_timer);
        evtimer_add(connection->retry_timer, &downstream->config->retry_ival);
    }

    if (connection->bootstrapped == 0) {
        /* this is the first time the connection has been set to down, in most
         * casees this means the program has just started up. In this state, we
         * want to immediately attempt to connect to the downstream without
         * waiting for the retry_timer to expire
         */
        event_active(connection->retry_timer, EV_READ, 1);
        connection->bootstrapped = 1;
    }

    return 0;
}         /* downstream_connection_set_down */

/**
 * @brief sets a downstream connection to active, signifying it is currently
 *        processing another request.
 *
 * @param connection
 *
 * @return 0 on success, -1 on error
 */
int
downstream_connection_set_active(downstream_c_t * connection) {
    downstream_t * downstream;

    if (connection == NULL) {
        return -1;
    }

    if (!(downstream = connection->parent)) {
        return -1;
    }

    switch (connection->status) {
        case downstream_status_active:
            TAILQ_REMOVE(&downstream->active, connection, next);
            downstream->num_active -= 1;
            break;
        case downstream_status_idle:
            TAILQ_REMOVE(&downstream->idle, connection, next);
            downstream->num_idle   -= 1;
            break;
        case downstream_status_down:
            TAILQ_REMOVE(&downstream->down, connection, next);
            downstream->num_down   -= 1;
            break;
        case downstream_status_nil:
            break;
        default:
            return -1;
    }

    TAILQ_INSERT_TAIL(&downstream->active, connection, next);

    downstream->num_active += 1;
    connection->status      = downstream_status_active;

    /* assuming set_active is used just prior to making any type of downstream
     * request, we set our start-time here. This is used to calculate an RTT
     * after the connection has been set back into the idle state
     */
    evutil_gettimeofday(&connection->tv_start, NULL);

    event_del(connection->retry_timer);

    return 0;
}         /* downstream_connection_set_active */

/**
 * @brief search through a list of downstream_t's and attempt to find one that
 *        has a name that matches the string.
 *
 * @param downstreams
 * @param name
 *
 * @return
 */
downstream_t *
downstream_find_by_name(lztq * downstreams, const char * name) {
    lztq_elem * ds_elem;
    lztq_elem * ds_temp;

    if (!downstreams || !name) {
        return NULL;
    }

    for (ds_elem = lztq_first(downstreams); ds_elem != NULL; ds_elem = ds_temp) {
        downstream_t * ds;

        ds = lztq_elem_data(ds_elem);
        assert(ds != NULL);

        if (!strcmp(ds->config->name, name)) {
            return ds;
        }

        ds_temp = lztq_next(ds_elem);
    }

    return NULL;
}

/**
 * @brief attempts to find an idle downstream connection with the most idle connections.
 *
 * @param rule
 *
 * @return a downstream connection, otherwise NULL if no downstreams are avail.
 */
downstream_c_t *
downstream_connection_get_most_idle(rule_t * rule) {
    downstream_t * downstream;
    downstream_t * most_idle;
    lztq_elem    * ds_elem;
    lztq_elem    * ds_elem_save;

    assert(rule != NULL);
    assert(rule->downstreams != NULL);

    most_idle = NULL;

    for (ds_elem = lztq_first(rule->downstreams); ds_elem; ds_elem = ds_elem_save) {
        downstream_t * ds;

        ds_elem_save = lztq_next(ds_elem);

        ds           = lztq_elem_data(ds_elem);
        assert(ds != NULL);

        if (!most_idle) {
            most_idle = ds;
            continue;
        }

        /* check to see if the number of idle connections in the current
         * downstream is higher than the saved downstream.
         */
        if (ds->num_idle > most_idle->num_idle) {
            /* this downstream has more idle connections, swap it over to
             * most_idle to use it.
             */
            most_idle = ds;
        }
    }

    if (most_idle) {
        assert(TAILQ_FIRST(&most_idle->idle) != NULL);

        return TAILQ_FIRST(&most_idle->idle);
    }

    /* no downstream connections are available */
    return NULL;
}

/**
 * @brief Attempts to find an idle downstream connection with the lowest RTT.
 *
 * @param rule
 *
 * @return a downstream connection on success, NULL if no downstreams are
 *         available.
 */
downstream_c_t *
downstream_connection_get_lowest_rtt(rule_t * rule) {
    lztq_elem      * ds_elem;
    lztq_elem      * ds_elem_save;
    downstream_c_t * conn;
    downstream_c_t * save;

    assert(rule != NULL);
    assert(rule->downstreams != NULL);

    save = conn = NULL;

    for (ds_elem = lztq_first(rule->downstreams); ds_elem; ds_elem = ds_elem_save) {
        downstream_t * downstream;

        ds_elem_save = lztq_next(ds_elem);
        downstream   = lztq_elem_data(ds_elem);
        assert(downstream != NULL);

        TAILQ_FOREACH(conn, &downstream->idle, next) {
            if (!save) {
                save = conn;
                continue;
            }

            if (conn->rtt < save->rtt) {
                save = conn;
            }
        }
    }

    return save;
}

/**
 * @brief Attempts to find the first idle downstream connection available.
 *
 * @param rule
 *
 * @return downstream connection, otherwise NULL if none are available.
 */
downstream_c_t *
downstream_connection_get_none(rule_t * rule) {
    lztq_elem * ds_elem;
    lztq_elem * ds_elem_save;

    assert(rule != NULL);
    assert(rule->downstreams != NULL);

    for (ds_elem = lztq_first(rule->downstreams); ds_elem; ds_elem = ds_elem_save) {
        downstream_t * downstream;

        ds_elem_save = lztq_next(ds_elem);
        downstream   = lztq_elem_data(ds_elem);
        assert(downstream != NULL);

        if (downstream->num_idle == 0) {
            continue;
        }

        return TAILQ_FIRST(&downstream->idle);
    }

    return NULL;
}

/**
 * @brief Attempts to find an idle connection using round-robin on configured downstreams.
 *        It should be noted that if only 1 downstream is configured, this will
 *        fallback to using the RTT load-balancing method.
 *
 * @param rule
 *
 * @return a downstream connection, NULL if none are avail.
 */
downstream_c_t *
downstream_connection_get_rr(rule_t * rule) {
    downstream_t   * downstream;
    lztq_elem      * downstream_elem;
    lztq_elem      * last_used_elem;
    downstream_c_t * conn;

    assert(rule != NULL);
    assert(rule->downstreams != NULL);

    if (lztq_size(rule->downstreams) <= 1) {
        return downstream_connection_get_lowest_rtt(rule);
    }

    last_used_elem = rule->last_downstream_used;

    if (!last_used_elem) {
        downstream_elem = lztq_first(rule->downstreams);
        last_used_elem  = lztq_last(rule->downstreams);
    } else {
        downstream_elem = lztq_next(last_used_elem);
    }

    if (!downstream_elem) {
        /* we're at the end of the list, circle back to the first */
        downstream_elem = lztq_first(rule->downstreams);
    }

    conn = NULL;

    do {
        downstream_t * ds;

        if (!downstream_elem) {
            /* we seem to have reached the end of the list, circle back to the
             * first.
             */
            if (!(downstream_elem = lztq_first(rule->downstreams))) {
                return NULL;
            }
        }

        ds = lztq_elem_data(downstream_elem);
        assert(ds != NULL);

        if ((downstream_elem == last_used_elem) && ds->num_idle == 0) {
            /* we have wrapped back to the original, and we don't have any idle
             * connections at all, so return NULL.
             */
            return NULL;
        }

        if (ds->num_idle == 0) {
            /* no idle connections on this downstream, try the next */
            downstream_elem = lztq_next(downstream_elem);
            continue;
        }

        /* If we reached here, we have found a downstream with idle connections,
         * so grab the first downstream_c_t and return it.
         */

        conn = TAILQ_FIRST(&ds->idle);
        assert(conn != NULL);

        rule->last_downstream_used = downstream_elem;
        break;
    } while (1);

    return conn;
}         /* downstream_connection_get_rr */

downstream_c_t *
downstream_connection_get(rule_t * rule) {
    rule_cfg_t * rcfg;

    assert(rule != NULL);

    rcfg = rule->config;
    assert(rcfg != NULL);

    switch (rcfg->lb_method) {
        case lb_method_rtt:
            return downstream_connection_get_lowest_rtt(rule);
        case lb_method_most_idle:
            return downstream_connection_get_most_idle(rule);
        case lb_method_rr:
            return downstream_connection_get_rr(rule);
        case lb_method_none:
            return downstream_connection_get_none(rule);
        case lb_method_rand:
        default:
            logger_log(rule->rproxy->err_log, lzlog_crit,
                       "%s(): unknown lb method %d", __FUNCTION__, rcfg->lb_method);
            break;
    }

    return NULL;
}

void
downstream_connection_writecb(evbev_t * bev, void * arg) {
    downstream_c_t * connection;
    downstream_t   * downstream;
    rproxy_t       * rproxy;
    request_t      * request;

    connection = arg;
    downstream = connection->parent;
    rproxy     = downstream->rproxy;
    request    = connection->request;

    assert(connection != NULL);

#ifdef RPROXY_DEBUG
#ifdef  RPROXY_CRAZY_DEBUG
    printf("writecb: conn=%p, dstream=%p, rproxy=%p, request=%p\n",
           connection, downstream, rproxy, request);
#endif
#endif

    if (!request) {
        downstream_connection_set_down(connection);
        return;
    }

    if (request && request->upstream_request) {
        if (request->hit_highwm) {
            /* our high watermark was hit, but now all data has been written to
             * the downstream, thus we can resume processing
             */
#if RPROXY_DEBUG
            printf("(RESUME UPSTREAM) upstream req status = %d\n",
                   request->upstream_request->status);
#endif

            request->hit_highwm = 0;
            evhtp_request_resume(request->upstream_request);
        }
    }

    return;
}         /* downstream_connection_writecb */

/**
 * @brief called when a downstream has either successfully been connect()'d or
 *        if an error has occured on the socket.
 *
 * @param bev
 * @param events
 * @param arg
 */
void
downstream_connection_eventcb(evbev_t * bev, short events, void * arg) {
    downstream_c_t * connection;
    downstream_t   * downstream;
    rproxy_t       * rproxy;
    int              res;

    assert(arg != NULL);

    connection = arg;
    downstream = connection->parent;
    assert(downstream != NULL);

    rproxy     = downstream->rproxy;
    assert(rproxy != NULL);

    if ((events & BEV_EVENT_CONNECTED)) {
        evutil_socket_t    sock;
        struct sockaddr_in sin;
        int                sinlen;

        sock   = bufferevent_getfd(bev);
        sinlen = sizeof(sin);

        getsockname(sock, (struct sockaddr *)&sin, &sinlen);

        connection->sport = ntohs(sin.sin_port);

        res = downstream_connection_set_idle(connection);
        assert(res >= 0);

        if (rproxy->server_cfg->disable_downstream_nagle == 1) {
            /* disable nagle algorithm for this downstream connection.
             */
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (int[]) { 1 }, sizeof(int));
        }

        return;
    }

    if (connection->request) {
        request_t       * request    = connection->request;
        rule_t          * rule       = request->rule;
        evhtp_request_t * up_request = request->upstream_request;

        request->error = 1;

        if (up_request) {
            evhtp_connection_t * up_conn = evhtp_request_get_connection(up_request);

            if (!request->upstream_err & up_request->finished == 0) {
                evhtp_unset_all_hooks(&up_request->hooks);

                logger_log_request_error(rule->err_log, request,
                                         "%s(): ds req proxy:%d -> %s:%d never completed",
                                         __FUNCTION__,
                                         connection->sport,
                                         downstream->config->host,
                                         downstream->config->port);

                request_free(request);
                evhtp_connection_free(up_conn);
                connection->request = NULL;
            }

            /* XXX: what happens if the upstream request doesn't have an error?
             * Well, the fini callback will be executed, and would result in a
             * double connection_set_down() call. This should be dealt with
             * differently to reduce overhead.
             */
        } else if (request->upstream_bev) {
            bufferevent_free(request->upstream_bev);
            request_free(request);

            connection->request = NULL;
        }
    }

    /* set the downstream connection to a downed state, which in turn
     * will attempt the reconnection process
     */

    if (connection && connection->status != downstream_status_down) {
        logger_log(rproxy->err_log, lzlog_info,
                   "downstream %s socket event (source port=%d) error %d (errno=%s) [ %s%s%s%s%s%s]",
                   connection->parent->config->name,
                   connection->sport, events, strerror(errno),
                   (events & BEV_EVENT_READING) ? "READING " : "",
                   (events & BEV_EVENT_WRITING) ? "WRITING " : "",
                   (events & BEV_EVENT_EOF)     ? "EOF " : "",
                   (events & BEV_EVENT_ERROR) ? "ERROR " : "",
                   (events & BEV_EVENT_TIMEOUT) ? "TIMEOUT " : "",
                   (events & BEV_EVENT_CONNECTED) ? "CONNECTED " : "");
    }


    res = downstream_connection_set_down(connection);
    assert(res >= 0);
}         /* downstream_connection_eventcb */

/**
 * @brief called when data becomes available on a downstream socket and deals
 *        with the data as a response of a request.
 *
 * @param bev
 * @param arg
 */
void
downstream_connection_readcb(evbev_t * bev, void * arg) {
    downstream_c_t * connection;
    downstream_t   * downstream;
    rproxy_t       * rproxy;
    request_t      * request;
    evbuf_t        * evbuf;
    rule_cfg_t     * rule_cfg;
    rule_t         * rule;
    void           * buf;
    size_t           avail;
    size_t           nread;
    struct timeval   diff;
    int              res;


    connection = arg;
    assert(connection != NULL);

    downstream = connection->parent;
    assert(downstream != NULL);

    rproxy     = downstream->rproxy;
    assert(rproxy != NULL);

    if (!(request = connection->request)) {
        downstream_connection_set_down(connection);
        return;
    }

    rule     = request->rule;
    assert(rule != NULL);

    rule_cfg = rule->config;
    assert(rule_cfg != NULL);

    evbuf    = bufferevent_get_input(bev);
    assert(evbuf != NULL);

    if (rproxy->server_cfg->high_watermark > 0) {
        /* if we have a high-watermark configuration for upstream connections
         * set, and the upstreams output buffer grows over this size, we must
         * disable the read side of the downstream connection until that buffer
         * is fully written.
         *
         * when the buffer has been fully written, the connection hook
         * upstream_on_write will enable the read side again.
         */
        if (evbuffer_get_length(bufferevent_get_output(request->upstream_bev)) >= rproxy->server_cfg->high_watermark) {
            request->hit_upstream_highwm = 1;
            bufferevent_disable(connection->connection, EV_READ);
        }
    }

    if (rule_cfg->passthrough == true) {
        /* passthrough enabled, just write the data from the downstream back to
         * the upstream.
         */

        /* write the data that came from the downstream to the upstream */
        bufferevent_write_buffer(request->upstream_bev, bufferevent_get_input(bev));

        return;
    }

    avail = evbuffer_get_length(evbuf);
    buf   = evbuffer_pullup(evbuf, avail);

    /* set our reading bit, this will inform any intermediary error type
     * callbacks to not free any resources while the parsing is being executed
     */
    request->reading = 1;

    nread = htparser_run(request->parser, &proxy_parser_hooks,
                         (const char *)buf, avail);

    /* unset our reading bit since we are no longer in our parsing loop */
    request->reading = 0;

    evbuffer_drain(evbuf, -1);

    if (nread != avail) {
        /* the request processing was aborted at some point, so
         * we mark it as an error
         */
        logger_log(rule->err_log, lzlog_err,
                   "%s() response parsing error: %s",
                   __FUNCTION__, htparser_get_strerror(request->parser));
        request->error = 1;
    }

    assert(request->upstream_request != NULL);

    if (request->done && !REQUEST_HAS_ERROR(request)) {
        /* downstream response has been fully processed and marked
         * as completed with no error conditions. End the streaming
         * reply to the upstream and log the request
         *
         * This will eventually call the upstream_fini() function after all data
         * has been written to the upstream.
         */

        logger_log_request(rule->req_log, request);

        return evhtp_send_reply_end(request->upstream_request);
    }

    if (REQUEST_HAS_ERROR(request)) {
        /* deal with whatever type of error happened */
        evhtp_connection_t * c =
            evhtp_request_get_connection(request->upstream_request);

        if (request->upstream_err) {
            /* upstream_error() was triggered, which means the upstream encountered
             * a socket error. If the request is marked as done, we can keep the
             * downstream connection open, otherwise we must shut it down.
             *
             * since upstream_error() unsets all the hooks associated with this
             * request, it should never call upstream_fini, so we can safely free
             * our resources and set our downstream connection status however we want.
             */
            if (request->done) {
                downstream_connection_set_idle(connection);
            } else {
                downstream_connection_set_down(connection);
            }
        } else if (request->error) {
            /* our downstream parsing encountered an error, if the request has been
             * marked as done, we can send the final response, otherwise we send a
             * 503 type error.
             */
            evhtp_unset_all_hooks(&request->upstream_request->hooks);

            if (request->done) {
                logger_log_request(rule->req_log, request);

                evhtp_send_reply_end(request->upstream_request);
            } else {
                evhtp_send_reply(request->upstream_request, 200);
                downstream_connection_set_down(connection);
            }
        }

        /* free up our request */
        request_free(connection->request);
        connection->request = NULL;
    }

    /* if we get to here, we are not done with downstream -> upstream IO */
}         /* downstream_connection_readcb */

/**
 * @brief called when the retry event timer has been triggered and attempts to
 *        reconnect to a downstream in a down state.
 *
 * @param sock
 * @param which
 * @param arg
 */
void
downstream_connection_retry(int sock, short which, void * arg) {
    downstream_c_t * connection;
    downstream_t   * downstream;
    rproxy_t       * rproxy;

    assert(arg != NULL);

    connection = arg;
    downstream = connection->parent;
    assert(downstream != NULL);

    rproxy     = downstream->rproxy;
    assert(rproxy != NULL);

    if (connection->connection) {
        bufferevent_free(connection->connection);
    }

    connection->connection = bufferevent_socket_new(downstream->evbase, -1,
                                                    BEV_OPT_CLOSE_ON_FREE);

    assert(connection->connection != NULL);

    bufferevent_setcb(connection->connection,
                      downstream_connection_readcb,
                      downstream_connection_writecb,
                      downstream_connection_eventcb, connection);

    /* once the socket has connected (or errored), the
     * downstream_connection_eventcb function is called.
     */
    {
        struct sockaddr_in sin;

        sin.sin_family      = AF_INET;
        sin.sin_addr.s_addr = inet_addr(downstream->config->host);
        sin.sin_port        = htons(downstream->config->port);


        bufferevent_socket_connect(connection->connection,
                                   (struct sockaddr *)&sin, sizeof(sin));
    }

    {
        /* if configured, apply our read/write timeouts on the downstream
         * connection.
         */
        struct timeval * tv_read  = NULL;
        struct timeval * tv_write = NULL;

        if (downstream->config->read_timeout.tv_sec ||
            downstream->config->read_timeout.tv_usec) {
            tv_read = &downstream->config->read_timeout;
        }

        if (downstream->config->write_timeout.tv_sec ||
            downstream->config->write_timeout.tv_usec) {
            tv_write = &downstream->config->write_timeout;
        }

        if (tv_read || tv_write) {
            bufferevent_set_timeouts(connection->connection, tv_read, tv_write);
        }
    }

    bufferevent_enable(connection->connection, EV_READ | EV_WRITE);
}         /* downstream_connection_retry */

/**
 * @brief initializes downstream connections
 *
 * Creates N downstream connection structures based on
 * the downstream_cfg's connections variable. Each
 * downstream_connection is initially set to down using
 * downstream_connection_set_down(). That function will
 * do the work of actually making a connect() attempt.
 *
 * @param evbase
 * @param downstream
 *
 * @return 0 on success, -1 on error
 */
int
downstream_connection_init(evbase_t * evbase, downstream_t * downstream) {
    int i;

    if (evbase == NULL || downstream == NULL) {
        return -1;
    }

    downstream->evbase = evbase;

    for (i = 0; i < downstream->config->n_connections; i++) {
        downstream_c_t * connection;
        int              res;

        if (!(connection = downstream_connection_new(evbase, downstream))) {
            logger_log(downstream->rproxy->err_log, lzlog_crit,
                       "%s(): could not create ds conn (%s)",
                       __FUNCTION__, strerror(errno));
            exit(EXIT_FAILURE);
        }

        res = downstream_connection_set_down(connection);
        assert(res >= 0);
    }

    return 0;
}

/**
 * @brief frees a downstream connection resource
 *
 * @param connection
 */
void
downstream_connection_free(downstream_c_t * connection) {
    if (connection == NULL) {
        return;
    }

    if (connection->retry_timer) {
        event_free(connection->retry_timer);
    }

    if (connection->connection) {
        bufferevent_free(connection->connection);
    }

    free(connection);
}

/**
 * @brief creates a new downstream connection using downstream_t information
 *
 * Initializes a downstream connection along with creating a retry event timer.
 *
 * @param evbase
 * @param downstream the parent downstream_t instance
 *
 * @return downstream_c_t
 */
downstream_c_t *
downstream_connection_new(evbase_t * evbase, downstream_t * downstream) {
    downstream_c_t * connection;

    if (evbase == NULL) {
        return NULL;
    }

    if (!(connection = calloc(sizeof(downstream_c_t), 1))) {
        return NULL;
    }

    connection->parent       = downstream;
    connection->rtt          = DBL_MAX;
    connection->status       = downstream_status_nil;
    connection->bootstrapped = 0;

    connection->retry_timer  = evtimer_new(evbase, downstream_connection_retry, connection);

    return connection;
}

/**
 * @brief frees all downstream connections and the parent
 *
 * @param downstream
 */
void
downstream_free(void * arg) {
    downstream_t   * downstream = arg;
    downstream_c_t * conn;
    downstream_c_t * save;

    if (downstream == NULL) {
        return;
    }

    /* free all of the active/idle/down connections */
    for (conn = TAILQ_FIRST(&downstream->active); conn; conn = save) {
        save = TAILQ_NEXT(conn, next);

        downstream_connection_free(conn);
    }

    for (conn = TAILQ_FIRST(&downstream->idle); conn; conn = save) {
        save = TAILQ_NEXT(conn, next);

        downstream_connection_free(conn);
    }

    for (conn = TAILQ_FIRST(&downstream->down); conn; conn = save) {
        save = TAILQ_NEXT(conn, next);

        downstream_connection_free(conn);
    }

    free(downstream);
}

/**
 * @brief allocates a downstream_t parent and initializes the downstream
 *        connection queues.
 *
 * @param rproxy
 * @param cfg
 *
 * @return downstream_t on success, NULL on error
 */
downstream_t *
downstream_new(rproxy_t * rproxy, downstream_cfg_t * cfg) {
    downstream_t * downstream;

    assert(rproxy != NULL);
    assert(cfg != NULL);

    if (!(downstream = calloc(sizeof(downstream_t), 1))) {
        return NULL;
    }

    downstream->config = cfg;
    downstream->rproxy = rproxy;

    TAILQ_INIT(&downstream->active);
    TAILQ_INIT(&downstream->idle);
    TAILQ_INIT(&downstream->down);

    return downstream;
}

