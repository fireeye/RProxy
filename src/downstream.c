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
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] upstream_request == NULL");
        request->error = 1;
        return -1;
    }

    if (!(key_s = malloc(len + 1))) {
        logger_log_request_error(request->rproxy->logger, request,
                                 "[CRIT] Could not malloc: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    key_s[len]    = '\0';
    memcpy(key_s, data, len);

    hdr           = evhtp_header_key_add(upstream_r->headers_out, key_s, 0);
    hdr->k_heaped = 1;

    return 0;
}

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
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] header_val upstream_r == NULL");
        request->error = 1;
        return -1;
    }

    if (!(val_s = calloc(len + 1, 1))) {
        logger_log_request_error(request->rproxy->logger, request,
                                 "[CRIT] Could not malloc: %s", strerror(errno));
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
    evhtp_request_t * upstream_r;

    assert(p != NULL);

    request = htparser_get_userdata(p);
    assert(request != NULL);

    rproxy  = request->rproxy;
    assert(rproxy != NULL);
    assert(request->pending != 1);

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    if (!(upstream_r = request->upstream_request)) {
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] parser_headers_complete() upstream_r == NULL");
        request->error = 1;
        return -1;
    }

    /* downstream headers have been fully parsed, start streaming
     * further data to the upstream
     */
    evhtp_send_reply_start(upstream_r, htparser_get_status(p));

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
static int
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
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] parser_new_chunk() upstream_r == NULL");
        request->error = 1;
        return -1;
    }

    if (!(buf = evbuffer_new())) {
        logger_log_request_error(request->rproxy->logger, request,
                                 "[CRIT] Could not malloc: %s", strerror(errno));
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
static int
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
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] parser_chunk_complete() upstream_r == NULL");
        request->error = 1;
        return -1;
    }

    if (!(buf = evbuffer_new())) {
        logger_log_request_error(request->rproxy->logger, request,
                                 "[CRIT] Could not malloc: %s", strerror(errno));
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
static int
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
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] chunks_complete() upstream_r == NULL");
        request->error = 1;
        return -1;
    }

    if (!(buf = evbuffer_new())) {
        logger_log_error(request->rproxy->logger,
                         "[CRIT] Could not malloc: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    evbuffer_add(buf, "0\r\n\r\n", 5);
    evhtp_send_reply_body(upstream_r, buf);
    evbuffer_free(buf);

    if (REQUEST_HAS_ERROR(request)) {
        return -1;
    }

    return 0;
}

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
static int
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
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] parser_body() upstream_r == NULL");
        request->error = 1;
        return -1;
    }

    if (!(buf = evbuffer_new())) {
        logger_log_request_error(request->rproxy->logger, request,
                                 "[CRIT] Could not malloc: %s", strerror(errno));
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
        logger_log_request_error(rproxy->logger, request,
                                 "[ERROR] proxy_parser_fini() upstream_r == NULL");
        request->error = 1;
        return -1;
    }

    /* the downstream response has no body data, so we mark the
     * request as done. Otherwise we must wait for the http parser
     * to call our read body callbacks (proxy_parser_*_chunk*() /
     * proxy_parser_body())
     */
    if (!htparser_get_content_length(request->parser)) {
        request->done = 1;
    }

    return 0;
}

static htparse_hooks proxy_parser_hooks = {
    .on_msg_begin       = NULL,
    .method             = NULL,
    .scheme             = NULL,
    .host               = NULL,
    .port               = NULL,
    .path               = NULL,
    .args               = NULL,
    .uri                = NULL,
    .on_hdrs_begin      = NULL,
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
            logger_log_error(downstream->rproxy->logger,
                             "[INFO] Downstream %s:%d is now up",
                             downstream->config->host, downstream->config->port);
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
        logger_log_error(downstream->rproxy->logger,
                         "[ERROR] Downstream proxy:%d -> %s:%d is down",
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

    evtimer_del(connection->retry_timer);
    evtimer_add(connection->retry_timer, &downstream->config->retry_ival);

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
} /* downstream_connection_set_down */

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
} /* downstream_connection_set_active */

/**
 * @brief attempts to find an idle downstream connection with the most idle connections.
 *
 * @param rproxy
 *
 * @return a downstream connection, otherwise NULL if no downstreams are avail.
 */
downstream_c_t *
downstream_connection_get_most_idle(rproxy_t * rproxy) {
    downstream_t * downstream;
    downstream_t * most_idle;

    most_idle = NULL;

    /* iterate over each downstream_t, check the num_idle variable on each one
     * until the largest number is found
     */
    TAILQ_FOREACH(downstream, &rproxy->downstreams, next) {
        if (most_idle == NULL) {
            most_idle = downstream;
            continue;
        }

        /* check to see if the number of idle connections in the current
         * downstream is higher than the saved downstream
         */
        if (downstream->num_idle > most_idle->num_idle) {
            /* this downstream has more idle connections, swap over most_idle to
             * use it
             */
            most_idle = downstream;
        }
    }

    if (most_idle) {
        assert(TAILQ_FIRST(&most_idle->idle) != NULL);

        /* return the first downstream connection in the downstream parent */
        return TAILQ_FIRST(&most_idle->idle);
    }

    /* no downstream connections are available */
    return NULL;
}

/**
 * @brief Attempts to find an idle downstream connection with the lowest RTT.
 *
 * @param rproxy
 *
 * @return a downstream connection on success, NULL if no downstreams are
 *         available.
 */
downstream_c_t *
downstream_connection_get_lowest_rtt(rproxy_t * rproxy) {
    downstream_c_t * conn;
    downstream_c_t * save;
    downstream_t   * downstream;

    /* iterate through each downstream and their idle connection
     * children and return the connection with the lowest RTT
     */

    save = NULL;

    TAILQ_FOREACH(downstream, &rproxy->downstreams, next) {
        TAILQ_FOREACH(conn, &downstream->idle, next) {
            if (save == NULL) {
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
 * @param rproxy
 *
 * @return downstream connection, otherwise NULL if none are available.
 */
downstream_c_t *
downstream_connection_get_none(rproxy_t * rproxy) {
    downstream_t * downstream;

    /* iterate through each downstream and return the first available idle connection */
    TAILQ_FOREACH(downstream, &rproxy->downstreams, next) {
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
 * @param rproxy
 *
 * @return a downstream connection, NULL if none are avail.
 */
downstream_c_t *
downstream_connection_get_rr(rproxy_t * rproxy) {
    downstream_t   * last_used_downstream;
    downstream_t   * downstream;
    downstream_c_t * conn;

    assert(rproxy != NULL);

    if (TAILQ_FIRST(&rproxy->downstreams) == TAILQ_LAST(&rproxy->downstreams, downstream_q)) {
        /* only one downstream is configured, fall-back to RTT method */
        return downstream_connection_get_lowest_rtt(rproxy);
    }

    last_used_downstream = rproxy->last_downstream_used;

    if (!last_used_downstream) {
        downstream = TAILQ_FIRST(&rproxy->downstreams);
    } else {
        downstream = TAILQ_NEXT(last_used_downstream, next);
    }

    if (!downstream) {
        /* we're at the end of the list, circle back to the first */
        downstream = TAILQ_FIRST(&rproxy->downstreams);
    }

    conn = NULL;

    do {
        if (!downstream) {
            /* we have reached the end of the list, circle back to the first */
            downstream = TAILQ_FIRST(&rproxy->downstreams);
        }

        if ((downstream == last_used_downstream) && downstream->num_idle == 0) {
            /* we have wrapped back to the original, and we don't have any idle
             * connections here either, so we return NULL
             */
            return NULL;
        }

        if (downstream->num_idle == 0) {
            /* no idle connections for this downstream, try the next */
            downstream = TAILQ_NEXT(downstream, next);
            continue;
        }

        /* found a downstream with idle connections, so grab the first
         * connection and return
         */

        conn = TAILQ_FIRST(&downstream->idle);
        assert(conn != NULL);

        /* update the last used downstream pointer */
        rproxy->last_downstream_used = downstream;
        break;
    } while (1);

    return conn;
} /* downstream_connection_get_rr */

downstream_c_t *
downstream_connection_get(rproxy_t * rproxy) {
    server_cfg_t * scfg;

    assert(rproxy != NULL);
    assert(rproxy->server_cfg != NULL);

    scfg = rproxy->server_cfg;

    switch (scfg->lbalance_method) {
        case lb_method_rtt:
            return downstream_connection_get_lowest_rtt(rproxy);
        case lb_method_most_idle:
            return downstream_connection_get_most_idle(rproxy);
        case lb_method_rr:
            return downstream_connection_get_rr(rproxy);
        case lb_method_none:
            return downstream_connection_get_none(rproxy);
        case lb_method_rand:
        default:
            logger_log_error(rproxy->logger, "[CRIT] Unknown loadbalance method %d", scfg->lbalance_method);
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
}

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
        return;
    }

    if (connection->request) {
        request_t       * request    = connection->request;
        evhtp_request_t * up_request = request->upstream_request;

        request->error = 1;

        if (up_request) {
            evhtp_connection_t * up_conn = evhtp_request_get_connection(up_request);

            if (!request->upstream_err) {
                evhtp_unset_all_hooks(&up_request->hooks);

                logger_log_request_error(rproxy->logger, request,
                                         "[WARN] Downstream request proxy:%d -> %s:%d never completed",
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
        }
    }

    /* set the downstream connection to a downed state, which in turn
     * will attempt the reconnection process
     */

    if (connection && connection->status != downstream_status_down) {
        logger_log_error(rproxy->logger, "[CRIT] downstream socket event (source port=%d) error %d [ %s%s%s%s%s%s]",
                         connection->sport, events,
                         (events & BEV_EVENT_READING) ? "READING " : "",
                         (events & BEV_EVENT_WRITING) ? "WRITING " : "",
                         (events & BEV_EVENT_EOF)     ? "EOF " : "",
                         (events & BEV_EVENT_ERROR) ? "ERROR " : "",
                         (events & BEV_EVENT_TIMEOUT) ? "TIMEOUT " : "",
                         (events & BEV_EVENT_CONNECTED) ? "CONNECTED " : "");
    }


    res = downstream_connection_set_down(connection);
    assert(res >= 0);
} /* downstream_connection_eventcb */

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
    void           * buf;
    size_t           avail;
    size_t           nread;
    struct timeval   diff;
    int              res;

    assert(arg != NULL);

    connection = arg;
    downstream = connection->parent;
    assert(downstream != NULL);

    rproxy     = downstream->rproxy;
    assert(rproxy != NULL);

    if (!(request = connection->request)) {
        /* XXX: technically we should never see this, deal with this as an error maybe? */

        /* we were signaled to read from the downstream, yet no request
         * has been associated with this connection, so we drain the input
         * buffers and return immediately.
         */
        evbuffer_drain(bufferevent_get_input(bev), -1);
        evbuffer_drain(bufferevent_get_output(bev), -1);

        downstream_connection_set_down(connection);
        return;
    }

    evbuf = bufferevent_get_input(bev);
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

        logger_log_request(rproxy->logger, request);

        return evhtp_send_reply_end(request->upstream_request);
    }

    if (REQUEST_HAS_ERROR(request)) {
        /* deal with whatever type of error happened */

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
                logger_log_request(rproxy->logger, request);
                evhtp_send_reply_end(request->upstream_request);
            } else {
                downstream_connection_set_down(connection);
            }
        }

        /* free up our request */
        request_free(request);
    }

    /* if we get to here, we are not done with downstream -> upstream IO */
} /* downstream_connection_readcb */

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
    downstream_c_t   * connection;
    downstream_t     * downstream;
    rproxy_t         * rproxy;
    struct sockaddr_in sin;

    assert(arg != NULL);

    connection = arg;
    downstream = connection->parent;
    assert(downstream != NULL);

    rproxy     = downstream->rproxy;
    assert(rproxy != NULL);

    if (connection->connection) {
        bufferevent_free(connection->connection);
    }


    sin.sin_family         = AF_INET;
    sin.sin_addr.s_addr    = inet_addr(downstream->config->host);
    sin.sin_port           = htons(downstream->config->port);

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
    bufferevent_socket_connect(connection->connection,
                               (struct sockaddr *)&sin, sizeof(sin));

    {
        /* if configured, apply our read/write timeouts on the downstream
         * connection.
         */
        int            s_read  = 0;
        int            s_write = 0;
        struct timeval r_tv    = { 0 };
        struct timeval w_tv    = { 0 };

        if (downstream->config->read_timeout) {
            r_tv.tv_sec = downstream->config->read_timeout;
            s_read      = 1;
        }

        if (downstream->config->write_timeout) {
            w_tv.tv_sec = downstream->config->write_timeout;
            s_write     = 1;
        }

        if (s_read || s_write) {
            bufferevent_set_timeouts(connection->connection,
                                     s_read ? &r_tv : NULL,
                                     s_write ? &w_tv : NULL);
        }
    }

    bufferevent_enable(connection->connection, EV_READ | EV_WRITE);
} /* downstream_connection_retry */

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

    for (i = 0; i < downstream->config->connections; i++) {
        downstream_c_t * connection;
        int              res;

        if (!(connection = downstream_connection_new(evbase, downstream))) {
            logger_log_error(downstream->rproxy->logger,
                             "[CRIT] Could not create new downstream connection! %s",
                             strerror(errno));
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
downstream_free(downstream_t * downstream) {
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

