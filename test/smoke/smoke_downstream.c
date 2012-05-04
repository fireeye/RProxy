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



#include <evhtp.h>
#include <event2/buffer.h>

struct event_base * evbase;
struct event      * timer_event;
int                 slow_data_bytes;

static void
head_cb(evhtp_request_t * req, void * arg) {
    evhtp_send_reply(req, EVHTP_RES_OK);
}

static void
simple_cb(evhtp_request_t * req, void * arg) {
    evhtp_send_reply(req, EVHTP_RES_OK);
}

static void
busy_cb(evhtp_request_t * req, void * arg) {
    evhtp_send_reply(req, EVHTP_RES_SERVUNAVAIL);
}

static void
nettirwer_cb(evhtp_request_t * req, void * arg) {
    evhtp_send_reply(req, EVHTP_RES_OK);
}

static void
data_cb(evhtp_request_t * req, void * arg) {
    evbuf_t * buf;

    buf = evbuffer_new();

    evhtp_send_reply_chunk_start(req, EVHTP_RES_OK);

    evbuffer_add(buf, "SUCCESS", strlen("SUCCESS"));
    evhtp_send_reply_chunk(req, buf);

    evbuffer_drain(buf, -1);

    evhtp_send_reply_chunk_end(req);
    evbuffer_free(buf);
}

static void
send_reply_header(evhtp_request_t * req, const char * header) {
    evbuf_t   * buf   = evbuffer_new();
    const char* found = evhtp_header_find(req->headers_in, header);

    evhtp_send_reply_chunk_start(req, EVHTP_RES_OK);
    evbuffer_add(buf, found, strlen(found));
    evhtp_send_reply_chunk(req, buf);

    evbuffer_drain(buf, -1);

    evhtp_send_reply_chunk_end(req);
    evbuffer_free(buf);
}

static void
forwarded_cb(evhtp_request_t * req, void * arg) {
    send_reply_header(req, "x-forwarded-for");
}

static void
ssl_subject_cb(evhtp_request_t * req, void * arg) {
    send_reply_header(req, "x-ssl-subject");
}

static void
ssl_issuer_cb(evhtp_request_t * req, void * arg) {
    send_reply_header(req, "x-ssl-issuer");
}

static void
ssl_notbefore_cb(evhtp_request_t * req, void * arg) {
    send_reply_header(req, "x-ssl-notbefore");
}

static void
ssl_notafter_cb(evhtp_request_t * req, void * arg) {
    send_reply_header(req, "x-ssl-notafter");
}

static void
ssl_serial_cb(evhtp_request_t * req, void * arg) {
    send_reply_header(req, "x-ssl-serial");
}

static void
ssl_cipher_cb(evhtp_request_t * req, void * arg) {
    send_reply_header(req, "x-ssl-cipher");
}

static void
ssl_certificate_cb(evhtp_request_t * req, void * arg) {
    send_reply_header(req, "x-ssl-certificate");
}

static void
useragent_cb(evhtp_request_t * req, void * arg) {
    send_reply_header(req, "user-agent");
}

static void
host_cb(evhtp_request_t * req, void * arg) {
    send_reply_header(req, "host");
}

static void
accept_cb(evhtp_request_t * req, void * arg) {
    send_reply_header(req, "accept");
}

static void
extension_cb(evhtp_request_t * req, void * arg) {
    send_reply_header(req, "x-ssl-extension");
}

static void
slowdata_timer_cb(evutil_socket_t fd, short event, void * arg) {
    evhtp_request_t * req = (evhtp_request_t *)arg;

    /* Write an additional 1 byte */
    evbuf_t* buf          = evbuffer_new();

    evbuffer_add(buf, "0", 1);
    evhtp_send_reply_chunk(req, buf);
    evbuffer_drain(buf, -1);
    ++slow_data_bytes;

    if (slow_data_bytes == 10) {
        /* Reached our limit, close the reply */
        evhtp_send_reply_chunk_end(req);
        evtimer_del(timer_event);
    } else {
        /* Keep going */
        struct timeval tv;
        tv.tv_sec  = 0;
        tv.tv_usec = 500000;
        evtimer_add(timer_event, &tv);
    }

    evbuffer_free(buf);
}

static void
slowdata_cb(evhtp_request_t * req, void * arg) {
    /* Init our slow data vars */
    slow_data_bytes = 0;

    /* Start the reply */
    evhtp_send_reply_chunk_start(req, EVHTP_RES_OK);

    /* Create a timer for this request */
    timer_event = evtimer_new(evbase, slowdata_timer_cb, req);

    /* Set the timer and exit. */
    struct timeval tv;
    tv.tv_sec   = 0;
    tv.tv_usec  = 500000;
    evtimer_add(timer_event, &tv);
}

static void
send_chunk(evhtp_request_t * req, const char* data, const char* hdrfmt, size_t len) {
    evbuf_t * buf = evbuffer_new();
    evbuf_t * output;

    /* Add the data to the output */
    evbuffer_add(buf, data, strlen(data));
    output = bufferevent_get_output(req->conn->bev);
    evbuffer_add_printf(output, hdrfmt, len);

    /* Send the buffer */
    evhtp_send_reply_body(req, buf);
    evbuffer_add(output, "\r\n", 2);

    /* Drain the buffer and free it */
    evbuffer_drain(buf, -1);
    evbuffer_free(buf);
}

static void
badchunk_length_cb(evhtp_request_t * req, void * arg) {
    evbuf_t * buf = evbuffer_new();
    evbuf_t * output;

    /* Start the chunk */
    evhtp_send_reply_chunk_start(req, EVHTP_RES_OK);

    /* Send some data */
    send_chunk(req, "SUCCESS", "%d\r\n", strlen("SUCCESS"));

    /* Close the chunk */
    evhtp_send_reply_chunk_end(req);
    evbuffer_free(buf);
}

static void
badchunk_transfer_cb(evhtp_request_t * req, void * arg) {
    /* Start the chunk */
    evhtp_send_reply_chunk_start(req, EVHTP_RES_OK);

    /* Send a few chunks with a bogus GET in the middle */
    send_chunk(req, "DATA", "%d\r\n", strlen("DATA"));
    send_chunk(req, "GET /index.html HTTP/1.1", "", 0);
    send_chunk(req, "MOREDATA", "%d\r\n", strlen("DATA"));

    /* Flush the connection */
    bufferevent_flush(req->conn->bev, EV_WRITE, BEV_FLUSH);

    /* Close the chunk */
    evhtp_send_reply_chunk_end(req);
}

static void
rr_cb(evhtp_request_t * req, void * arg) {
    evbuffer_add(req->buffer_out, arg, strlen((const char *)arg));
    evhtp_send_reply(req, EVHTP_RES_OK);
}

int
main(int argc, char ** argv) {
    evhtp_t * htp  = NULL;
    evhtp_t * htp2 = NULL;

    evbase          = event_base_new();
    htp             = evhtp_new(evbase, NULL);
    htp2            = evhtp_new(evbase, NULL);

    slow_data_bytes = 0;

    evhtp_set_cb(htp, "/", head_cb, NULL);
    evhtp_set_cb(htp, "/simple/", simple_cb, NULL);
    evhtp_set_cb(htp, "/busy/", busy_cb, NULL);
    evhtp_set_cb(htp, "/nettirwer/", nettirwer_cb, NULL);
    evhtp_set_cb(htp, "/data/", data_cb, NULL);
    evhtp_set_cb(htp, "/forwarded/", forwarded_cb, NULL);
    evhtp_set_cb(htp, "/subject/", ssl_subject_cb, NULL);
    evhtp_set_cb(htp, "/issuer/", ssl_issuer_cb, NULL);
    evhtp_set_cb(htp, "/notbefore/", ssl_notbefore_cb, NULL);
    evhtp_set_cb(htp, "/notafter/", ssl_notafter_cb, NULL);
    evhtp_set_cb(htp, "/serial/", ssl_serial_cb, NULL);
    evhtp_set_cb(htp, "/cipher/", ssl_cipher_cb, NULL);
    evhtp_set_cb(htp, "/certificate/", ssl_certificate_cb, NULL);
    evhtp_set_cb(htp, "/useragent/", useragent_cb, NULL);
    evhtp_set_cb(htp, "/host/", host_cb, NULL);
    evhtp_set_cb(htp, "/accept/", accept_cb, NULL);
    evhtp_set_cb(htp, "/extension/", extension_cb, NULL);
    evhtp_set_cb(htp, "/slowdata/", slowdata_cb, NULL);
    evhtp_set_cb(htp, "/badchunklength/", badchunk_length_cb, NULL);
    evhtp_set_cb(htp, "/badchunktransfer/", badchunk_transfer_cb, NULL);

    evhtp_set_cb(htp, "/test_rr/", rr_cb, "one\n");
    evhtp_set_cb(htp2, "/test_rr/", rr_cb, "two\n");

    if (evhtp_bind_socket(htp, "0.0.0.0", 8090, 128) < 0) {
        fprintf(stderr, "Could not bind socket: %s\n", strerror(errno));
        exit(-1);
    }

    if (evhtp_bind_socket(htp2, "0.0.0.0", 8091, 128) < 0) {
        fprintf(stderr, "Couldnot bind to socket: %s\n", strerror(errno));
        exit(-1);
    }

    event_base_loop(evbase, 0);

    return 0;
} /* main */

