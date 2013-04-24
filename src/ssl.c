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
#include <sys/stat.h>

#include "rproxy.h"

#ifdef NO_STRNLEN
static size_t
strnlen(const char * s, size_t maxlen) {
    const char * e;
    size_t       n;

    for (e = s, n = 0; *e && n < maxlen; e++, n++) {
        ;
    }

    return n;
}

#endif /* ifdef NO_STRNLEN */

#ifdef NO_STRNDUP
static char *
strndup(const char * s, size_t n) {
    size_t len = strnlen(s, n);
    char * ret;

    if (len < n) {
        return strdup(s);
    }

    ret    = malloc(n + 1);
    ret[n] = '\0';

    strncpy(ret, s, n);
    return ret;
}

#endif /* ifdef NO_STRNDUP */

unsigned char *
ssl_subject_tostr(evhtp_ssl_t * ssl) {
    unsigned char * subj_str;
    char          * p;
    X509          * cert;
    X509_NAME     * name;

    if (!ssl) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    if (!(name = X509_get_subject_name(cert))) {
        X509_free(cert);
        return NULL;
    }

    if (!(p = X509_NAME_oneline(name, NULL, 0))) {
        X509_free(cert);
        return NULL;
    }

    subj_str = strdup(p);

    OPENSSL_free(p);
    X509_free(cert);

    return subj_str;
}

unsigned char *
ssl_issuer_tostr(evhtp_ssl_t * ssl) {
    X509          * cert;
    X509_NAME     * name;
    char          * p;
    unsigned char * issr_str;

    if (!ssl) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    if (!(name = X509_get_issuer_name(cert))) {
        X509_free(cert);
        return NULL;
    }

    if (!(p = X509_NAME_oneline(name, NULL, 0))) {
        X509_free(cert);
        return NULL;
    }

    issr_str = strdup(p);

    OPENSSL_free(p);
    X509_free(cert);

    return issr_str;
}

unsigned char *
ssl_notbefore_tostr(evhtp_ssl_t * ssl) {
    BIO           * bio;
    X509          * cert;
    ASN1_TIME     * time;
    size_t          len;
    unsigned char * time_str;

    if (!ssl) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    if (!(time = X509_get_notBefore(cert))) {
        X509_free(cert);
        return NULL;
    }

    if (!(bio = BIO_new(BIO_s_mem()))) {
        X509_free(cert);
        return NULL;
    }

    if (!ASN1_TIME_print(bio, time)) {
        BIO_free(bio);
        X509_free(cert);
        return NULL;
    }

    if ((len = BIO_pending(bio)) == 0) {
        BIO_free(bio);
        X509_free(cert);
        return NULL;
    }

    if (!(time_str = calloc(len + 1, 1))) {
        return NULL;
    }

    BIO_read(bio, time_str, len);

    BIO_free(bio);
    X509_free(cert);

    return time_str;
} /* ssl_notbefore_tostr */

unsigned char *
ssl_notafter_tostr(evhtp_ssl_t * ssl) {
    BIO           * bio;
    X509          * cert;
    ASN1_TIME     * time;
    size_t          len;
    unsigned char * time_str;

    if (!ssl) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    if (!(time = X509_get_notAfter(cert))) {
        X509_free(cert);
        return NULL;
    }

    if (!(bio = BIO_new(BIO_s_mem()))) {
        X509_free(cert);
        return NULL;
    }

    if (!ASN1_TIME_print(bio, time)) {
        BIO_free(bio);
        X509_free(cert);
        return NULL;
    }

    if ((len = BIO_pending(bio)) == 0) {
        BIO_free(bio);
        X509_free(cert);
        return NULL;
    }

    if (!(time_str = calloc(len + 1, 1))) {
        return NULL;
    }

    BIO_read(bio, time_str, len);

    BIO_free(bio);
    X509_free(cert);

    return time_str;
} /* ssl_notafter_tostr */

unsigned char *
ssl_sha1_tostr(evhtp_ssl_t * ssl) {
    EVP_MD       * md_alg;
    X509         * cert;
    unsigned int   n;
    unsigned char  md[EVP_MAX_MD_SIZE];
    unsigned char*  buf = NULL;
    size_t         offset;
    size_t         nsz;
    int            sz;
    int            i;

    if (!ssl) {
        return NULL;
    }

    md_alg = EVP_sha1();

    if (!md_alg) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    n   = 0;
    if (!X509_digest(cert, md_alg, md, &n)) {
        return NULL;
    }

    nsz = 3 * n + 1;
    buf = (unsigned char *)calloc(nsz, 1);
    if (buf) {
        offset = 0;
        for (i = 0; i < n; i++) {
            sz      = snprintf(buf + offset, nsz - offset, "%02X%c", md[i], (i + 1 == n) ? 0 : ':');
            offset += sz;

            if (sz < 0 || offset >= nsz) {
                free(buf);
                buf = NULL;
                break;
            }
        }
    }

    X509_free(cert);

    return buf;
} /* ssl_sha1 */

unsigned char *
ssl_serial_tostr(evhtp_ssl_t * ssl) {
    BIO           * bio;
    X509          * cert;
    size_t          len;
    unsigned char * ser_str;

    if (!ssl) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    if (!(bio = BIO_new(BIO_s_mem()))) {
        X509_free(cert);
        return NULL;
    }

    i2a_ASN1_INTEGER(bio, X509_get_serialNumber(cert));

    if ((len = BIO_pending(bio)) == 0) {
        BIO_free(bio);
        X509_free(cert);
        return NULL;
    }

    if (!(ser_str = calloc(len + 1, 1))) {
        return NULL;
    }

    BIO_read(bio, ser_str, len);

    X509_free(cert);
    BIO_free(bio);

    return ser_str;
}

unsigned char *
ssl_cipher_tostr(evhtp_ssl_t * ssl) {
    const SSL_CIPHER * cipher;
    const char       * p;
    unsigned char    * cipher_str;

    if (!ssl) {
        return NULL;
    }

    if (!(cipher = SSL_get_current_cipher(ssl))) {
        return NULL;
    }

    if (!(p = SSL_CIPHER_get_name(cipher))) {
        return NULL;
    }

    cipher_str = strdup(p);

    return cipher_str;
}

unsigned char *
ssl_cert_tostr(evhtp_ssl_t * ssl) {
    X509          * cert;
    BIO           * bio;
    unsigned char * raw_cert_str;
    unsigned char * cert_str;
    unsigned char * p;
    size_t          raw_cert_len;
    size_t          cert_len;
    int             i;

    if (!ssl) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    if (!(bio = BIO_new(BIO_s_mem()))) {
        X509_free(cert);
        return NULL;
    }

    if (!PEM_write_bio_X509(bio, cert)) {
        BIO_free(bio);
        X509_free(cert);

        return NULL;
    }

    raw_cert_len = BIO_pending(bio);
    raw_cert_str = calloc(raw_cert_len + 1, 1);

    BIO_read(bio, raw_cert_str, raw_cert_len);

    cert_len     = raw_cert_len - 1;

    for (i = 0; i < raw_cert_len - 1; i++) {
        if (raw_cert_str[i] == '\n') {
            /*
             * \n's will be converted to \r\n\t, so we must reserve
             * enough space for that much data.
             */
            cert_len += 2;
        }
    }

    /* 2 extra chars, one for possible last char (if not '\n'), and one for NULL terminator */
    cert_str = calloc(cert_len + 2, 1);
    p        = cert_str;

    for (i = 0; i < raw_cert_len - 1; i++) {
        if (raw_cert_str[i] == '\n') {
            *p++ = '\r';
            *p++ = '\n';
            *p++ = '\t';
        } else {
            *p++ = raw_cert_str[i];
        }
    }

    /* Don't assume last character is '\n' */
    if (raw_cert_str[i] != '\n') {
        *p++ = raw_cert_str[i];
    }

    BIO_free(bio);
    X509_free(cert);
    free(raw_cert_str);

    return cert_str;
} /* ssl_cert_tostr */

unsigned char *
ssl_x509_ext_tostr(evhtp_ssl_t * ssl, const char * oid) {
    unsigned char * ext_str;
    X509          * cert;
    ASN1_OBJECT   * oid_obj;

    STACK_OF(X509_EXTENSION) * exts;
    int                   oid_pos;
    X509_EXTENSION      * ext;
    ASN1_OCTET_STRING   * octet;
    const unsigned char * octet_data;
    long                  xlen;
    int                   xtag;
    int                   xclass;

    if (!ssl) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    if (!(oid_obj = OBJ_txt2obj(oid, 1))) {
        X509_free(cert);
        return NULL;
    }

    ext_str = NULL;
    exts    = cert->cert_info->extensions;
    oid_pos = X509v3_get_ext_by_OBJ(exts, oid_obj, -1);

    if (!(ext = X509_get_ext(cert, oid_pos))) {
        ASN1_OBJECT_free(oid_obj);
        X509_free(cert);
        return NULL;
    }

    if (!(octet = X509_EXTENSION_get_data(ext))) {
        ASN1_OBJECT_free(oid_obj);
        X509_free(cert);
        return NULL;
    }

    octet_data = octet->data;

    if (ASN1_get_object(&octet_data, &xlen, &xtag, &xclass, octet->length)) {
        ASN1_OBJECT_free(oid_obj);
        X509_free(cert);
        return NULL;
    }

    /* We're only supporting string data. Could optionally add support
     * for encoded binary data */

    if (xlen > 0 && xtag == 0x0C && octet->type == V_ASN1_OCTET_STRING) {
        ext_str = strndup(octet_data, xlen);
    }

    ASN1_OBJECT_free(oid_obj);
    X509_free(cert);

    return ext_str;
} /* ssl_x509_ext_tostr */

static int
ssl_crl_ent_should_reload(ssl_crl_ent_t * crl_ent) {
    struct stat statb;

    if (crl_ent->cfg->filename) {
        if (stat(crl_ent->cfg->filename, &statb) == -1) {
            /* file doesn't exist, we need to error out of this */
            return -1;
        }

#if __APPLE__
        if (statb.st_mtimespec.tv_sec > crl_ent->last_file_mod.tv_sec ||
            statb.st_mtimespec.tv_nsec > crl_ent->last_file_mod.tv_nsec) {
            /* file has been modified, so return yes */
            return 1;
        }
#else
        if (statb.st_mtime > crl_ent->last_file_mod) {
            return 1;
        }
#endif
    }

    if (crl_ent->cfg->dirname) {
        if (stat(crl_ent->cfg->dirname, &statb) == -1) {
            return -1;
        }

#if __APPLE__
        if (statb.st_mtimespec.tv_sec > crl_ent->last_dir_mod.tv_sec ||
            statb.st_mtimespec.tv_nsec > crl_ent->last_dir_mod.tv_nsec) {
            return 1;
        }
#else
        if (statb.st_mtime > crl_ent->last_file_mod) {
            return 1;
        }
#endif
    }

    return 0;
} /* ssl_crl_ent_should_reload */

int
ssl_crl_ent_reload(ssl_crl_ent_t * crl_ent) {
    X509_LOOKUP * lookup;
    X509_STORE  * old_crl;
    struct stat   file_stat;
    int           res;

    if (crl_ent == NULL) {
        return -1;
    }

    /* make sure we have either (or both) a crl file or directory */
    if (crl_ent->cfg->filename == NULL && crl_ent->cfg->dirname == NULL) {
        return -1;
    }

    if ((res = ssl_crl_ent_should_reload(crl_ent)) <= 0) {
        /* we should error on a negative status here, but for right now we
         * figure the crl list does not need to be reloaded.
         */
        return res;
    }

    /* if this crl_ent already has an allocated X509_STORE, we set it aside to
     * be free'd if all goes well with the new load.
     */
    old_crl = NULL;

    if (crl_ent->crl != NULL) {
        old_crl      = crl_ent->crl;
        crl_ent->crl = NULL;
    }

    /* initialize our own X509 storage stack. We utilize our own stack and our
     * own manual CRL verification because OpenSSL does not give us a method of
     * determining what a normal X509 is versus what a X509 CRL is. Since we
     * want to allow RProxy to dynamically read in CRL information as it comes
     * in, we must do it ourselves.
     */
    if ((crl_ent->crl = X509_STORE_new()) == NULL) {
        /* something bad happened, so add the old crl back and return an error
         * XXX: log something here.
         */
        crl_ent->crl = old_crl;
        return -1;
    }

    if (crl_ent->cfg->filename != NULL) {
        if (stat(crl_ent->cfg->filename, &file_stat) == -1) {
            /* XXX log error here */
            X509_STORE_free(crl_ent->crl);

            crl_ent->crl = old_crl;
            return -1;
        }

        if (!S_ISREG(file_stat.st_mode)) {
            /* not a file, XXX log error here */
            X509_STORE_free(crl_ent->crl);

            crl_ent->crl = old_crl;
            return -1;
        }

        /* attempt to add the filename to our x509 store */
        if (!(lookup = X509_STORE_add_lookup(crl_ent->crl, X509_LOOKUP_file()))) {
            /* oops, log something here */
            X509_STORE_free(crl_ent->crl);

            /* fallback to the old */
            crl_ent->crl = old_crl;

            return -1;
        }

        /* copy over the value of the last time this file was modified which we
         * use to check whether we should roll this crl over or not when the
         * even timer is triggered.
         * */
#ifdef __APPLE__
        memcpy(&crl_ent->last_file_mod, &file_stat.st_mtimespec, sizeof(struct timespec));
#else
        crl_ent->last_file_mod = file_stat.st_mtime;
#endif

        X509_LOOKUP_load_file(lookup, crl_ent->cfg->filename, X509_FILETYPE_PEM);
    }

    if (crl_ent->cfg->dirname != NULL) {
        if (stat(crl_ent->cfg->dirname, &file_stat) == -1) {
            X509_STORE_free(crl_ent->crl);

            crl_ent->crl = old_crl;
            return -1;
        }

        if (!S_ISDIR(file_stat.st_mode)) {
            X509_STORE_free(crl_ent->crl);

            crl_ent->crl = old_crl;
            return -1;
        }

        if (!(lookup = X509_STORE_add_lookup(crl_ent->crl, X509_LOOKUP_hash_dir()))) {
            X509_STORE_free(crl_ent->crl);

            crl_ent->crl = old_crl;
            return -1;
        }

#ifdef __APPLE__
        memcpy(&crl_ent->last_dir_mod, &file_stat.st_mtimespec, sizeof(struct timespec));
#else
        crl_ent->last_dir_mod = file_stat.st_mtime;
#endif


        X509_LOOKUP_add_dir(lookup, crl_ent->cfg->dirname, X509_FILETYPE_PEM);
    }

    return 0;
} /* ssl_crl_ent_reload */

static void
ssl_reload_timercb(int sock, short which, void * arg) {
    ssl_crl_ent_t * crl_ent;

    if (!(crl_ent = (ssl_crl_ent_t *)arg)) {
        return;
    }

    /* TODO: log stuff here */
    pthread_mutex_lock(&crl_ent->lock);
    {
        ssl_crl_ent_reload(crl_ent);
        event_add(crl_ent->reload_timer_ev, &crl_ent->cfg->reload_timer);
    }
    pthread_mutex_unlock(&crl_ent->lock);
}

ssl_crl_ent_t *
ssl_crl_ent_new(evhtp_t * htp, ssl_crl_cfg_t * config) {
    ssl_crl_ent_t * crl_ent;

    if (htp == NULL || config == NULL) {
        return NULL;
    }

    if (!(crl_ent = calloc(sizeof(ssl_crl_ent_t), 1))) {
        return NULL;
    }

    crl_ent->cfg = config;
    crl_ent->htp = htp;
    crl_ent->reload_timer_ev = evtimer_new(htp->evbase, ssl_reload_timercb, crl_ent);
    pthread_mutex_init(&crl_ent->lock, NULL);

    ssl_crl_ent_reload(crl_ent);
    event_add(crl_ent->reload_timer_ev, &config->reload_timer);

    return crl_ent;
}

static int
ssl_verify_crl(int ok, X509_STORE_CTX * ctx, ssl_crl_ent_t * crl_ent) {
    X509         * cert;
    X509_NAME    * subject;
    X509_NAME    * issuer;
    X509_CRL     * crl;
    X509_STORE_CTX store_ctx;
    EVP_PKEY     * public_key;
    X509_OBJECT    x509_obj = { 0 };
    int            res;
    int            timestamp_res;

    if (crl_ent == NULL) {
        return ok;
    }

    cert    = X509_STORE_CTX_get_current_cert(ctx);
    subject = X509_get_subject_name(cert);
    issuer  = X509_get_issuer_name(cert);

    /* lookup the CRL using the subject of the cert */
    X509_STORE_CTX_init(&store_ctx, crl_ent->crl, NULL, NULL);
    res     = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, subject, &x509_obj);
    crl     = x509_obj.data.crl;

    if ((res > 0) && crl != NULL) {
        public_key = X509_get_pubkey(cert);

        res        = X509_CRL_verify(crl, public_key);

        if (public_key != NULL) {
            EVP_PKEY_free(public_key);
        }

        if (res <= 0) {
            X509_OBJECT_free_contents(&x509_obj);

            return 0;
        }

        timestamp_res = X509_cmp_current_time(X509_CRL_get_nextUpdate(crl));

        if (timestamp_res == 0) {
            /* invalid nextupdate found */
            X509_OBJECT_free_contents(&x509_obj);

            return 0;
        }

        if (timestamp_res < 0) {
            /* CRL is expired */
            X509_OBJECT_free_contents(&x509_obj);

            return 0;
        }

        X509_OBJECT_free_contents(&x509_obj);
    }

    memset((void *)&x509_obj, 0, sizeof(x509_obj));

    X509_STORE_CTX_init(&store_ctx, crl_ent->crl, NULL, NULL);
    res = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, issuer, &x509_obj);
    crl = x509_obj.data.crl;

    if ((res > 0) && crl != NULL) {
        int num_revoked;
        int i;


        num_revoked = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));

        for (i = 0; i < num_revoked; i++) {
            X509_REVOKED * revoked;
            ASN1_INTEGER * asn1_serial;

            revoked     = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
            asn1_serial = revoked->serialNumber;

            if (!ASN1_INTEGER_cmp(asn1_serial, X509_get_serialNumber(cert))) {
                X509_OBJECT_free_contents(&x509_obj);

                return 0;
            }
        }

        X509_OBJECT_free_contents(&x509_obj);
    }

    return ok;
} /* ssl_verify_crl */

int
ssl_x509_verifyfn(int ok, X509_STORE_CTX * store) {
    char                 buf[256];
    X509               * err_cert;
    int                  err;
    int                  depth;
    SSL                * ssl;
    evhtp_connection_t * connection;
    evhtp_ssl_cfg_t    * ssl_cfg;

    err_cert   = X509_STORE_CTX_get_current_cert(store);
    err        = X509_STORE_CTX_get_error(store);
    depth      = X509_STORE_CTX_get_error_depth(store);
    ssl        = X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());

    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

    connection = SSL_get_app_data(ssl);
    ssl_cfg    = connection->htp->ssl_cfg;

    if (depth > ssl_cfg->verify_depth) {
        ok  = 0;
        err = X509_V_ERR_CERT_CHAIN_TOO_LONG;

        X509_STORE_CTX_set_error(store, err);
    }

    if (!ok) {
        rproxy_t * rproxy;

        rproxy = evthr_get_aux(connection->thread);
        assert(rproxy != NULL);

        logger_log(rproxy->err_log, lzlog_err,
                   "SSL: verify error:num=%d:%s:depth=%d:%s", err,
                   X509_verify_cert_error_string(err), depth, buf);
    }


    /* right now the only thing using the evhtp argument is the crl_ent_t's, in
     * the future this will become more generic. So here we check to see if the
     * CRL checking is enabled, and if it is, do CRL verification.
     */
    if (connection->htp->arg) {
        ssl_crl_ent_t * crl_ent = (ssl_crl_ent_t *)connection->htp->arg;

        pthread_mutex_lock(&crl_ent->lock);
        {
            ok = ssl_verify_crl(ok, store, (ssl_crl_ent_t *)connection->htp->arg);
        }
        pthread_mutex_unlock(&crl_ent->lock);
    }

    return ok;
} /* ssl_x509_verifyfn */

int
ssl_x509_issuedcb(X509_STORE_CTX * ctx, X509 * x, X509 * issuer) {
    return 1;
}

