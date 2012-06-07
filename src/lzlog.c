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

#include "lzlog.h"

typedef struct lzlog_vtbl lzlog_vtbl;

struct log {
    lzlog_vtbl    * vtbl;
    char          * ident;
    int             opts;
    lzlog_level     level;
    pthread_mutex_t mutex;
};

struct lzlog_vtbl {
    size_t size;
    void   (* destroy)(lzlog * log);
    void   (* print)(lzlog * log, lzlog_level level, const char * fmt, va_list ap);
};

static char * _level_str[] = {
    "EMERG",
    "ALERT",
    "CRIT",
    "ERROR",
    "WARN",
    "NOTICE",
    "INFO",
    "DEBUG",
    NULL
};

void
lzlog_vprintf(lzlog * log, lzlog_level level, const char * fmt, va_list ap) {
    if (log == NULL) {
        return;
    }

    if (level > log->level) {
        return;
    }

    if (log->vtbl->print) {
        (log->vtbl->print)(log, level, fmt, ap);
    }
}

void
lzlog_write(lzlog * log, lzlog_level level, const char * fmt, ...) {
    va_list ap;

    if (log == NULL) {
        return;
    }

    if (level > log->level) {
        return;
    }

    va_start(ap, fmt);
    {
        lzlog_vprintf(log, level, fmt, ap);
    }
    va_end(ap);
}

lzlog *
lzlog_new(lzlog_vtbl * vtbl, const char * ident, int opts) {
    lzlog * log;

    if (!(log = calloc(vtbl->size, 1))) {
        return NULL;
    }

    pthread_mutex_init(&log->mutex, NULL);

    log->ident = ident ? strdup(ident) : strdup("pname");
    log->vtbl  = vtbl;
    log->level = lzlog_max;
    log->opts  = opts;

    return log;
}

void
log_free(lzlog * log) {
    if (!log) {
        return;
    }

    if (log->vtbl->destroy) {
        (log->vtbl->destroy)(log);
    }

    if (log->ident) {
        free(log->ident);
    }

    pthread_mutex_destroy(&log->mutex);

    free(log);
}

void
lzlog_set_level(lzlog * log, lzlog_level level) {
    if (!log) {
	return;
    }

    log->level = level;
}

static char *
_reformat(lzlog * log, const char * fmt, lzlog_level level) {
    int    sres;
    char * buf = NULL;
    size_t len = strlen(fmt) + 4;

    if (log->opts == LZLOG_OPT_NONE) {
        return NULL;
    }

    if (!(buf = calloc(len, 1))) {
        abort();
    }

    if (log->opts & LZLOG_OPT_WDATE) {
        char   sbuf[255];
        time_t tt = time(NULL);

        len += strftime(sbuf, 254, "%b %d %H:%M:%S ", localtime(&tt));
        buf  = realloc(buf, len);
        sres = snprintf(buf, len, "%s", sbuf);

        if (sres >= len || sres < 0) {
            abort();
        }
    }

    if (log->opts & LZLOG_OPT_WNAME) {
        len += strlen(log->ident);
        buf  = realloc(buf, len);

        strncat(buf, log->ident, len);
    }

    if (log->opts & LZLOG_OPT_WPID) {
        char  sbuf[10 + 3];    /* pid + [] + null */
        pid_t pid = getpid();

        sres = snprintf(sbuf, sizeof(sbuf), "[%u]", pid);

        if (sres >= sizeof(sbuf) || sres < 0) {
            abort();
        }

        len += strlen(sbuf);
        buf  = realloc(buf, len);

        strncat(buf, sbuf, len);
    }

    if (log->opts & LZLOG_OPT_WLEVEL) {
        if (level < lzlog_max) {
            len += strlen(_level_str[level]) + 3;
            buf  = realloc(buf, len);

            if (log->opts != LZLOG_OPT_WLEVEL) {
                strcat(buf, ": ");
            }

            strncat(buf, _level_str[level], len);
        }
    }

    strncat(buf, ": ", len);
    strncat(buf, fmt, len);
    strncat(buf, "\n", len);

    return buf;
} /* _reformat */

static void
_syslog_print(lzlog * log, lzlog_level level, const char * fmt, va_list ap) {
    int    priority = 0;
    char * nfmt     = NULL;

    nfmt = _reformat(log, fmt, level);

    switch (level) {
        case lzlog_emerg:
            priority   = LOG_EMERG;
            break;
        case lzlog_alert:
            priority   = LOG_ALERT;
            break;
        case lzlog_crit:
            priority   = LOG_CRIT;
            break;
        case lzlog_err:
            priority   = LOG_ERR;
            break;
        case lzlog_warn:
            priority   = LOG_WARNING;
            break;
        case lzlog_notice:
            priority = LOG_NOTICE;
            break;
        case lzlog_info:
            priority   = LOG_INFO;
            break;
        case lzlog_debug:
            priority   = LOG_DEBUG;
            break;
        default:
            priority   = LOG_ERR;
            break;
    } /* switch */

    vsyslog(priority, nfmt ? nfmt : fmt, ap);

    if (nfmt) {
        free(nfmt);
    }
}     /* _syslog_print */

static void
_syslog_destroy(lzlog * log) {
    return closelog();
}

static lzlog_vtbl _syslzlog_vtbl = {
    sizeof(lzlog),
    _syslog_destroy,
    _syslog_print
};

lzlog *
lzlog_syslog_new(const char * ident, int opts, int facility) {
    int syslog_opts = 0;

    if (opts & LZLOG_OPT_WPID) {
        syslog_opts |= LOG_PID;
    }

    openlog(ident, syslog_opts, facility);

    return lzlog_new(&_syslzlog_vtbl, ident, opts);
}

struct _log_file {
    lzlog_vtbl parent;
    char     * ident;
    FILE     * file;
};

static void
_file_print(lzlog * log, lzlog_level level, const char * fmt, va_list ap) {
    struct _log_file * this = (struct _log_file *)log;
    char             * nfmt = NULL;


    nfmt = _reformat(log, fmt, level);

    pthread_mutex_lock(&log->mutex);
    {
        vfprintf(this->file, nfmt ? nfmt : fmt, ap);
    }
    pthread_mutex_unlock(&log->mutex);

    if (nfmt) {
        free(nfmt);
    }
}

static void
_file_destroy(lzlog * log) {
    struct _log_file * this = (struct _log_file *)log;

    pthread_mutex_lock(&log->mutex);
    {
        fflush(this->file);
        fclose(this->file);
    }
    pthread_mutex_unlock(&log->mutex);

    free(this);
}

static lzlog_vtbl _file_vtbl = {
    sizeof(struct _log_file),
    _file_destroy,
    _file_print
};

lzlog *
lzlog_file_new(const char * file, const char * ident, int opts) {
    lzlog            * result;
    struct _log_file * lfile;
    const char       * filename;

    filename = file ? file : "/dev/stdout";

    if (!(result = lzlog_new(&_file_vtbl, ident, opts))) {
        return NULL;
    }

    lfile = (struct _log_file *)result;

    if (!(lfile->file = fopen(filename, "a+"))) {
        return NULL;
    }

    lfile->ident = ident ? strdup(ident) : NULL;

    return result;
}
