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
    lzlog_type      type;
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

struct {
    int          facility;
    const char * str;
} _facility_strmap[] = {
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

struct {
    lzlog_level  level;
    const char * str;
} _level_strmap[] = {
    { lzlog_emerg,  "emerg"  },
    { lzlog_alert,  "alert"  },
    { lzlog_crit,   "crit"   },
    { lzlog_err,    "err"    },
    { lzlog_warn,   "warn"   },
    { lzlog_notice, "notice" },
    { lzlog_info,   "info"   },
    { lzlog_debug,  "debug"  },
    { -1,           NULL     }
};

int
lzlog_facilitystr_to_facility(const char * str) {
    int i;

    if (str == NULL) {
        return -1;
    }

    for (i = 0; _facility_strmap[i].str; i++) {
        if (!strcasecmp(_facility_strmap[i].str, str)) {
            return _facility_strmap[i].facility;
        }
    }

    return -1;
}

lzlog_level
lzlog_levelstr_to_level(const char * str) {
    int i;

    if (str == NULL) {
        return -1;
    }

    for (i = 0; _level_strmap[i].str; i++) {
        if (!strcasecmp(_level_strmap[i].str, str)) {
            return _level_strmap[i].level;
        }
    }

    return -1;
}

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

static lzlog *
lzlog_new(lzlog_vtbl * vtbl, const char * ident, int opts) {
    lzlog * log;

    if (!(log = calloc(vtbl->size, 1))) {
        return NULL;
    }

    pthread_mutex_init(&log->mutex, NULL);

    if (ident) {
        log->ident = strdup(ident);
    } else {
        log->ident = strdup("pname");
    }

    log->vtbl  = vtbl;
    log->level = lzlog_max;
    log->opts  = opts;

    return log;
}

void
lzlog_free(lzlog * log) {
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

lzlog_type
lzlog_get_type(lzlog * log) {
    return log->type;
}

static char *
_reformat(lzlog * log, const char * fmt, lzlog_level level) {
    int    sres;
    char * buf   = NULL;
    size_t len   = strlen(fmt) + 4;
    int    wrote = 0;

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

        wrote = 1;
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

        len  += strlen(sbuf);
        buf   = realloc(buf, len);

        strncat(buf, sbuf, len);

        wrote = 1;
    }

    if (log->opts & LZLOG_OPT_WLEVEL) {
        if (level < lzlog_max) {
            len += strlen(_level_str[level]) + 3;
            buf  = realloc(buf, len);

            if (log->opts != LZLOG_OPT_WLEVEL) {
                strcat(buf, ": ");
            }

            strncat(buf, _level_str[level], len);

            wrote = 1;
        }
    }

    if (wrote == 1) {
        strncat(buf, ": ", len);
    }

    strncat(buf, fmt, len);

    if (log->opts & LZLOG_OPT_NEWLINE) {
        strncat(buf, "\n", len);
    }

    return buf;
} /* _reformat */

static void
_syslog_print(lzlog * log, lzlog_level level, const char * fmt, va_list ap) {
    int    priority = 0;
    char * nfmt     = NULL;

    nfmt = _reformat(log, fmt, level);

    switch (level) {
        case lzlog_emerg:
            priority = LOG_EMERG;
            break;
        case lzlog_alert:
            priority = LOG_ALERT;
            break;
        case lzlog_crit:
            priority = LOG_CRIT;
            break;
        case lzlog_err:
            priority = LOG_ERR;
            break;
        case lzlog_warn:
            priority = LOG_WARNING;
            break;
        case lzlog_notice:
            priority = LOG_NOTICE;
            break;
        case lzlog_info:
            priority = LOG_INFO;
            break;
        case lzlog_debug:
            priority = LOG_DEBUG;
            break;
        default:
            priority = LOG_ERR;
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
#ifdef __APPLE__
    return lzlog_asl_new(ident, opts, facility);
#endif
    int     syslog_opts = 0;
    lzlog * log;

    if (opts & LZLOG_OPT_WPID) {
        syslog_opts |= LOG_PID;
    }

    openlog(ident, syslog_opts, facility);

    log       = lzlog_new(&_syslzlog_vtbl, ident, opts);
    log->type = lzlog_syslog;

    return log;
}

struct _log_file {
    lzlog  parent;
    FILE * file;
};

static void
_file_print(lzlog * log, lzlog_level level, const char * fmt, va_list ap) {
    struct _log_file * this = (struct _log_file *)log;
    char             * nfmt = NULL;


    nfmt = _reformat(log, fmt, level);

    pthread_mutex_lock(&log->mutex);
    {
        vfprintf(this->file, nfmt ? nfmt : fmt, ap);
        fflush(this->file);
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

    if (!(result = lzlog_new(&_file_vtbl, ident, opts))) {
        return NULL;
    }

    result->type = lzlog_file;
    lfile        = (struct _log_file *)result;

    if (!(lfile->file = fopen(file, "a+"))) {
        return NULL;
    }

    return result;
}

lzlog *
lzlog_from_template(const char * template, const char * ident, int opts) {
    char      * scheme;
    char      * path;
    char      * levelstr;
    char      * template_cpy;
    lzlog_level level;
    lzlog     * log;

    if (template == NULL) {
        return NULL;
    }

    template_cpy = strdup(template);

    /*
     * templates are as follows:
     *
     * <scheme>:<filename|syslog_facility>#<max_loglevel>
     */

    scheme       = strtok(template_cpy, ":");
    path         = strtok(NULL, ":");
    levelstr     = strtok(path, "#");
    levelstr     = strtok(NULL, "#");

    if (!scheme || !path) {
        free(template_cpy);
        return NULL;
    }

    if (!strcasecmp(scheme, "syslog")) {
        int facility;

        if (!(facility = lzlog_facilitystr_to_facility(path))) {
            free(template_cpy);
            return NULL;
        }

        log = lzlog_syslog_new(ident, opts, facility);
    } else if (!strcasecmp(scheme, "file")) {
        log = lzlog_file_new(path, ident, opts);
    } else {
        free(template_cpy);
        return NULL;
    }

    if (levelstr) {
        level = lzlog_levelstr_to_level(levelstr);
    } else {
        level = lzlog_notice;
    }

    lzlog_set_level(log, level);

    free(template_cpy);
    return log;
} /* lzlog_from_template */

#ifdef __APPLE__
#include <asl.h>

const char *
asl_syslog_faciliy_num_to_name(int n) {
    if (n < 0) {
        return NULL;
    }

    if (n == LOG_AUTH) {
        return "auth";
    }
    if (n == LOG_AUTHPRIV) {
        return "authpriv";
    }
    if (n == LOG_CRON) {
        return "cron";
    }
    if (n == LOG_DAEMON) {
        return "daemon";
    }
    if (n == LOG_FTP) {
        return "ftp";
    }
    if (n == LOG_INSTALL) {
        return "install";
    }
    if (n == LOG_KERN) {
        return "kern";
    }
    if (n == LOG_LPR) {
        return "lpr";
    }
    if (n == LOG_MAIL) {
        return "mail";
    }
    if (n == LOG_NETINFO) {
        return "netinfo";
    }
    if (n == LOG_REMOTEAUTH) {
        return "remoteauth";
    }
    if (n == LOG_NEWS) {
        return "news";
    }
    if (n == LOG_AUTH) {
        return "security";
    }
    if (n == LOG_SYSLOG) {
        return "syslog";
    }
    if (n == LOG_USER) {
        return "user";
    }
    if (n == LOG_UUCP) {
        return "uucp";
    }
    if (n == LOG_LOCAL0) {
        return "local0";
    }
    if (n == LOG_LOCAL1) {
        return "local1";
    }
    if (n == LOG_LOCAL2) {
        return "local2";
    }
    if (n == LOG_LOCAL3) {
        return "local3";
    }
    if (n == LOG_LOCAL4) {
        return "local4";
    }
    if (n == LOG_LOCAL5) {
        return "local5";
    }
    if (n == LOG_LOCAL6) {
        return "local6";
    }
    if (n == LOG_LOCAL7) {
        return "local7";
    }
    if (n == LOG_LAUNCHD) {
        return "launchd";
    }

    return NULL;
} /* asl_syslog_faciliy_num_to_name */

struct _log_asl {
    lzlog     parent;
    char    * facility;
    aslclient asl_f;
};

static void
_asl_print(lzlog * log, lzlog_level level, const char * fmt, va_list ap) {
    aslmsg            facmsg;
    int               priority = 0;
    struct _log_asl * this     = (struct _log_asl *)log;

    switch (level) {
        case lzlog_emerg:
            priority = ASL_LEVEL_EMERG;
            break;
        case lzlog_alert:
            priority = ASL_LEVEL_ALERT;
            break;
        case lzlog_crit:
            priority = ASL_LEVEL_CRIT;
            break;
        case lzlog_err:
            priority = ASL_LEVEL_ERR;
            break;
        case lzlog_warn:
            priority = ASL_LEVEL_WARNING;
            break;
        case lzlog_notice:
            priority = ASL_LEVEL_NOTICE;
            break;
        case lzlog_info:
            priority = ASL_LEVEL_INFO;
            break;
        case lzlog_debug:
            priority = ASL_LEVEL_DEBUG;
            break;
        default:
            priority = ASL_LEVEL_ERR;
            break;
    } /* switch */

    facmsg = asl_new(ASL_TYPE_MSG);

    asl_set(facmsg, ASL_KEY_FACILITY, this->facility);
    asl_vlog(this->asl_f, facmsg, priority, fmt, ap);
    asl_free(facmsg);
}     /* _asl_print */

static lzlog_vtbl _asl_vtbl = {
    sizeof(struct _log_asl),
    NULL,
    _asl_print
};

lzlog *
lzlog_asl_new(const char * ident, int opts, int facility) {
    lzlog           * result;
    struct _log_asl * lasl;
    const char      * facility_str =
        asl_syslog_faciliy_num_to_name(facility);

    if (!(result = lzlog_new(&_asl_vtbl, ident, opts))) {
        return NULL;
    }

    result->type   = lzlog_asl;
    lasl           = (struct _log_asl *)result;

    lasl->asl_f    = asl_open(ident, facility_str, 0);
    lasl->facility = strdup(facility_str);

    return result;
}

#endif
