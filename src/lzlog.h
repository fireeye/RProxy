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

#ifndef __LZLOG_H__
#define __LZLOG_H__

#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

#define LZLOG_OPT_NONE         (1 << 0)
#define LZLOG_OPT_WDATE        (1 << 1)
#define LZLOG_OPT_WLEVEL       (1 << 2)
#define LZLOG_OPT_WPID         (1 << 3)
#define LZLOG_OPT_WNAME        (1 << 4)
#define LZLOG_OPT_EMU_SYSLZLOG (LZLOG_OPT_WDATE | LZLOG_OPT_WNAME | LZLOG_OPT_WPID)

struct lzlog;
struct lzlog_vtbl;

enum lzlog_level {
    lzlog_emerg = 0,
    lzlog_alert,
    lzlog_crit,
    lzlog_err,
    lzlog_warn,
    lzlog_notice,
    lzlog_info,
    lzlog_debug,
    lzlog_max
};

typedef enum lzlog_level lzlog_level;
typedef struct log       lzlog;

void    lzlog_write(lzlog * log, lzlog_level level, const char * fmt, ...);
void    lzlog_free(lzlog * log);

lzlog * lzlog_file_new(const char * file, const char * ident, int opts);
lzlog * lzlog_syslog_new(const char * ident, int opts, int facility);

#endif

