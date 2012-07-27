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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions
 * and
 * limitations under the License.
 */
#ifndef __LZQ_H__
#define __LZQ_H__

struct lztq_elem;
struct lztq;

typedef struct lztq_elem lztq_elem;
typedef struct lztq      lztq;

typedef void (*lzq_freefn)(void *);
typedef int (*lztq_iterfn)(lztq_elem * elem, void * arg);

lztq      * lztq_new(void);
lztq      * lztq_dup(lztq * tq);
void        lztq_free(lztq * tq);

lztq_elem * lztq_elem_new(void * data, size_t len, lzq_freefn freefn);
void        lztq_elem_free(lztq_elem * elem);

lztq_elem * lztq_append(lztq * head, void * data, size_t len, lzq_freefn freefn);
lztq_elem * lztq_append_elem(lztq * head, lztq_elem * elem);
lztq_elem * lztq_prepend(lztq * head, void * data, size_t len, lzq_freefn freefn);
lztq_elem * lztq_prepend_elem(lztq * head, lztq_elem * elem);

lztq_elem * lztq_first(lztq * head);
lztq_elem * lztq_last(lztq * head);
lztq_elem * lztq_next(lztq_elem * elem);
lztq_elem * lztq_prev(lztq_elem * elem);

int         lztq_elem_remove(lztq_elem * elem);
int         lztq_for_each(lztq * head, lztq_iterfn iterfn, void * arg);

void      * lztq_elem_data(lztq_elem * elem);
lztq      * lztq_elem_head(lztq_elem * elem);
size_t      lztq_elem_size(lztq_elem * elem);
size_t      lztq_size(lztq * head);

#endif

