#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include "lzq.h"

struct lztq_elem {
    lztq     * tq_head;
    void     * data;
    size_t     len;
    lzq_freefn free_fn;

    TAILQ_ENTRY(lztq_elem) next;
};

TAILQ_HEAD(__lztqhd, lztq_elem);

struct lztq {
    size_t          n_elem;
    struct __lztqhd elems;
};

static void
_lzq_freefn(void * data) {
    if (data) {
        free(data);
    }
}

lztq *
lztq_new(void) {
    lztq * tq;

    if (!(tq = malloc(sizeof(lztq)))) {
        return NULL;
    }

    TAILQ_INIT(&tq->elems);

    tq->n_elem = 0;

    return tq;
}

void
lztq_free(lztq * tq) {
    lztq_elem * elem;
    lztq_elem * temp;

    if (!tq) {
        return;
    }

    for (elem = lztq_first(tq); elem != NULL; elem = temp) {
        temp = lztq_next(elem);

        lztq_elem_remove(elem);
        lztq_elem_free(elem);
    }

    free(tq);
}

static int
lztq_dup_itercb(lztq_elem * elem, void * arg) {
    lztq * tq = arg;
    size_t len;
    void * data;

    len  = lztq_elem_size(elem);
    data = lztq_elem_data(elem);

    if (len) {
        if (!(data = malloc(len))) {
            return -1;
        }

        memcpy(data, lztq_elem_data(elem), len);
    }

    if (!lztq_append(tq, data, len, elem->free_fn)) {
        return -1;
    }

    return 0;
}

lztq *
lztq_dup(lztq * tq) {
    lztq * new_tq;

    if (tq == NULL) {
        return NULL;
    }

    if (!(new_tq = lztq_new())) {
        return NULL;
    }

    if (lztq_for_each(tq, lztq_dup_itercb, new_tq)) {
        lztq_free(new_tq);
        return NULL;
    }

    return new_tq;
}

lztq_elem *
lztq_elem_new(void * data, size_t len, lzq_freefn freefn) {
    lztq_elem * elem;

    if (!(elem = malloc(sizeof(lztq_elem)))) {
        return NULL;
    }

    elem->data    = data;
    elem->len     = len;
    elem->tq_head = NULL;

    if (freefn) {
        elem->free_fn = freefn;
    } else {
        elem->free_fn = _lzq_freefn;
    }

    return elem;
}

void
lztq_elem_free(lztq_elem * elem) {
    if (elem == NULL) {
        return;
    }

    if (elem->data) {
        (elem->free_fn)(elem->data);
    }

    free(elem);
}

lztq_elem *
lztq_append(lztq * tq, void * data, size_t len, lzq_freefn freefn) {
    lztq_elem * elem;

    if (tq == NULL) {
        return NULL;
    }

    if (!(elem = lztq_elem_new(data, len, freefn))) {
        return NULL;
    }

    return lztq_append_elem(tq, elem);
}

lztq_elem *
lztq_append_elem(lztq * tq, lztq_elem * elem) {
    if (!tq || !elem) {
        return NULL;
    }

    TAILQ_INSERT_TAIL(&tq->elems, elem, next);

    tq->n_elem   += 1;
    elem->tq_head = tq;

    return elem;
}

lztq_elem *
lztq_prepend(lztq * tq, void * data, size_t len, lzq_freefn freefn) {
    lztq_elem * elem;

    if (!tq) {
        return NULL;
    }

    if (!(elem = lztq_elem_new(data, len, freefn))) {
        return NULL;
    }

    return lztq_prepend_elem(tq, elem);
}

lztq_elem *
lztq_prepend_elem(lztq * tq, lztq_elem * elem) {
    if (!tq || !elem) {
        return NULL;
    }

    TAILQ_INSERT_HEAD(&tq->elems, elem, next);

    tq->n_elem   += 1;
    elem->tq_head = tq;

    return elem;
}

lztq_elem *
lztq_first(lztq * tq) {
    if (!tq) {
        return NULL;
    }

    return TAILQ_FIRST(&tq->elems);
}

lztq_elem *
lztq_last(lztq * tq) {
    if (!tq) {
        return NULL;
    }

    return TAILQ_LAST(&tq->elems, __lztqhd);
}

lztq_elem *
lztq_next(lztq_elem * elem) {
    if (!elem) {
        return NULL;
    }

    return TAILQ_NEXT(elem, next);
}

lztq_elem *
lztq_prev(lztq_elem * elem) {
    if (!elem) {
        return NULL;
    }

    return TAILQ_PREV(elem, __lztqhd, next);
}

int
lztq_elem_remove(lztq_elem * elem) {
    lztq * head;

    if (!elem) {
        return -1;
    }

    if (!(head = elem->tq_head)) {
        return -1;
    }

    TAILQ_REMOVE(&head->elems, elem, next);

    head->n_elem -= 1;

    return 0;
}

int
lztq_for_each(lztq * tq, lztq_iterfn iterfn, void * arg) {
    lztq_elem * elem;

    if (!tq || !iterfn) {
        return -1;
    }

    TAILQ_FOREACH(elem, &tq->elems, next) {
        int sres;

        if ((sres = (iterfn)(elem, arg)) != 0) {
            return sres;
        }
    }

    return 0;
}

void *
lztq_elem_data(lztq_elem * elem) {
    if (elem) {
        return elem->data;
    }

    return NULL;
}

size_t
lztq_elem_size(lztq_elem * elem) {
    if (elem) {
        return elem->len;
    }

    return 0;
}

lztq *
lztq_elem_head(lztq_elem * elem) {
    if (elem) {
        return elem->tq_head;
    }

    return NULL;
}

size_t
lztq_size(lztq * head) {
    if (!head) {
        return 0;
    }

    return head->n_elem;
}

