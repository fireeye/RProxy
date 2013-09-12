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

#include "rproxy.h"

void
request_free(request_t * request) {
    if (request == NULL) {
        return;
    }

    if (request->parser) {
        free(request->parser);
    }

    if (request->pending_ev) {
        event_free(request->pending_ev);
    }

    if (request->upstream_rlbev != NULL) {
        ratelim_free_bev(request->upstream_rlbev);
    }

    if (request->downstream_rlbev != NULL) {
        ratelim_free_bev(request->downstream_rlbev);
    }

    free(request);
}

request_t *
request_new(rproxy_t * rproxy) {
    request_t * request;

    if (rproxy == NULL) {
        return NULL;
    }

    if (!(request = calloc(sizeof(request_t), 1))) {
        return NULL;
    }

    request->rproxy = rproxy;
    request->parser = htparser_new();

    htparser_init(request->parser, htp_type_response);
    htparser_set_userdata(request->parser, request);

    return request;
}

