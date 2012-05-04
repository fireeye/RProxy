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
#include "regress.h"
#include "tinytest.h"
#include "tinytest_macros.h"

#if 0
static void
test_foo(void * ptr) {
    int bar = 50;

    tt_assert(bar == 50);
end:
    return;
}

static void
test_fail(void * ptr) {
    int bar = 50;

    tt_assert(bar == 1);
end:
    return;
}

struct testcase_t test_testcases[] = {
    { "foo",  test_foo,  0, NULL, NULL },
    { "fail", test_fail, 0, NULL, NULL },
    END_OF_TESTCASES
};
#endif

struct testgroup_t testgroups[] = {
    { "cfg/", cfg_testcases },
    END_OF_GROUPS
};

int
main(int argc, char ** argv) {
    if (tinytest_main(argc, (const char **)argv, testgroups)) {
        return 1;
    }

    return 0;
}

