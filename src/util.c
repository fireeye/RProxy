#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>

#ifndef NO_RLIMITS
#include <sys/time.h>
#include <sys/resource.h>
#endif

#include "rproxy.h"

int
util_write_header_to_evbuffer(evhtp_header_t * hdr, void * arg) {
    evbuf_t * buf;

    buf = arg;
    assert(buf != NULL);

    evbuffer_add(buf, hdr->key, hdr->klen);
    evbuffer_add(buf, ": ", 2);
    evbuffer_add(buf, hdr->val, hdr->vlen);
    evbuffer_add(buf, "\r\n", 2);

    return 0;
}

evbuf_t *
util_request_to_evbuffer(evhtp_request_t * r) {
    evbuf_t * buf;
    char    * query_args;

    if (r->uri && r->uri->query_raw) {
        query_args = r->uri->query_raw;
    } else {
        query_args = "";
    }

    if (*query_args == '?') {
        query_args++;
    }

    buf = evbuffer_new();
    assert(buf != NULL);

    evbuffer_add_printf(buf, "%s %s%s%s HTTP/%d.%d\r\n",
                        htparser_get_methodstr(r->conn->parser),
                        r->uri->path->full,
                        *query_args ? "?" : "", query_args,
                        htparser_get_major(r->conn->parser),
                        htparser_get_minor(r->conn->parser));

    evhtp_headers_for_each(r->headers_in, util_write_header_to_evbuffer, buf);
    evbuffer_add(buf, "\r\n", 2);

    return buf;
}

void
util_dropperms(const char * user, const char * group) {
    if (group) {
        struct group * grp;

        if (!(grp = getgrnam(group))) {
            fprintf(stderr, "No such group '%s'\n", group);
            exit(1);
        }

        if (setgid(grp->gr_gid) != 0) {
            fprintf(stderr, "Could not grp perm to '%s' (%s)\n",
                    group, strerror(errno));
            exit(1);
        }
    }

    if (user) {
        struct passwd * usr;

        if (!(usr = getpwnam(user))) {
            fprintf(stderr, "No such user '%s'\n", user);
            exit(1);
        }

        if (seteuid(usr->pw_uid) != 0) {
            fprintf(stderr, "Could not usr perm to '%s' (%s)\n",
                    user, strerror(errno));
            exit(1);
        }
    }
}

int
util_daemonize(char * root, int noclose) {
    int fd;

    switch (fork()) {
        case -1:
            return -1;
        case 0:
            break;
        default:
            exit(EXIT_SUCCESS);
    }

    if (setsid() == -1) {
        return -1;
    }

    if (root == 0) {
        if (chdir(root) != 0) {
            perror("chdir");
            return -1;
        }
    }

    if (noclose == 0 && (fd = open("/dev/null", O_RDWR, 0)) != -1) {
        if (dup2(fd, STDIN_FILENO) < 0) {
            perror("dup2 stdin");
            return -1;
        }
        if (dup2(fd, STDOUT_FILENO) < 0) {
            perror("dup2 stdout");
            return -1;
        }
        if (dup2(fd, STDERR_FILENO) < 0) {
            perror("dup2 stderr");
            return -1;
        }

        if (fd > STDERR_FILENO) {
            if (close(fd) < 0) {
                perror("close");
                return -1;
            }
        }
    }
    return 0;
} /* daemonize */

int
util_set_rlimits(int nofiles) {
#ifndef NO_RLIMITS
    struct rlimit limit;
    rlim_t        max_nofiles;

    if (nofiles <= 0) {
        return -1;
    }

    if (getrlimit(RLIMIT_NOFILE, &limit) == -1) {
        fprintf(stderr, "Could not obtain curr NOFILE lim: %s\n", strerror(errno));
        return 0;
    }

    if (nofiles > limit.rlim_max) {
        fprintf(stderr, "Unable to set curr NOFILE (requested=%d, sys-limit=%d)\n",
                (int)nofiles, (int)limit.rlim_max);
        fprintf(stderr, "Please make sure your systems limits.conf is set high enough (usually in /etc/security/limits.conf!\n");
        return -1;
    }

    if (nofiles < 10000) {
        fprintf(stderr, "WARNING: %d max-nofiles is very small, this could be bad, lets check...\n", nofiles);

        if ((int)limit.rlim_max >= 10000) {
            fprintf(stderr, "INFO: using %d (your hard-limit) on max-nofiles instead of %d!\n", (int)limit.rlim_max, nofiles);
            nofiles = limit.rlim_max;
        } else {
            fprintf(stderr, "WARN: nope, can't go any higher, you may want to fix this...\n");
        }
    }

    limit.rlim_cur = nofiles;

    if (setrlimit(RLIMIT_NOFILE, &limit) == -1) {
        fprintf(stderr, "Could not set NOFILE lim: %s\n", strerror(errno));
        return -1;
    }

#else
    fprintf(stderr, "Your system does not support get|setrlimits!\n");
#endif
    return 0;
} /* rproxy_set_rlimits */

/**
 * @brief glob/wildcard type pattern matching.
 *
 * Note: This code was derived from redis's (v2.6) stringmatchlen() function.
 *
 * @param pattern
 * @param string
 *
 * @return
 */
int
util_glob_match(const char * pattern, const char * string) {
    size_t pat_len;
    size_t str_len;

    if (!pattern || !string) {
        return 0;
    }

    pat_len = strlen(pattern);
    str_len = strlen(string);

    while (pat_len) {
        if (pattern[0] == '*') {
            while (pattern[1] == '*') {
                pattern++;
                pat_len--;
            }

            if (pat_len == 1) {
                return 1;
            }

            while (str_len) {
                if (util_glob_match(pattern + 1, string)) {
                    return 1;
                }

                string++;
                str_len--;
            }

            return 0;
        } else {
            if (pattern[0] != string[0]) {
                return 0;
            }

            string++;
            str_len--;
        }

        pattern++;
        pat_len--;

        if (str_len == 0) {
            while (*pattern == '*') {
                pattern++;
                pat_len--;
            }
            break;
        }
    }

    if (pat_len == 0 && str_len == 0) {
        return 1;
    }

    return 0;
} /* util_glob_match */

static int
_glob_match_iterfn(lztq_elem * elem, void * arg) {
    const char * needle;
    const char * haystack;

    if (!(needle = (const char *)arg)) {
        return -1;
    }

    if (!(haystack = (const char *)lztq_elem_data(elem))) {
        return -1;
    }

    return util_glob_match(haystack, needle);
}

/**
 * @brief iterate over a tailq of strings and attempt to find a wildcard match.
 *
 * @param tq a lztq of strings to match against. (haystack)
 * @param str  the string to compare. (needle)
 *
 * @return -1 on errir, 1 on match, 0 on no match.
 */
int
util_glob_match_lztq(lztq * tq, const char * str) {
    /* if the tailq is empty, we default to allowed */
    if (tq == NULL || lztq_size(tq) == 0) {
        return 1;
    }

    /* since lztq_for_each will break from the loop if the iterator returns
     * anything but zero, we utilize the result as an indicator as to whether
     * the wildcard match was sucessful.
     *
     * result =  0 == no match
     * result =  1 == match
     * result = -1 == matching error
     */
    return lztq_for_each(tq, _glob_match_iterfn, (void *)str);
}

static int
_rm_headers_iterfn(lztq_elem * elem, void * arg) {
    evhtp_headers_t * headers;
    const char      * header_key;

    if (!(headers = (evhtp_headers_t *)arg)) {
        return -1;
    }

    if (!(header_key = (const char *)lztq_elem_data(elem))) {
        return -1;
    }

    evhtp_kv_rm_and_free(headers, evhtp_kvs_find_kv(headers, header_key));

    return 0;
}

/**
 * @brief iterates over a lzq of strings and removes any headers with that
 *        string.
 *
 * @param tq
 * @param headers
 *
 * @return 0 on success, otherwise -1
 */
int
util_rm_headers_via_lztq(lztq * tq, evhtp_headers_t * headers) {
    if (tq == NULL || headers == NULL) {
        return 0;
    }

    return lztq_for_each(tq, _rm_headers_iterfn, (void *)headers);
}

