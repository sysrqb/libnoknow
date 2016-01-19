/**
 * libnoknow - The Nothing Or Knowledge (Oblivious Transfer) Library
 * Copyright (C) 2015 Matthew Finkel
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef NOKNOW_LOG_INT_H
#define NOKNOW_LOG_INT_H 1

#include <noklog.h>

typedef struct nok_log_ctx_s {
  libnok_log_level_t verbosity;
  FILE *outlog;
  FILE *errlog;
} nok_log_ctx_t;

nok_log_ctx_t * nok_log_init() __attribute__ ((visibility ("hidden")));
#if USING_OPENSSL
int nok_log_create_in_mem_buffer(BIO **inmem)
    __attribute__ ((visibility ("hidden")));
BIO * nok_log_get_in_mem_bio();
    __attribute__ ((visibility ("hidden")));
#endif /* USING_OPENSSL */
int nok_log__logmsg(nok_log_ctx_t *ctx, libnok_log_level_t level,
                    char *filename, int lineno, const char *func,
                    const char *fmt, ...)
                __attribute__ ((format (printf, 6, 7),visibility ("hidden")));

#define nok_log_logmsg(l, ...) \
    nok_log__logmsg(l, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)

#endif /* NOKNOW_LOG_INT_H */
