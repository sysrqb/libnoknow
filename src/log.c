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

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/bio.h>

#include <internal/log.h>
#include <internal/noknow.h>

#include <internal/nok_snprintf.h>

nok_log_ctx_t *
nok_log_init()
{
  nok_log_ctx_t *newctx;
  newctx = (nok_log_ctx_t *) malloc(sizeof(*newctx));
  if (newctx == NULL)
    return NULL;
  memset(newctx, 0, sizeof(*newctx));
  newctx->verbosity = NOK_VERBOSITY_NOTICE;
  newctx->outlog = newctx->errlog = NULL;
  return newctx;
}

int
libnok_log_set_logs(libnok_context_t *ctx, FILE *out, FILE *err)
{
  if (out != NULL)
    ctx->logctx.outlog = out;
  if (err != NULL)
    ctx->logctx.errlog = err;
  return 0;
}

int
libnok_log_set_log_verbosity(libnok_context_t *ctx, libnok_log_level_t level)
{
  ctx->logctx.verbosity = level;
  return 0;
}

#if USING_OPENSSL
int
nok_log_create_in_mem_buffer(nok_log_ctx_t *ctx, BIO **inmem)
{
  *inmem = BIO_new(BIO_s_mem());
  if (*inmem == NULL)
    return -1;
  return 0;
}

BIO *
nok_log_get_in_mem_bio(nok_log_ctx_t *ctx)
{
  BIO *inmem = NULL;
  if (noka_log_create_in_mem_buffer(&inmem))
    return NULL;
  return inmem;
}
#endif /* USING_OPENSSL */

const char *
nok_log_get_verbosity_level_to_string(libnok_log_level_t level)
{
  switch (level) {
    case NOK_VERBOSITY_ERROR:
      return "error";
    case NOK_VERBOSITY_WARNING:
      return "warn";
    case NOK_VERBOSITY_NOTICE:
      return "notice";
    case NOK_VERBOSITY_INFO:
      return "info";
    case NOK_VERBOSITY_DEBUG:
      return "debug";
  }
  return "invalid";
}

int
nok_log__logmsg(nok_log_ctx_t *ctx, libnok_log_level_t level, char *filename,
                int lineno, const char *func, const char *fmt, ...)
{
  FILE *file;
  struct timespec tv;
  char date[100];
  char msg[500];
  time_t now;
  struct tm *tvs;
  const char *notime = "[no time]";
  const char *now_rep = NULL;
  const char *datefmt = "[%F %T";
  uint8_t written;
  va_list ap;

  if (ctx == NULL)
    return -1;

  if (level > ctx->verbosity)
    return 0;

  if (level < NOK_VERBOSITY_WARNING)
    file = ctx->errlog;
  else
    file = ctx->outlog;

  memset(date, 0, sizeof(date));
  memset(msg, 0, sizeof(msg));
  if (clock_gettime(CLOCK_REALTIME, &tv) == -1) {
    now = time(NULL);
    if (now == (time_t) -1) {
      strncpy(date, notime, strlen(notime));
      written = strlen(notime);
    } else {
      tvs = gmtime(&now);
      if (now_rep == NULL) {
        written = sprintf(date, "[%s] ", "no time");
      } else {
        written = strftime(date, sizeof(date), datefmt, tvs);
      }
    }
  } else {
    tvs = gmtime(&(tv.tv_sec));
    if (tvs == NULL) {
      strncpy(date, notime, strlen(notime));
      written = strlen(notime);
    }
    written = strftime(date, sizeof(date), datefmt, tvs);
    written += sprintf(date + written, ".%lu]", tv.tv_nsec);
  }
  written = nok_snprintf(msg, sizeof(msg), "%s (%s:%d) %s():\n\t[%s] ", date,
                         filename, lineno, func,
                         nok_log_get_verbosity_level_to_string(level));
  va_start(ap, fmt);
  written += vsnprintf(msg + written, sizeof(msg) - written, fmt, ap);
  va_end(ap);
  msg[written] = '\0';
  fprintf(file, "%s", msg);
  return written;
}
