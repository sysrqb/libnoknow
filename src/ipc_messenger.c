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

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <internal/ipc_messenger.h>
#include <internal/ipc_protocol.h>
#include <internal/nok_snprintf.h>
#include <internal/rpc.h>

/* Store formatted string in buf
 *  
 * Return the number of bytes written. On failure, return 0 and
 * buf is NULL.
 */
int
write_message_into_buffer(char **buf, const char *fmt, ...)
{
  va_list ap;
  char *msg;
  int32_t msglen = 100;
  int wrote;
  msg = (char *)calloc(msglen, sizeof(*msg));
  if (msg == NULL)
    return 0;
    
  do {
    uint32_t new_msglen;
    va_start(ap, fmt);
    /* vsnprintf() wasn't added until C99 and C++11 */
    wrote = nok_vsnprintf(msg, msglen, fmt, ap);
    va_end(ap);
    if (wrote < msglen && wrote > -1)
      break;
    if (wrote > -1)
      new_msglen = wrote + 1;
    else
      new_msglen = msglen*2;
    if (realloc(msg, new_msglen) == NULL) {
      msg[msglen-1] = '\0';
      break;
    }
    memset(msg+wrote, 0, new_msglen-msglen);
    msglen = new_msglen;
  } while (msglen < INT_MAX);
  *buf = msg;
  return wrote;
}

int
create_status(domain_status_t **status_msg, const char *msg, uint32_t msglen,
              libnok_log_level_t level)
{
  domain_status_t *status;
  status = domain_status_new();
  if (status == NULL)
    return -1;
  if (domain_status_set_verbosity(status, level) != 0)
    goto err;
  if (domain_status_set_msglen(status, msglen) != 0)
    goto err;
  if (domain_status_set_msg(status, msg) != 0)
    goto err;
  if (domain_status_check(status) != NULL)
    goto err;

  *status_msg = status;
  return 0;
err:
  domain_status_free(status);
  return -1;
}

int
create_domain_base_for_status(domain_base_t **base, domain_status_t *msg,
                              uint32_t len)
{
  domain_base_t *dom;

  dom = domain_base_new();
  if (dom == NULL)
    return -1;
  if (domain_base_set_version(dom, 0))
    goto err;
  if (domain_base_set_length(dom, len))
    goto err;
  if (domain_base_set_message_domain(dom, DOMAIN_STATUS))
    goto err;
  if (domain_base_set_domain_message_domstat(dom, msg))
    goto err;

  *base = dom;
  return 0;
err:
  domain_base_free(dom);
  return -1;
}

int
send_message(libnok_context_t *ctx)
{
  if (ctx == NULL || ctx->send_buf.data == NULL)
    return -1;
  switch (ctx->comm->dev) {
  case LIBNOK_FILEDESCR_COMM:
    return rpc_send_message_fd(ctx);
  default:
    return -1;
  }
  return 0;
}

static int
encode_message(domain_base_t *dom, uint8_t *msgout)
{
  ssize_t len;
  uint32_t domlen;
  uint8_t *msg;

  if (dom == NULL)
    return -1;

  if (domain_base_check(dom) == NULL)
    return -1;

  domlen = domain_base_get_length(dom);
  /* 1 byte version */
  domlen += 1;

  msg = (uint8_t *) calloc(domlen, sizeof(*msg));
  if (msg == NULL)
    return -1;

  do {
    len = domain_base_encode(msg, domlen, dom);
    if (len == -1) {
      free(msg);
      return -1;
    } else if (len == -2) {
      uint8_t *newmsg;
      size_t new_domlen = 2*domlen;
      newmsg = (uint8_t *) realloc(msg, new_domlen*sizeof(*msg));
      if (newmsg == NULL) {
        free(msg);
        return -1;
      }
      msg = newmsg;
      domlen = new_domlen;
    } else if (len > 1) {
      msgout = msg;
      return len;
    } else {
      return -1;
    }
  } while (len < 1);
 
  return 0;
}

int
create_and_send_status_message(libnok_context_t *ctx, libnok_log_level_t level,
                               const char *fmt, ...)
{
  char *msg;
  int msglen;
  va_list ap;
  domain_status_t *status_msg;
  domain_base_t *dom;

  va_start(ap, fmt);
  msglen = write_message_into_buffer(&msg, fmt, ap);
  va_end(ap);
  if (msglen <= 0) {
    ctx->status_msg_failure_count++;
    return -1;
  }

  if (create_status(&status_msg, msg, msglen, level)) {
    free(msg);
    ctx->status_msg_failure_count++;
    return -1;
  }
  if (create_domain_base_for_status(&dom, status_msg, /* u8 message_domain */ 1 +
                                                      /* u8 verbosity */ 1 +
                                                      /* u16 msglen */ 2 + msglen)) {
    free(msg);
    ctx->status_msg_failure_count++;
    return -1;
  }
  msglen = encode_message(dom, (uint8_t *)msg);
  if (msglen < 1) {
    ctx->status_msg_failure_count++;
    return -1;
  }
  ctx->send_buf.data = msg;
  ctx->send_buf.size = (size_t)msglen;
  ctx->send_buf.size = sizeof(*msg);
  return send_message(ctx);
}


