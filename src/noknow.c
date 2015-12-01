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

#include <stdlib.h>
#include <string.h>

/* libnok include */
#include <noknow.h>


int
libnok_set_protocol(libnok_context_t *ctx, libnok_transfer_protocol_t proto)
{
  if (ctx == NULL)
    return -1;
  if (proto >= LIBNOK_NOT_SUPPORTED_XFER_PROTOCOL)
    return -1;
  if (proto < 0)
    return -1;
  ctx->proto = proto;
  return 0;
}

int
libnok_set_serialization(libnok_context_t *ctx,
                         libnok_serialization_t serial)
{
  if (ctx == NULL)
    return -1;
  if (serial >= LIBNOK_NOT_SUPPORTED_SERIAL_METHOD)
    return -1;
  if (serial < 0)
    return -1;
  ctx->serial = serial;
  return 0;
}

int
libnok_set_player(libnok_context_t *ctx, libnok_player_t player)
{
  if (ctx == NULL)
    return -1;
  if (player > LIBNOK_UNKNOWN_PLAYER)
    return -1;
  if (player < 0)
    return -1;
  ctx->player = player;
  return 0;
}

int
libnok_set_communication_method(libnok_context_t *ctx,
                                libnok_communication_method_t *comm_method)
{
  if (ctx == NULL)
    return -1;
  if (comm_method == NULL)
    return -1;
  if (comm_method->dev >= LIBNOK_NOT_SUPPORTED_COMM_DEV)
    return -1;
  if (comm_method->dev < 0)
    return -1;
  ctx->comm = comm_method;
  return 0;
}

libnok_transfer_protocol_t
libnok_get_transfer_protocol(libnok_context_t *ctx)
{
  if (ctx == NULL)
    return LIBNOK_UNKNOWN_XFER_PROTOCOL;
  return ctx->proto;
}

libnok_serialization_t
libnok_get_serialization(libnok_context_t *ctx)
{
  if (ctx == NULL)
    return LIBNOK_UNKNOWN_SERIAL_METHOD;
  return ctx->serial;
}

libnok_player_t
libnok_get_player(libnok_context_t *ctx)
{
  if (ctx == NULL)
    return LIBNOK_UNKNOWN_PLAYER;
  return ctx->player;
}

libnok_communication_method_t *
libnok_get_communication_method(libnok_context_t *ctx)
{
  if (ctx == NULL)
    return NULL;
  return ctx->comm;
}

libnok_communication_method_t *
libnok_create_filedescr_comm_method(const int fd)
{
  libnok_communication_method_t *comm = NULL;
  if (fd < 0)
    return NULL;
  comm = (libnok_communication_method_t *)malloc(sizeof(*comm));
  if (comm == NULL)
    return NULL;
  memset(comm, 0, sizeof(*comm));
  comm->fd = fd;
  comm->dev = LIBNOK_FILEDESCR_COMM;
  return comm;
}

libnok_communication_method_t *
libnok_create_internal_comm_method(const char *hostname, const size_t len)
{
  libnok_communication_method_t *comm = NULL;
  if (hostname == NULL)
    return NULL;
  if (len < 1)
    return NULL;
  comm = (libnok_communication_method_t *)malloc(sizeof(*comm));
  if (comm == NULL)
    return NULL;
  memset(comm, 0, sizeof(*comm));
  comm->hostname = strndup(hostname, len);
  comm->hostname_len = len;
  comm->dev = LIBNOK_INTERNAL_COMM;
  return comm;
}

libnok_communication_method_t *
libnok_create_callback_comm_method(int (*send_cb)(const void *buf,
				                  size_t count),
                                   int (*recv_cb)(const void *buf,
				                  size_t count))
{
  libnok_communication_method_t *comm = NULL;
  if (send_cb == NULL)
    return NULL;
  if (recv_cb == NULL)
    return NULL;
  comm = (libnok_communication_method_t *)malloc(sizeof(*comm));
  if (comm == NULL)
    return NULL;
  memset(comm, 0, sizeof(*comm));
  comm->send_cb = send_cb;
  comm->recv_cb = recv_cb;
  comm->dev = LIBNOK_CALLBACK_COMM;
  return comm;
}

libnok_context_t *
libnok_init(libnok_transfer_protocol_t proto,
            libnok_serialization_t serial,
            libnok_player_t player,
            libnok_communication_method_t *comm_meth)

{
  libnok_context_t *ctx = NULL;
  if (proto > LIBNOK_NOT_SUPPORTED_XFER_PROTOCOL || proto < 0)
    return NULL;
  if (serial > LIBNOK_NOT_SUPPORTED_SERIAL_METHOD || serial < 0)
    return NULL;
  if (player > LIBNOK_UNKNOWN_PLAYER || player < 0)
    return NULL;
  if (comm_meth == NULL) {
    comm_meth =
        (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
    if (comm_meth == NULL)
      return NULL;
  } else {
    if (comm_meth->dev > LIBNOK_NOT_SUPPORTED_COMM_DEV ||
        comm_meth->dev < 0)
      return NULL;
  }
  ctx = (libnok_context_t *) malloc(sizeof(*ctx));
  if (ctx == NULL)
    return NULL;
  ctx->proto = proto;
  ctx->serial = serial;
  ctx->player = player;
  ctx->comm = comm_meth;
  ctx->child_pid = -1;
  ctx->recv_buf = NULL;
  return ctx;
}

int
libnok_data_for_transfer(libnok_context_t *ctx, void **data,
                         size_t datum_size, size_t len)
{
  if (ctx == NULL)
    return -1;
  if (datum_size < 1)
    return -1;
  if (data == NULL)
    return -1;
  if (*data == NULL)
    return -1;
  if (len < 1)
    return -1;
  if (ctx->child_pid > 0) {
    /* send anything buffered and this new data */
  } else {
    if (ctx->send_buf.data != NULL) {
      /* We already have data buffered. If this occurs then maybe we
       * should queue it instead of failing, or we should overwrite
       * the current buffer. As a first pass failing seems sane-ish.
       */
      return -1;
    }
    ctx->send_buf.data = (void *)malloc(len*datum_size);
    if (ctx->send_buf.data == NULL)
      return -1;
    ctx->send_buf.size = datum_size;
    ctx->send_buf.count = len;
  }
  return 0;
}

void
get_pending_data(libnok_context_t *ctx)
{
  return;
}

int
libnok_receive_data(libnok_context_t *ctx, void **data,
                    size_t datum_size, size_t len, size_t *wrote)
{
  int size = 0;
  if (ctx == NULL)
    return -1;
  if (datum_size < 1)
    return -1;
  if (data == NULL)
    return -1;
  if (*data == NULL)
    return -1;
  if (len < 1)
    return -1;
  if (wrote == NULL)
    return -1;
  get_pending_data(ctx);
  if (ctx->recv_buf == NULL)
    return 0;
  size = ctx->recv_buf->count*ctx->recv_buf->size;
  if (ctx->recv_buf->data == NULL && size > 0)
    return -1;
  *wrote = size;
  if (size > datum_size*len)
    return -1;
  memcpy(*data, ctx->recv_buf->data, size);
  return 0;
}
