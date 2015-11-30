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
  return ctx;
}

int
libnok_data_for_transfer(libnok_context_t *ctx, void **data,
                         size_t datum_size, size_t len)
{
  return -1;
}

int
libnok_receive_data(libnok_context_t *ctx, void **data,
                    size_t datum_size, size_t len)
{
  return -1;
}
