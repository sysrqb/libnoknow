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

#include <noknow.h>


int
libnok_set_protocol(libnok_context_t *ctx, libnok_transfer_protocol_t proto)
{
  return -1;
}

int
libnok_set_serialization(libnok_context_t *ctx,
                         libnok_serialization_t serial)
{
  return -1;
}

int
libnok_set_player(libnok_context_t *ctx, libnok_player_t player)
{
  return -1;
}

int
libnok_set_communication_method(libnok_context_t *ctx,
                                libnok_communication_method_t *comm_method)
{
  return -1;
}

libnok_transfer_protocol_t
libnok_get_transfer_protocol(libnok_context_t *ctx)
{
  return UNKNOWN_XFER_PROTOCOL;
}

libnok_serialization_t
libnok_get_serialization(libnok_context_t *ctx)
{
  return UNKNOWN_SERIAL_METHOD;
}

libnok_player_t
libnok_get_player(libnok_context_t *ctx)
{
  return UNKNOWN_PLAYER;
}

libnok_communication_method_t *
libnok_get_communication_method(libnok_context_t *ctx)
{
  return NULL;
}

libnok_context_t *
libnok_init(libnok_transfer_protocol_t proto,
            libnok_serialization_t serial,
            libnok_player_t player,
            libnok_communication_method_t *comm_meth)

{
  return NULL;
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
