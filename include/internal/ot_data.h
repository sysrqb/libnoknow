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

#ifndef NOK_OT_DATA_H
#define NOK_OT_DATA_H 1

#include <noknow.h>

typedef struct internal_transfer_context_s {
  /* The protocol we're following */
  libnok_transfer_protocol_t proto;
  /* The way we serialize the bytes */
  libnok_serialization_t peer_serial;
  /* The way we serialize the bytes */
  libnok_serialization_t ipc_serial;
  /* Our character in this game */
  libnok_player_t player;
  /* How we send and recv data from the other player */
  libnok_communication_method_t *comm;

 
#ifdef __cplusplus
}
#endif

#endif /* NOK_OT_DATA_H */
