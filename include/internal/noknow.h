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

#include <stddef.h>

#include <noknow.h>

/* Define how we should communicate with the peer */
struct libnok_communication_method_s {
  /* Choose a method */
  libnok_communication_device_t dev;
  /* If FILEDESCR_COMM, then define the fd */
  int fd;
  /* If INTERNAL_COMM, then define the peer's destination address */
  char *hostname;
  size_t hostname_len;
  /* If CALLBACK_COMM, then define the send and recv callbacks */
  int (*send_cb)(const void *buf, size_t count);
  int (*recv_cb)(const void *buf, size_t count);
};

/* Generic buffer struct */
struct libnok_data_buffer_s {
  /* Buffer */
  void *data;
  /* Datum length */
  size_t size;
  /* Number of *size* byte elements in *data* */
  size_t count;
}; 

/* Prototype for internally-defined structure for holding state. */
struct libnok_context_s {
  libnok_transfer_protocol_t proto;
  libnok_serialization_t peer_serial;
  libnok_serialization_t ipc_serial;
  libnok_player_t player;
  libnok_communication_method_t *comm;
  /* Our childs pid, after fork */
  int child_pid;
  /* Data queued for child */
  libnok_data_buffer_t send_buf;
  /* Data queued for read by application */
  libnok_data_buffer_t *recv_buf;
};

