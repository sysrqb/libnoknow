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

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/* List of supported oblivious transfer protocols */
typedef enum libnok_transfer_protocol {
  LIBNOK_UNKNOWN_XFER_PROTOCOL,
  LIBNOK_NOT_SUPPORTED_XFER_PROTOCOL
} libnok_transfer_protocol_t;

/* List of supported serialization mechanisms */
typedef enum libnok_serialization {
  LIBNOK_NO_SERIAL_METHOD,
  LIBNOK_UNKNOWN_SERIAL_METHOD,
  LIBNOK_NOT_SUPPORTED_SERIAL_METHOD
} libnok_serialization_t;

/* Choose a side, either side */
typedef enum libnok_player {
  LIBNOK_RECEIVER,
  LIBNOK_TRANSMITTER,
  LIBNOK_UNKNOWN_PLAYER
} libnok_player_t;

/* How do we transmit and receive data? */
typedef enum libnok_communication_device {
  /* Is it an open file descriptor? */
  LIBNOK_FILEDESCR_COMM,
  /* It is using callback function? */
  LIBNOK_CALLBACK_COMM,
  /* Should we establish the connection ourselves? */
  LIBNOK_INTERNAL_COMM,
  /* Unknown device */
  LIBNOK_UNKNOWN_COMM_DEV,
  /* Unsupported device */
  LIBNOK_NOT_SUPPORTED_COMM_DEV
} libnok_communication_device_t;

/* Define how we should communicate with the peer */
typedef struct libnok_communication_method_s libnok_communication_method_t;

/* Generic buffer struct */
typedef struct libnok_data_buffer_s libnok_data_buffer_t;

/* Prototype for internally-defined structure for holding state. */
typedef struct libnok_context_s libnok_context_t;

/* For the specified instance ctx, (re)define the protocol */
int libnok_set_protocol(libnok_context_t *ctx,
                        libnok_transfer_protocol_t proto);
/* For the specified instance ctx, (re)define the peer serialization method */
int libnok_set_peer_serialization(libnok_context_t *ctx,
                                  libnok_serialization_t serial);
/* For the specified instance ctx, (re)define the ipc serialization method */
int libnok_set_ipc_serialization(libnok_context_t *ctx,
                                 libnok_serialization_t serial);
/* For the specified instance ctx, (re)define which player we are */
int libnok_set_player(libnok_context_t *ctx, libnok_player_t player);
/* For the specified instance ctx, (re)define the communication medium */
int libnok_set_communication_method(libnok_context_t *ctx,
                                    libnok_communication_method_t *comm_method);
/* For the specified instance ctx, get the protocol */
libnok_transfer_protocol_t libnok_get_transfer_protocol(libnok_context_t *ctx);
/* For the specified instance ctx, get the peer serialization */
libnok_serialization_t libnok_get_peer_serialization(libnok_context_t *ctx);
/* For the specified instance ctx, get the ipc serialization */
libnok_serialization_t libnok_get_ipc_serialization(libnok_context_t *ctx);
/* For the specified instance ctx, get which player we are */
libnok_player_t libnok_get_player(libnok_context_t *ctx);
/* For the specified instance ctx, get the communication medium */
libnok_communication_method_t *
libnok_get_communication_method(libnok_context_t *ctx);
/* Create a comm method for use in initializing a context */
libnok_communication_method_t *
libnok_create_filedescr_comm_method(const int fd);
libnok_communication_method_t *
libnok_create_internal_comm_method(const char *hostname, const size_t len);
libnok_communication_method_t *
libnok_create_callback_comm_method(int (*send_cb)(const void *buf,
				                  size_t count),
                                   int (*recv_cb)(const void *buf,
				                  size_t count));
/* Create and initialize a new instance */
libnok_context_t * libnok_init(libnok_transfer_protocol_t proto,
                               libnok_serialization_t peer_serial,
                               libnok_serialization_t ipc_serial,
                               libnok_player_t player,
                               libnok_communication_method_t *comm_meth);
/* Define the set of data that should be transferred. The set, data, is
   an array of arrays of an arbitrary data size, each of size datum_size.
   This means, an application should be able to provide an array of any
   data it has, of type T, and the OT operations should succeed if
   datum_size is sizeof(T), and data has len elements. Returns -1 on error. */
int libnok_data_for_transfer(libnok_context_t *ctx, void **data,
                             size_t datum_size, size_t len);
/* Define the expected data which will be received. The bytes received
   are stored in data. The received item must be datum_size bytes. If the
   chosen protocol allows receiving more than element then len defines
   how many elements can fit in the data array. In other words, if data
   holds more than one item, then it hold items of type T, where sizeof(T)
   if datum_len, and data is an array of Ts of length len.
   The number of bytes written in *data* is returned in *wrote*. If the data
   we have for return is larger than datum_size*len then we return -1 and
   return the needed size in *wrote*. Returns -1 on error. */
int libnok_receive_data(libnok_context_t *ctx, void **data,
                        size_t datum_size, size_t len, size_t *wrote);

#ifdef __cplusplus
}
#endif
