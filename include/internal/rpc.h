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

/* Read and write RPCs. TODO, spawn rpc thread */

#ifndef NOK_RPC_H
#define NOK_RPC_H 1

#include <stdint.h>

#include <internal/noknow.h>

#ifdef __cplusplus
extern "C" {
#endif

int 
__attribute__ ((visibility("hidden")))
rpc_read_message_fd(libnok_context_t *ctx);
int
__attribute__ ((visibility("hidden")))
rpc_send_message_fd(libnok_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* NOK_RPC_H */
