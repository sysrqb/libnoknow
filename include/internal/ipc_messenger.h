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

#ifndef NOK_IPC_MESSENGER_H
#define NOK_IPC_MESSENGER_H 1

#include <stdarg.h>
#include <stdio.h>

#include <noknow.h>
#include <internal/ipc_protocol.h>
#include <internal/noknow.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 0: Message type not defined
 * 1: Control message
 * 2: Protocol message
 * 4: Status messsage
 * ....
 *
 * Same mapping as in ipc_protocol.h
 */

typedef enum ipc_domain_e {
  IPC_DOMAIN_NOT_DEF,
  IPC_DOMAIN_CONTROL,
  IPC_DOMAIN_PROTOCOL,
  IPC_DOMAIN_STATUS = 4,
} ipc_domain_t;

/**
 *
 */
int
__attribute__ ((visibility("hidden")))
send_message(libnok_context_t *ctx);
/*INLINE int
__attribute__ ((visibility("hidden")))
create_and_send_control_message(libnok_context_t *ctx, const char *msg)
{
  return create_and_send_message(ctx, IPC_DOMAIN_CONTROL, msg);
}
INLINE int
__attribute__ ((visibility("hidden")))
create_and_send_protocol_message(libnok_context_t *ctx, const char *msg)
{
  return create_and_send_message(ctx, IPC_DOMAIN_PROTOCOL, msg);
}
*/
int
__attribute__ ((visibility("hidden"),format(printf,3,4)))
create_and_send_status_message(libnok_context_t *ctx, libnok_log_level_t level,
                               const char *fmt, ...);
int
__attribute__ ((visibility("hidden"),format(printf,3,4)))
emit_status_message(libnok_context_t *ctx, libnok_log_level_t level,
                    const char *fmt, ...)
{
  int r;
  va_list ap;
  va_start(ap, fmt);
  r = create_and_send_status_message(ctx, level, fmt, ap);
  va_end(ap);
  return r;
}
#ifdef __cplusplus
}
#endif

#endif /* NOK_IPC_MESSENGER_H */
