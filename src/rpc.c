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

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <internal/ipc_protocol.h>
#include <internal/noknow.h>
#include <internal/rpc.h>

INLINE int
get_version(int fd, int *count)
{
  char buf;
  ssize_t s;
  s = read(fd, &buf, sizeof(buf));
  if (count != NULL)
    *count = s;
  if (s > 0)
    return (int) buf;
  return -1;
}

INLINE long
get_length(int fd, int *count)
{
  char buf[4];
  ssize_t s;
  s = read(fd, buf, sizeof(*buf)*sizeof(buf));
  if (count != NULL)
    *count = s;
  if (s > 0)
    return (long) *buf;
  return -1;
}

INLINE int
get_message(int fd, char *message, uint32_t len)
{
  uint32_t offset, remains;
  ssize_t s;

  remains = len;
  offset = 0;
  do {
    s = read(fd, message + offset, remains);
    if (s > 0 && s < remains) {
      remains -= s;
      offset += s;
    } else if (s == -1) {
      return -offset;
    }
  } while (s != 0);

  if (offset == len || s == len)
      return len;
  else
    return offset;
}
    
int
rpc_read_message_fd(libnok_context_t *ctx)
{
  uint8_t msgvers;
  uint32_t msglen;
  int r, bytesread;
  char *message;
  if (ctx == NULL || ctx->comm == NULL)
    return -1;
  switch (ctx->comm->dev) {
  case LIBNOK_FILEDESCR_COMM:
    break;
  default:
    return -2;
  }

  r = get_version(ctx->comm->fd, &bytesread);
  if (r < 0 || bytesread < 1)
    return -1;
  if (bytesread != sizeof(msgvers))
    return -1;
  msgvers = (uint8_t) r;

  r = get_length(ctx->comm->fd, &bytesread);
  if (r < 0 || bytesread < 1)
    return -1;
  if (bytesread != sizeof(msglen))
    return -1;
  msglen = (uint32_t) r;

  message = (char *)malloc(sizeof(*message)*msglen);
  if (message == NULL)
    return -1;
  r = get_message(ctx->comm->fd, message, msglen);
  if (r < -1) {
    /* TODO Handle I/O error */
  } else if (((size_t)r) < msglen) {
    /* TODO truncated message */
  } else {
    assert(ctx->recv_buf == NULL);
    ctx->recv_buf->data = (void *)message;
    ctx->recv_buf->size = sizeof(*message);
    ctx->recv_buf->count = msglen;
  }
  return 0;
}

int
rpc_send_message_fd(libnok_context_t *ctx)
{
  size_t msglen;
  size_t written = 0;
  void *msg;
  if (ctx == NULL || ctx->send_buf.data == NULL)
    return -1;
  assert(ctx->comm->dev == LIBNOK_FILEDESCR_COMM);
  msg = ctx->send_buf.data;
  msglen = ctx->send_buf.size*ctx->send_buf.count;
  do {
    ssize_t written_now;
    written_now = write(ctx->comm->fd, ((char *)msg) + written, msglen - written);
    if (written_now == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        continue;
      if (errno == EPIPE)
        /* Do something smart. It died. */
        return -1;
      return -1;
    }
    written += written_now;
  } while (written < msglen);
  return 0;
}

