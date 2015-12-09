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

#include <gtest/gtest.h>

/* We need these defs, too */
#include <internal/noknow.h>

/* Test init() */
TEST(CtxInstantiation, CtxInit)
{
  libnok_transfer_protocol_t proto = LIBNOK_NOT_DEFINED_XFER_PROTOCOL;
  libnok_serialization_t peer_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_serialization_t ipc_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_player_t player = LIBNOK_NOT_DEFINED_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  ASSERT_NE((libnok_context_t *)NULL, ctx);
  EXPECT_NE((libnok_communication_method_t *)NULL, ctx->comm);
  free(ctx->comm);
  free(ctx);

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = LIBNOK_NOT_DEFINED_COMM_DEV;
  proto = (libnok_transfer_protocol_t) ((int)proto + 2);
  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  EXPECT_EQ((libnok_context_t *)NULL, ctx);
  if (ctx != NULL)
    goto err_free;
  proto = LIBNOK_NOT_DEFINED_XFER_PROTOCOL;

  peer_serial = (libnok_serialization_t) ((int)peer_serial + 3);
  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  EXPECT_EQ((libnok_context_t *)NULL, ctx);
  if (ctx != NULL)
    goto err_free;
  peer_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;

  ipc_serial = (libnok_serialization_t) ((int)ipc_serial + 3);
  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  EXPECT_EQ((libnok_context_t *)NULL, ctx);
  if (ctx != NULL)
    goto err_free;
  ipc_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;

  player = (libnok_player_t) ((int)player + 2);
  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  EXPECT_EQ((libnok_context_t *)NULL, ctx);
  if (ctx != NULL)
    goto err_free;
  player = LIBNOK_NOT_DEFINED_PLAYER;

  comm_meth->dev =
    (libnok_communication_device_t) ((int)comm_meth->dev + 5);
  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  EXPECT_EQ((libnok_context_t *)NULL, ctx);
  if (ctx != NULL)
    goto err_free;
  comm_meth->dev = LIBNOK_NOT_DEFINED_COMM_DEV;

  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  ASSERT_NE((libnok_context_t *)NULL, ctx);

err_free:
  free(ctx);
}

/* Test set_protoco() */
TEST(CtxInstantiation, SetProtocol)
{
  libnok_transfer_protocol_t proto = LIBNOK_NOT_DEFINED_XFER_PROTOCOL;
  libnok_serialization_t peer_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_serialization_t ipc_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_player_t player = LIBNOK_NOT_DEFINED_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = LIBNOK_NOT_DEFINED_COMM_DEV;
  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  EXPECT_EQ(-1, libnok_set_protocol(NULL, proto));
  proto = (libnok_transfer_protocol_t) ((int)proto + 2);
  EXPECT_EQ(-1, libnok_set_protocol(NULL, proto));
  EXPECT_EQ(-1, libnok_set_protocol(ctx, proto));
  proto = (libnok_transfer_protocol_t) ((int)proto - 1);
  EXPECT_EQ(-1, libnok_set_protocol(ctx, proto));
  proto = LIBNOK_NOT_DEFINED_XFER_PROTOCOL;
  EXPECT_EQ(0, libnok_set_protocol(ctx, proto));

err_free:
  free(comm_meth);
  free(ctx);
}

/* Test set_*_serialization() */
TEST(CtxInstantiation, SetSerialization)
{
  libnok_transfer_protocol_t proto = LIBNOK_NOT_DEFINED_XFER_PROTOCOL;
  libnok_serialization_t peer_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_serialization_t ipc_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_player_t player = LIBNOK_NOT_DEFINED_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = LIBNOK_NOT_DEFINED_COMM_DEV;
  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  peer_serial = LIBNOK_NOT_SUPPORTED_SERIAL_METHOD;
  EXPECT_EQ(-1, libnok_set_peer_serialization(NULL, peer_serial));
  peer_serial = (libnok_serialization_t) ((int)peer_serial + 2);
  EXPECT_EQ(-1, libnok_set_peer_serialization(NULL, peer_serial));
  EXPECT_EQ(-1, libnok_set_peer_serialization(ctx, peer_serial));
  peer_serial = (libnok_serialization_t) ((int)peer_serial - 1);
  EXPECT_EQ(-1, libnok_set_peer_serialization(ctx, peer_serial));
  peer_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  EXPECT_EQ(0, libnok_set_peer_serialization(ctx, peer_serial));
  EXPECT_EQ(peer_serial, libnok_get_peer_serialization(ctx));

  ipc_serial = LIBNOK_NOT_SUPPORTED_SERIAL_METHOD;
  EXPECT_EQ(-1, libnok_set_ipc_serialization(NULL, ipc_serial));
  ipc_serial = (libnok_serialization_t) ((int)ipc_serial + 2);
  EXPECT_EQ(-1, libnok_set_ipc_serialization(NULL, ipc_serial));
  EXPECT_EQ(-1, libnok_set_ipc_serialization(ctx, ipc_serial));
  ipc_serial = (libnok_serialization_t) ((int)ipc_serial - 1);
  EXPECT_EQ(-1, libnok_set_ipc_serialization(ctx, ipc_serial));
  ipc_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  EXPECT_EQ(0, libnok_set_ipc_serialization(ctx, ipc_serial));
  EXPECT_EQ(ipc_serial, libnok_get_ipc_serialization(ctx));

err_free:
  free(comm_meth);
  free(ctx);
}

/* Test set_player() */
TEST(CtxInstantiation, SetPlayer)
{
  libnok_transfer_protocol_t proto = LIBNOK_NOT_DEFINED_XFER_PROTOCOL;
  libnok_serialization_t peer_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_serialization_t ipc_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_player_t player = LIBNOK_NOT_DEFINED_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = LIBNOK_NOT_DEFINED_COMM_DEV;
  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  EXPECT_EQ(-1, libnok_set_player(NULL, player));
  player = (libnok_player_t) ((int)player + 2);
  EXPECT_EQ(-1, libnok_set_player(NULL, player));
  EXPECT_EQ(-1, libnok_set_player(ctx, player));
  player = (libnok_player_t) ((int)player - 1);
  EXPECT_EQ(-1, libnok_set_player(ctx, player));
  player = LIBNOK_NOT_DEFINED_PLAYER;
  EXPECT_EQ(0, libnok_set_player(ctx, player));

err_free:
  free(comm_meth);
  free(ctx);
}

/* Test set_communication_method() */
TEST(CtxInstantiation, SetCommMethod)
{
  libnok_transfer_protocol_t proto = LIBNOK_NOT_DEFINED_XFER_PROTOCOL;
  libnok_serialization_t peer_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_serialization_t ipc_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_player_t player = LIBNOK_NOT_DEFINED_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = LIBNOK_NOT_DEFINED_COMM_DEV;
  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  comm_meth->dev = LIBNOK_NOT_SUPPORTED_COMM_DEV;
  EXPECT_EQ(-1, libnok_set_communication_method(NULL, comm_meth));
  comm_meth->dev =
    (libnok_communication_device_t) ((int)comm_meth->dev + 2);
  EXPECT_EQ(-1, libnok_set_communication_method(NULL, comm_meth));
  EXPECT_EQ(-1, libnok_set_communication_method(NULL, NULL));
  EXPECT_EQ(-1, libnok_set_communication_method(ctx, NULL));
  EXPECT_EQ(-1, libnok_set_communication_method(ctx, comm_meth));
  comm_meth->dev =
    (libnok_communication_device_t) ((int)comm_meth->dev - 1);
  EXPECT_EQ(-1, libnok_set_communication_method(ctx, comm_meth));
  comm_meth->dev = LIBNOK_NOT_DEFINED_COMM_DEV;
  EXPECT_EQ(0, libnok_set_communication_method(ctx, comm_meth));

err_free:
  free(comm_meth);
  free(ctx);
}

/* Test get_transfer_protocol() */
TEST(CtxInstantiation, GetProtocol)
{
  libnok_transfer_protocol_t proto = LIBNOK_NOT_DEFINED_XFER_PROTOCOL;
  libnok_serialization_t peer_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_serialization_t ipc_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_player_t player = LIBNOK_NOT_DEFINED_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = LIBNOK_NOT_DEFINED_COMM_DEV;
  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  EXPECT_EQ(LIBNOK_NOT_DEFINED_XFER_PROTOCOL,
            libnok_get_transfer_protocol(NULL));
  EXPECT_EQ(proto, libnok_get_transfer_protocol(ctx));
  EXPECT_EQ(0, libnok_set_protocol(ctx, proto));
  EXPECT_EQ(proto, libnok_get_transfer_protocol(ctx));

err_free:
  free(comm_meth);
  free(ctx);
}

/* Test get_*_serialization() */
TEST(CtxInstantiation, GetSerialization)
{
  libnok_transfer_protocol_t proto = LIBNOK_NOT_DEFINED_XFER_PROTOCOL;
  libnok_serialization_t peer_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_serialization_t ipc_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_player_t player = LIBNOK_NOT_DEFINED_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = LIBNOK_NOT_DEFINED_COMM_DEV;
  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  EXPECT_EQ(LIBNOK_NOT_DEFINED_SERIAL_METHOD, libnok_get_peer_serialization(NULL));
  EXPECT_EQ(peer_serial, libnok_get_peer_serialization(ctx));
  EXPECT_EQ(0, libnok_set_peer_serialization(ctx, peer_serial));
  EXPECT_EQ(peer_serial, libnok_get_peer_serialization(ctx));

  EXPECT_EQ(LIBNOK_NOT_DEFINED_SERIAL_METHOD, libnok_get_ipc_serialization(NULL));
  EXPECT_EQ(ipc_serial, libnok_get_ipc_serialization(ctx));
  EXPECT_EQ(0, libnok_set_ipc_serialization(ctx, ipc_serial));
  EXPECT_EQ(ipc_serial, libnok_get_ipc_serialization(ctx));

err_free:
  free(comm_meth);
  free(ctx);
}

/* Test get_player() */
TEST(CtxInstantiation, GetPlayer)
{
  libnok_transfer_protocol_t proto = LIBNOK_NOT_DEFINED_XFER_PROTOCOL;
  libnok_serialization_t peer_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_serialization_t ipc_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_player_t player = LIBNOK_NOT_DEFINED_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = LIBNOK_NOT_DEFINED_COMM_DEV;
  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  EXPECT_EQ(LIBNOK_NOT_DEFINED_PLAYER, libnok_get_player(NULL));
  EXPECT_EQ(player, libnok_get_player(ctx));
  EXPECT_EQ(0, libnok_set_player(ctx, player));
  EXPECT_EQ(player, libnok_get_player(ctx));

err_free:
  free(comm_meth);
  free(ctx);
}

/* Test get_communication_method() */
TEST(CtxInstantiation, GetCommMethod)
{
  libnok_transfer_protocol_t proto = LIBNOK_NOT_DEFINED_XFER_PROTOCOL;
  libnok_serialization_t peer_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_serialization_t ipc_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_player_t player = LIBNOK_NOT_DEFINED_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = LIBNOK_NOT_DEFINED_COMM_DEV;
  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  EXPECT_EQ((libnok_communication_method_t *)NULL,
            libnok_get_communication_method(NULL));
  EXPECT_EQ(comm_meth, libnok_get_communication_method(ctx));
  EXPECT_EQ(0, libnok_set_communication_method(ctx, comm_meth));
  EXPECT_EQ(comm_meth, libnok_get_communication_method(ctx));

err_free:
  free(comm_meth);
  free(ctx);
}

static int
test_send_cb(const void *buf, size_t count)
{
  if (count < 1)
    return -1;
  return count;
}

static int
test_recv_cb(const void *buf, size_t count)
{
  if (count < 1)
    return -1;
  return count;
}

/* Test create_*_comm_method() */
TEST(CtxInstantiation, CreateCommMethod)
{
  libnok_communication_method_t *comm_meth = NULL;
  int fd;
  const char *hostname = "hostname";

  fd = -1;
  comm_meth = libnok_create_filedescr_comm_method(fd);
  EXPECT_EQ((libnok_communication_method_t *)NULL, comm_meth);
  if (comm_meth != NULL)
    free(comm_meth);
  fd = 1;
  comm_meth = libnok_create_filedescr_comm_method(fd);
  EXPECT_NE((libnok_communication_method_t *)NULL, comm_meth);
  EXPECT_EQ(LIBNOK_FILEDESCR_COMM, comm_meth->dev);
  EXPECT_EQ(fd, comm_meth->fd);
  free(comm_meth);

  comm_meth = libnok_create_internal_comm_method(NULL, strlen(hostname));
  EXPECT_EQ((libnok_communication_method_t *)NULL, comm_meth);
  if (comm_meth != NULL)
    free(comm_meth);
  comm_meth = libnok_create_internal_comm_method(hostname, 0);
  EXPECT_EQ((libnok_communication_method_t *)NULL, comm_meth);
  if (comm_meth != NULL)
    free(comm_meth);
  comm_meth = libnok_create_internal_comm_method(hostname, strlen(hostname));
  EXPECT_NE((libnok_communication_method_t *)NULL, comm_meth);
  if (comm_meth != NULL) {
    EXPECT_EQ(LIBNOK_INTERNAL_COMM, comm_meth->dev);
    EXPECT_EQ(strlen(hostname), comm_meth->hostname_len);
    EXPECT_STREQ(hostname, comm_meth->hostname);
  }
  free(comm_meth);

  comm_meth = libnok_create_callback_comm_method(NULL, NULL);
  EXPECT_EQ((libnok_communication_method_t *)NULL, comm_meth);
  if (comm_meth != NULL)
    free(comm_meth);
  comm_meth = libnok_create_callback_comm_method(&test_send_cb, NULL);
  EXPECT_EQ((libnok_communication_method_t *)NULL, comm_meth);
  if (comm_meth != NULL)
    free(comm_meth);
  comm_meth = libnok_create_callback_comm_method(NULL, &test_recv_cb);
  EXPECT_EQ((libnok_communication_method_t *)NULL, comm_meth);
  if (comm_meth != NULL)
    free(comm_meth);
  comm_meth = libnok_create_callback_comm_method(&test_send_cb, &test_recv_cb);
  EXPECT_NE((libnok_communication_method_t *)NULL, comm_meth);
  if (comm_meth != NULL) {
    EXPECT_EQ(LIBNOK_CALLBACK_COMM, comm_meth->dev);
    EXPECT_NE((void *)NULL, comm_meth->send_cb);
    EXPECT_NE((void *)NULL, comm_meth->recv_cb);
  }
  free(comm_meth);
}

/* Test data_for_transfer() */
TEST(CtxData, ForTransfer)
{
  libnok_transfer_protocol_t proto = LIBNOK_NOT_DEFINED_XFER_PROTOCOL;
  libnok_serialization_t peer_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_serialization_t ipc_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_player_t player = LIBNOK_NOT_DEFINED_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;
  char *data = NULL, **pdata = NULL;
  size_t datum_size = 0, len = 0;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = LIBNOK_NOT_DEFINED_COMM_DEV;
  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  EXPECT_EQ(-1, libnok_data_for_transfer(NULL, (void **)pdata,
                                         datum_size, len));
  EXPECT_EQ(-1, libnok_data_for_transfer(ctx, (void **)pdata,
                                         datum_size, len));
  pdata = &data;
  EXPECT_EQ(-1, libnok_data_for_transfer(ctx, (void **)pdata,
                                         datum_size, len));
  datum_size = sizeof(*data);
  len = 2;
  EXPECT_EQ(-1, libnok_data_for_transfer(ctx, (void **)pdata,
                                         datum_size, len));
  data = (char *)malloc(datum_size*len);
  EXPECT_NE((char *)NULL, data);
  if (data == NULL)
    goto err_free;
  EXPECT_EQ(0, libnok_data_for_transfer(ctx, (void **)pdata,
                                        datum_size, len));

err_free:
  free(comm_meth);
  free(ctx);
}

/* Test receive_data() */
TEST(CtxData, Receive)
{
  libnok_transfer_protocol_t proto = LIBNOK_NOT_DEFINED_XFER_PROTOCOL;
  libnok_serialization_t peer_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_serialization_t ipc_serial = LIBNOK_NOT_DEFINED_SERIAL_METHOD;
  libnok_player_t player = LIBNOK_NOT_DEFINED_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;
  char *data = NULL, **pdata = NULL;
  size_t datum_size = 0, len = 0;
  size_t wrote = 0;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = LIBNOK_NOT_DEFINED_COMM_DEV;
  ctx = libnok_init(proto, peer_serial, ipc_serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  EXPECT_EQ(-1, libnok_receive_data(NULL, (void **)pdata,
                                    datum_size, len, &wrote));
  EXPECT_EQ(-1, libnok_receive_data(ctx, (void **)pdata,
                                    datum_size, len, &wrote));
  EXPECT_EQ(-1, libnok_receive_data(ctx, (void **)pdata,
                                    datum_size, len, NULL));
  pdata = &data;
  EXPECT_EQ(-1, libnok_receive_data(ctx, (void **)pdata,
                                    datum_size, len, &wrote));
  datum_size = sizeof(*data);
  len = 2;
  EXPECT_EQ(-1, libnok_receive_data(ctx, (void **)pdata,
                                    datum_size, len, &wrote));
  data = (char *)malloc(datum_size*len);
  EXPECT_NE((char *)NULL, data);
  if (data == NULL)
    goto err_free;
  EXPECT_EQ(0, libnok_receive_data(ctx, (void **)pdata,
                                   datum_size, len, &wrote));

err_free:
  free(comm_meth);
  free(ctx);
}
