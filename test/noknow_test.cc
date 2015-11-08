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


#include <gtest/gtest.h>
#include <noknow.h>

/* Test init() */
TEST(CtxInstantiation, CtxInit)
{
  libnok_transfer_protocol_t proto = UNKNOWN_XFER_PROTOCOL;
  libnok_serialization_t serial = UNKNOWN_SERIAL_METHOD;
  libnok_player_t player = UNKNOWN_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  ctx = libnok_init(proto, serial, player, comm_meth);
  EXPECT_EQ((libnok_context_t *)NULL, ctx);
  if (ctx != NULL)
    goto err_free;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = UNKNOWN_COMM_DEV;
  proto = (libnok_transfer_protocol_t) ((int)proto + 2);
  ctx = libnok_init(proto, serial, player, comm_meth);
  EXPECT_EQ((libnok_context_t *)NULL, ctx);
  if (ctx != NULL)
    goto err_free;
  proto = UNKNOWN_XFER_PROTOCOL;

  serial = (libnok_serialization_t) ((int)serial + 2);
  ctx = libnok_init(proto, serial, player, comm_meth);
  EXPECT_EQ((libnok_context_t *)NULL, ctx);
  if (ctx != NULL)
    goto err_free;
  serial = UNKNOWN_SERIAL_METHOD;

  player = (libnok_player_t) ((int)player + 2);
  ctx = libnok_init(proto, serial, player, comm_meth);
  EXPECT_EQ((libnok_context_t *)NULL, ctx);
  if (ctx != NULL)
    goto err_free;
  player = UNKNOWN_PLAYER;

  comm_meth->dev =
    (libnok_communication_device_t) ((int)comm_meth->dev + 2);
  ctx = libnok_init(proto, serial, player, comm_meth);
  EXPECT_EQ((libnok_context_t *)NULL, ctx);
  if (ctx != NULL)
    goto err_free;
  comm_meth->dev = UNKNOWN_COMM_DEV;

  ctx = libnok_init(proto, serial, player, comm_meth);
  ASSERT_NE((libnok_context_t *)NULL, ctx);

err_free:
  free(ctx);
}

/* Test set_protoco() */
TEST(CtxInstantiation, SetProtocol)
{
  libnok_transfer_protocol_t proto = UNKNOWN_XFER_PROTOCOL;
  libnok_serialization_t serial = UNKNOWN_SERIAL_METHOD;
  libnok_player_t player = UNKNOWN_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = UNKNOWN_COMM_DEV;
  ctx = libnok_init(proto, serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  EXPECT_EQ(-1, libnok_set_protocol(NULL, proto));
  proto = (libnok_transfer_protocol_t) ((int)proto + 2);
  EXPECT_EQ(-1, libnok_set_protocol(NULL, proto));
  EXPECT_EQ(-1, libnok_set_protocol(ctx, proto));
  proto = (libnok_transfer_protocol_t) ((int)proto - 1);
  EXPECT_EQ(-1, libnok_set_protocol(ctx, proto));
  proto = UNKNOWN_XFER_PROTOCOL;
  EXPECT_EQ(0, libnok_set_protocol(ctx, proto));

err_free:
  free(comm_meth);
  free(ctx);
}

/* Test set_serialization() */
TEST(CtxInstantiation, SetSerialization)
{
  libnok_transfer_protocol_t proto = UNKNOWN_XFER_PROTOCOL;
  libnok_serialization_t serial = UNKNOWN_SERIAL_METHOD;
  libnok_player_t player = UNKNOWN_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = UNKNOWN_COMM_DEV;
  ctx = libnok_init(proto, serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  EXPECT_EQ(-1, libnok_set_serialization(NULL, serial));
  serial = (libnok_serialization_t) ((int)serial + 2);
  EXPECT_EQ(-1, libnok_set_serialization(NULL, serial));
  EXPECT_EQ(-1, libnok_set_serialization(ctx, serial));
  serial = (libnok_serialization_t) ((int)serial - 1);
  EXPECT_EQ(-1, libnok_set_serialization(ctx, serial));
  serial = UNKNOWN_SERIAL_METHOD;
  EXPECT_EQ(0, libnok_set_serialization(ctx, serial));

err_free:
  free(comm_meth);
  free(ctx);
}

/* Test set_player() */
TEST(CtxInstantiation, SetPlayer)
{
  libnok_transfer_protocol_t proto = UNKNOWN_XFER_PROTOCOL;
  libnok_serialization_t serial = UNKNOWN_SERIAL_METHOD;
  libnok_player_t player = UNKNOWN_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = UNKNOWN_COMM_DEV;
  ctx = libnok_init(proto, serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  EXPECT_EQ(-1, libnok_set_player(NULL, player));
  player = (libnok_player_t) ((int)player + 2);
  EXPECT_EQ(-1, libnok_set_player(NULL, player));
  EXPECT_EQ(-1, libnok_set_player(ctx, player));
  player = (libnok_player_t) ((int)player - 1);
  EXPECT_EQ(-1, libnok_set_player(ctx, player));
  player = UNKNOWN_PLAYER;
  EXPECT_EQ(0, libnok_set_player(ctx, player));

err_free:
  free(comm_meth);
  free(ctx);
}

/* Test set_communication_method() */
TEST(CtxInstantiation, SetCommMethod)
{
  libnok_transfer_protocol_t proto = UNKNOWN_XFER_PROTOCOL;
  libnok_serialization_t serial = UNKNOWN_SERIAL_METHOD;
  libnok_player_t player = UNKNOWN_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = UNKNOWN_COMM_DEV;
  ctx = libnok_init(proto, serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

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
  comm_meth->dev = UNKNOWN_COMM_DEV;
  EXPECT_EQ(0, libnok_set_communication_method(ctx, comm_meth));

err_free:
  free(comm_meth);
  free(ctx);
}

/* Test get_transfer_protocol() */
TEST(CtxInstantiation, GetProtocol)
{
  libnok_transfer_protocol_t proto = UNKNOWN_XFER_PROTOCOL;
  libnok_serialization_t serial = UNKNOWN_SERIAL_METHOD;
  libnok_player_t player = UNKNOWN_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = UNKNOWN_COMM_DEV;
  ctx = libnok_init(proto, serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  EXPECT_EQ(-1, libnok_get_transfer_protocol(NULL));
  EXPECT_EQ(proto, libnok_get_transfer_protocol(ctx));
  EXPECT_EQ(0, libnok_set_protocol(ctx, proto));
  EXPECT_EQ(proto, libnok_get_transfer_protocol(ctx));

err_free:
  free(comm_meth);
  free(ctx);
}

/* Test get_serialization() */
TEST(CtxInstantiation, GetSerialization)
{
  libnok_transfer_protocol_t proto = UNKNOWN_XFER_PROTOCOL;
  libnok_serialization_t serial = UNKNOWN_SERIAL_METHOD;
  libnok_player_t player = UNKNOWN_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = UNKNOWN_COMM_DEV;
  ctx = libnok_init(proto, serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  EXPECT_EQ(-1, libnok_get_serialization(NULL));
  EXPECT_EQ(serial, libnok_get_serialization(ctx));
  EXPECT_EQ(0, libnok_set_serialization(ctx, serial));
  EXPECT_EQ(serial, libnok_get_serialization(ctx));

err_free:
  free(comm_meth);
  free(ctx);
}

/* Test get_player() */
TEST(CtxInstantiation, GetPlayer)
{
  libnok_transfer_protocol_t proto = UNKNOWN_XFER_PROTOCOL;
  libnok_serialization_t serial = UNKNOWN_SERIAL_METHOD;
  libnok_player_t player = UNKNOWN_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = UNKNOWN_COMM_DEV;
  ctx = libnok_init(proto, serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  EXPECT_EQ(-1, libnok_get_player(NULL));
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
  libnok_transfer_protocol_t proto = UNKNOWN_XFER_PROTOCOL;
  libnok_serialization_t serial = UNKNOWN_SERIAL_METHOD;
  libnok_player_t player = UNKNOWN_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = UNKNOWN_COMM_DEV;
  ctx = libnok_init(proto, serial, player, comm_meth);
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

/* Test data_for_transfer() */
TEST(CtxData, ForTransfer)
{
  libnok_transfer_protocol_t proto = UNKNOWN_XFER_PROTOCOL;
  libnok_serialization_t serial = UNKNOWN_SERIAL_METHOD;
  libnok_player_t player = UNKNOWN_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;
  char *data = NULL, **pdata = NULL;
  size_t datum_size = 0, len = 0;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = UNKNOWN_COMM_DEV;
  ctx = libnok_init(proto, serial, player, comm_meth);
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
  libnok_transfer_protocol_t proto = UNKNOWN_XFER_PROTOCOL;
  libnok_serialization_t serial = UNKNOWN_SERIAL_METHOD;
  libnok_player_t player = UNKNOWN_PLAYER;
  libnok_communication_method_t *comm_meth = NULL;
  libnok_context_t *ctx = NULL;
  char *data = NULL, **pdata = NULL;
  size_t datum_size = 0, len = 0;

  comm_meth =
      (libnok_communication_method_t *) malloc(sizeof(*comm_meth));
  ASSERT_NE((libnok_communication_method_t *)NULL, comm_meth);
  comm_meth->dev = UNKNOWN_COMM_DEV;
  ctx = libnok_init(proto, serial, player, comm_meth);
  EXPECT_NE((libnok_context_t *)NULL, ctx);
  if (ctx == NULL)
    goto err_free;

  EXPECT_EQ(-1, libnok_receive_data(NULL, (void **)pdata, datum_size, len));
  EXPECT_EQ(-1, libnok_receive_data(ctx, (void **)pdata, datum_size, len));
  pdata = &data;
  EXPECT_EQ(-1, libnok_receive_data(ctx, (void **)pdata, datum_size, len));
  datum_size = sizeof(*data);
  len = 2;
  EXPECT_EQ(-1, libnok_receive_data(ctx, (void **)pdata, datum_size, len));
  data = (char *)malloc(datum_size*len);
  EXPECT_NE((char *)NULL, data);
  if (data == NULL)
    goto err_free;
  EXPECT_EQ(0, libnok_receive_data(ctx, (void **)pdata, datum_size, len));

err_free:
  free(comm_meth);
  free(ctx);
}
