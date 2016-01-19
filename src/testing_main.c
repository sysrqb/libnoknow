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

#include <assert.h>
#include <endian.h>
#include <stdio.h>
#include "egl85.h"
#include "log.h"

int
run_egl85()
{
  egl85_ctx_t shared, *pshared;
  egl85_sender_ctx_t sender;
  egl85_receiver_ctx_t receiver;
  unsigned char *q = NULL/*, *message = NULL*/;
  uint32_t q_len, msg_len, message;
  BIGNUM *msg0, *msg1, *msg;
  /*int padding = RSA_PKCS1_OAEP_PADDING;*/
  int padding = RSA_NO_PADDING;
  int destiny = 1;

  pshared = &shared;
  msg0 = BN_new();
  msg1 = BN_new();
  msg = BN_new();

  if (setup_shared_values(&shared, padding, destiny)) {
    toyot_log_logmsg(ERROR, "setup_shared_values() failed\n");
    goto err;
  }
  if (setup_sender(&sender, pshared)) {
    toyot_log_logmsg(ERROR, "setup_sender() failed\n");
    goto err;
  }
  if (setup_receiver(&receiver, pshared)) {
    toyot_log_logmsg(ERROR, "setup_receiver() failed\n");
    goto err;
  }

  if (receiver_select_1_out_2(&receiver, &q, &q_len)) {
    toyot_log_logmsg(ERROR, "receiver_select_1_out_2() failed\n");
    goto err;
  }
  if (sender_compute_1_out_2(&sender, q, q_len)) {
    toyot_log_logmsg(ERROR, "sender_compute_1_out_2() failed\n");
    goto err;
  }
  if (sender_encode_ot_message(&sender, msg0, msg1)) {
    toyot_log_logmsg(ERROR, "sender_encode_ot_message() failed\n");
    goto err;
  }

  if (receiver_recover_message(&receiver, msg0, msg1, msg)) {
    toyot_log_logmsg(ERROR, "receiver_recover_message() failed\n");
    goto err;
  }
  msg_len = BN_num_bytes(msg);
  if (sizeof(message) < msg_len) {
    toyot_log_logmsg(ERROR, "msg (%d) is larger than message (%d)\n",
                            msg_len, sizeof(message));
    goto err;
  }
  /*message = malloc(sizeof(*message)*msg_len);
  if (message == NULL) {
    toyot_log_logmsg(ERROR, "Allocating memory for message failed\n");
    goto err;
  }*/
    
  BN_bn2bin(msg, (unsigned char *)&message);
  toyot_log_logmsg(INFO, "Receiver recovered message '%s' (%x)\n",
                         (unsigned char *)message, message);

  if (destroy_receiver(&receiver)) {
    toyot_log_logmsg(ERROR, "destroy_receiver() failed\n");
    goto err;
  }
  if (destroy_sender(&sender)) {
    toyot_log_logmsg(ERROR, "destroy_sender() failed\n");
    goto err;
  }
  if (destroy_shared_values(pshared)) {
    toyot_log_logmsg(ERROR, "destroy_shared_values() failed\n");
    goto err;
  }

  free(q);
  return 0;

err:
  if (q)
    free(q);
  return -1;
  
}

int
main(int argc, char *argv[])
{
  FILE *outlog = NULL, *errlog = NULL;
  outlog = stdout;
  errlog = stderr;
  ERR_load_crypto_strings();

  toyot_log_set_logs(outlog, errlog);
  toyot_log_set_log_verbosity(INFO);
  return run_egl85();
}

