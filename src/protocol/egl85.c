#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "egl85.h"
#include "log.h"

static const int
generate_new_key(RSA **key)
{
  *key = RSA_generate_key(384, 17, NULL, NULL);
  return 0;
}

static char *
get_bn_string(BIGNUM *bn, uint32_t *retlen)
{
  static char *bn_val = NULL;
  static uint32_t bn_val_len = 512;
  char *internal_buf;
  uint32_t internal_buf_len = 0;
  uint32_t retval = 0;
  BIO *inmem = toyot_log_get_in_mem_bio();
  if (inmem == NULL) {
    return "<unknown>";
  }

  if (retlen == NULL)
    retlen = &retval;

  BN_print(inmem, bn);
  internal_buf_len = BIO_get_mem_data(inmem, &internal_buf);
  if (bn_val == NULL) {
    if ((internal_buf_len + 1) > bn_val_len)
      bn_val_len = internal_buf_len;
    bn_val = malloc(sizeof(*bn_val)*(bn_val_len + 1));
    if (bn_val == NULL) {
      return "<unknown>";
    }
  } else {
    uint32_t prev_size = 0;
    if ((internal_buf_len + 1) > bn_val_len) {
      prev_size = bn_val_len;
      bn_val_len = internal_buf_len;
    }
    bn_val = realloc(bn_val, bn_val_len);
    memset(bn_val + prev_size, 0, bn_val_len - prev_size);
  }
  memset(bn_val, 0, bn_val_len + 1);
  memcpy(bn_val, internal_buf, internal_buf_len);
  
  BIO_free(inmem);
  *retlen = bn_val_len;

  return bn_val;
}

char *
get_bn_string_r(BIGNUM *bn, uint32_t *retlen, char **str)
{
  uint32_t retval = 0;
  if (retlen == NULL)
    retlen = &retval;
  char *bn_str = get_bn_string(bn, retlen);
  if (*str == NULL) {
    *str = malloc(sizeof(*str)*(*retlen) + 1);
    if (*str == NULL) {
      return NULL;
    }
  }
  memset(*str, 0, *retlen + 1);
  strncpy(*str, bn_str, *retlen);
  return *str;
}

const int
copy_pub_key(RSA *priv, RSA *pub)
{
  pub->engine = priv->engine;
  pub->n = BN_dup(priv->n);
  if (pub->n == NULL) {
    toyot_log_logmsg(ERROR, "Duplicating priv->n failed\n");
    goto err;
  }
  pub->e = BN_dup(priv->e);
  if (pub->e == NULL) {
    toyot_log_logmsg(ERROR, "Duplicating priv->e failed\n");
    goto err;
  }

  return 0;
err:
  return -1;
}

const int
uncopy_pub_key(RSA *pub)
{
  pub->engine = NULL;
  return 0;
}

const int
get_random_from_dev(size_t len, unsigned char *rand)
{
  int file;
  file = open("/dev/urandom", O_RDONLY);
  if (file == -1) {
    toyot_log_logmsg(ERROR, "Failed while opening urandom\n");
    goto err;
  }
  if (read(file, rand, len) != len) {
    toyot_log_logmsg(ERROR, "We didn't read %d bytes from urandom\n", len);
    goto err;
  }
  close(file);

  return 0;
err:
  if (file)
    close(file);
  return -1;
}

const int
get_random(size_t len, unsigned char *rand)
{
  static uint8_t seeded = 0;

  if (!seeded) {
    unsigned char seed[64];
    if (get_random_from_dev(sizeof(seed), seed))
      return -1;
    RAND_seed(seed, sizeof(seed));
    seeded = 1;
  }

  return RAND_bytes(rand, len) ? -1 : 0;
}

const int
choose_bit()
{
  uint8_t byte;
  get_random(sizeof(byte), &byte);
  return byte & 0x01;
}

const int
setup_shared_values(egl85_ctx_t *shared, int padding, int destiny)
{
  uint32_t rand;
  shared->m0 = BN_new();
  shared->m1 = BN_new();
  shared->rsa_padding = padding;
  shared->destiny = destiny;
  shared->s = 0;
  if (shared->destiny)
    shared->s = choose_bit();
  toyot_log_logmsg(INFO, "Destiny mode is %s\n",
                         shared->destiny ? "enabled" : "disabled");

  get_random(sizeof(rand), (unsigned char *)&(rand));
  rand = htobe32(rand);
  shared->m0 = BN_bin2bn((unsigned char *)&rand, sizeof(rand), shared->m0);
  if (shared->m0 == NULL)
    return -1;
  get_random(sizeof(rand), (unsigned char *)&(rand));
  rand = htobe32(rand);
  shared->m1 = BN_bin2bn((unsigned char *)&rand, sizeof(rand), shared->m1);
  if (shared->m1 == NULL)
    return -1;

  shared->pub = NULL;
  shared->pub = RSA_new();
  if (shared->pub == NULL) {
    return -1;
  }

  return 0;
}

const int
destroy_shared_values(egl85_ctx_t *shared)
{
  if (!shared->pub) {
    toyot_log_logmsg(ERROR, "Shared public key is NULL\n");
    return -1;
  }
  RSA_free(shared->pub);
  return 0;
}

const int
setup_sender(egl85_sender_ctx_t *sender, egl85_ctx_t *shared)
{
  memset(&(sender->msg0), 0, sizeof(sender->msg0));
  memset(&(sender->msg1), 0, sizeof(sender->msg1));
  memset(&(sender->k0), 0, sizeof(sender->k0));
  memset(&(sender->k1), 0, sizeof(sender->k1));

  sender->mp0 = BN_new();
  sender->mp1 = BN_new();

  sender->base = shared;

  sender->key = NULL;
  generate_new_key(&(sender->key));
  if (sender->key == NULL) {
    return -1;
  }
  toyot_log_logmsg(DEBUG, "Public modulus: %s\n", get_bn_string(sender->key->n, NULL));
  copy_pub_key(sender->key, sender->base->pub);

  /* Messages for OT with receiver */
  sender->msg0 = (uint32_t)"m0\0\0";
  sender->msg1 = (uint32_t)"m1\0\0";
  toyot_log_logmsg(INFO, "Sender's message0: %x\n", sender->msg0);
  toyot_log_logmsg(INFO, "Sender's message1: %x\n", sender->msg1);

  return 0;
}

const int
destroy_sender(egl85_sender_ctx_t *sender)
{
  uncopy_pub_key(sender->key);
  RSA_free(sender->key);
  
  return 0;
}

const int
setup_receiver(egl85_receiver_ctx_t *receiver, egl85_ctx_t *shared)
{
  char *n = NULL;
  BIGNUM *bn_k = NULL;
  int key_bits = 0;
  memset(&(receiver->k), 0, sizeof(receiver->k));
  memset(&(receiver->msg), 0, sizeof(receiver->msg));

  receiver->base = shared;
  receiver->r = choose_bit();

  get_bn_string_r(shared->pub->n, NULL, &n);
  key_bits = BN_num_bits(shared->pub->n);
  while (receiver->k == 0 || (BN_cmp(bn_k, shared->pub->n) > 0)) {
    int k_bits = 0;
    get_random(sizeof(receiver->k), (unsigned char *)&(receiver->k));

    bn_k = BN_bin2bn((unsigned char *)&(receiver->k), sizeof(receiver->k), bn_k);
    if (bn_k == NULL) {
      toyot_log_logmsg(ERROR, "K binary to BN conversion failed\n");
      return -1;
    }
    toyot_log_logmsg(DEBUG, "Receiver's potential k = '%x' (%s)\n", receiver->k, get_bn_string(bn_k, NULL));
    k_bits = BN_num_bits(bn_k);
    toyot_log_logmsg(DEBUG, "Shifting receiver's potential k by %d bits\n", key_bits - k_bits);
    BN_lshift(bn_k, bn_k, key_bits - k_bits);
    toyot_log_logmsg(DEBUG, "Receiver's potential k: %s\n", get_bn_string(bn_k, NULL));
    toyot_log_logmsg(DEBUG, "                     n: %s\n", n);
  }
  toyot_log_logmsg(INFO, "Receiver's k = '%x'\n", receiver->k);

  if (bn_k != NULL)
    BN_free(bn_k);

  return 0;
}

const int
destroy_receiver(egl85_receiver_ctx_t *receiver)
{
  return 0;
}

const int
recvr_encipher_message(unsigned char *k, size_t k_len,
                       const unsigned char *message, size_t msg_len,
                       RSA *pub, size_t *q_len, unsigned char **q, int padding)
{
  BIGNUM *bn_enc = NULL, *bn_msg = NULL, *bn_res = NULL, *bn_k = NULL;
  BN_CTX *tmp = NULL;
  unsigned char *enc = NULL;
  int len;
  uint32_t bn_len;
  uint8_t free_k = 0;

  toyot_log_logmsg(INFO, "Receiver encrypting k=%x, %u bytes with %u byte modulus\n",
                 (uint32_t)k, k_len, RSA_size(pub));
  bn_k = BN_bin2bn(k, k_len, NULL);
  if (bn_k == NULL) {
    toyot_log_logmsg(ERROR, "K binary to BN conversion failed\n");
    goto err;
  }

  toyot_log_logmsg(DEBUG, "bn_k: %s\n", get_bn_string(bn_k, &bn_len));

  enc = malloc(sizeof(*enc)*RSA_size(pub));
  if (enc == NULL) {
    toyot_log_logmsg(ERROR, "Memory allocation for enc failed.\n");
    goto err;
  }
  if (padding == RSA_NO_PADDING) {
    uint32_t rsa_size = RSA_size(pub);
    if (k_len < rsa_size) {
      unsigned char *new_k = NULL;
      new_k = malloc(sizeof(*new_k)*rsa_size);
      if (new_k == NULL) {
        toyot_log_logmsg(ERROR, "Memory allocation for new_k failed.\n");
        goto err;
      }
      free_k = 1;
      memset(new_k, 0, rsa_size);
      memcpy(new_k, k, k_len);
      k = new_k;
      k_len = rsa_size;
    } else if (k_len > rsa_size) {
      toyot_log_logmsg(ERROR, "k (%u) is larger than the RSA modulus (%d). "
                              "This is a failure condition\n", k_len,
                              rsa_size);
      goto err;
    }
  }

  len = RSA_public_encrypt(k_len, k, enc, pub, padding);
  if (len < 0) {
    toyot_log_logmsg(ERROR, "Message enciphering failed: %s\n",
                  ERR_error_string(ERR_get_error(), NULL));
    goto err;
  }
  bn_enc = BN_bin2bn(enc, len, NULL);
  if (bn_enc == NULL) {
    toyot_log_logmsg(ERROR, "Enciphered binary to BN conversion failed\n");
    goto err;
  }

  toyot_log_logmsg(DEBUG, "bn_enc: %s\n", get_bn_string(bn_enc, &bn_len));

  bn_msg = BN_bin2bn(message, msg_len, NULL);
  if (bn_msg == NULL) {
    toyot_log_logmsg(ERROR, "Message binary to BN conversion failed\n");
    goto err;
  }

  toyot_log_logmsg(DEBUG, "bn_msg: %s\n", get_bn_string(bn_msg, &bn_len));

  bn_res = BN_new();
  if (bn_res == NULL) {
    toyot_log_logmsg(ERROR, "Allocating new BIGNUM failed\n");
    goto err;
  }

  tmp = BN_CTX_new();
  if (tmp == NULL) {
    toyot_log_logmsg(ERROR, "Allocating new BIGNUM CTX "
                    "failed\n");
    goto err;
  }

  if (!BN_mod_add(bn_res, bn_enc, bn_msg, pub->n, tmp)) {
    toyot_log_logmsg(ERROR, "Addition failed: %s\n",
                  ERR_error_string(ERR_get_error(), NULL));
    goto err;
  }
  toyot_log_logmsg(DEBUG, "bn_res (q) = bn_enc + bn_msg: %s\n", get_bn_string(bn_res, &bn_len));
  *q_len = BN_num_bytes(bn_res);
  *q = malloc(sizeof(**q)*(*q_len));
  if (*q == NULL) {
    toyot_log_logmsg(ERROR, "Couldn't allocate memory for q\n");
    goto err;
  }
  memset(*q, 0, sizeof(**q)*(*q_len));

  len = BN_bn2bin(bn_res, *q);
  if (!(len > 0)) {
    toyot_log_logmsg(ERROR, "BN to binary conversion failed: len %d\n", len);
    goto err;
  }

  free(enc);
  BN_CTX_free(tmp);
  BN_free(bn_res);
  BN_free(bn_k);
  BN_free(bn_msg);
  BN_free(bn_enc);
  if (free_k)
    free(k);

  return 0;
err:
  if (enc)
    free(enc);
  if (tmp)
    BN_CTX_free(tmp);
  if (bn_k)
    BN_free(bn_k);
  if (bn_res)
    BN_free(bn_res);
  if (bn_msg)
    BN_free(bn_msg);
  if (bn_enc)
    BN_free(bn_enc);
  if (free_k)
    free(k);
  return -1;
}

const int
sender_decipher_k(unsigned char *m, size_t m_len,
                  RSA *priv, unsigned char **k, const size_t k_len,
                  unsigned char *q, size_t q_len, int padding)
{
  BIGNUM *bn_m = NULL, *bn_q = NULL, *bn_res = NULL;
  BN_CTX *tmp = NULL;
  unsigned char *enc = NULL, *deciph = NULL;
  int len;
  uint32_t bn_len;

  /* TODO Invalid read of size 1 - Correct endianness? */
  bn_q = BN_bin2bn(q, q_len, NULL);
  if (bn_q == NULL) {
    toyot_log_logmsg(ERROR, "Converting q failed.\n");
    goto err;
  }

  toyot_log_logmsg(DEBUG, "bn_q: %s\n", get_bn_string(bn_q, &bn_len));

  bn_m = BN_bin2bn(m, m_len, NULL);
  if (bn_m == NULL) {
    toyot_log_logmsg(ERROR, "Converting m failed.\n");
    goto err;
  }

  toyot_log_logmsg(DEBUG, "bn_m: %s\n", get_bn_string(bn_m, &bn_len));

  bn_res = BN_new();
  if (bn_res == NULL) {
    toyot_log_logmsg(ERROR, "Failed while allocated memory for bn_res.\n");
    goto err;
  }

  tmp = BN_CTX_new();
  if (tmp == NULL) {
    toyot_log_logmsg(ERROR, "Allocating new BIGNUM CTX failed\n");
    goto err;
  }

  if (!BN_mod_sub(bn_res, bn_q, bn_m, priv->n, tmp)) {
    toyot_log_logmsg(ERROR, "m subtraction failed\n");
    goto err;
  }

  toyot_log_logmsg(DEBUG, "bn_res = bn_q - bn_m: %s\n", get_bn_string(bn_res, &bn_len));

  enc = malloc(sizeof(*enc)*RSA_size(priv));
  if (enc == NULL) {
    toyot_log_logmsg(ERROR, "Could not allocate memory for enc.\n");
    goto err;
  }
  memset(enc, 0, sizeof(*enc)*RSA_size(priv));

  len = BN_bn2bin(bn_res, enc);
  if (!(len > 0)) {
    toyot_log_logmsg(ERROR, "Converting diff from BN failed\n");
    goto err;
  }
  toyot_log_logmsg(DEBUG, "Stored converted bn_res in enc as %d bytes\n", len);

  deciph = malloc(sizeof(*deciph)*RSA_size(priv));
  if (deciph == NULL) {
    toyot_log_logmsg(ERROR, "Could not allocate memory for deciph.\n");
    goto err;
  }
  memset(deciph, 0, sizeof(*deciph)*RSA_size(priv));

  len = RSA_private_decrypt(len, enc, deciph, priv, padding);
  if (len == -1) {
    /*if (ERR_get_error() == 67608697) {
    if (rsa_err == RSA_R_PADDING_CHECK_FAILED) {
    if (rsa_err == 67608697) {*/
    long unsigned int rsa_err = ERR_get_error();
    /* Why 7? I don't know yet. */
    if (((rsa_err & 0xfff) - 7) == RSA_R_PADDING_CHECK_FAILED) {
      toyot_log_logmsg(ERROR, "Deciphering k failed: OAEP leaks the selection: %s.\n", ERR_error_string(rsa_err, NULL));
      memset(*k, 0, k_len);
    } else {
      toyot_log_logmsg(ERROR, "Deciphering k failed: %s (%lx)\n",
                    ERR_error_string(rsa_err, NULL), rsa_err);
      goto err;
    }
  }
  toyot_log_logmsg(INFO, "Sender deciphered k: %d bytes: %x\n", len, (uint32_t)(*deciph));
  memcpy(*k, deciph, k_len);

  free(enc);
  free(deciph);
  BN_free(bn_q);
  BN_free(bn_m);
  BN_free(bn_res);
  BN_CTX_free(tmp);
  return 0;
err:
  if (enc)
    free(enc);
  if (deciph)
    free(deciph);
  if (bn_q)
    BN_free(bn_q);
  if (bn_m)
    BN_free(bn_m);
  if (bn_res)
    BN_free(bn_res);
  if (tmp)
    BN_CTX_free(tmp);
  return -1;
}

const int
sender_encode_message(unsigned char *msg, size_t msg_len,
                      unsigned char *k, size_t k_len,
                      RSA *priv, BIGNUM *bn_res_msg)
{
  BIGNUM *bn_k = NULL, *bn_msg = NULL;
  BN_CTX *tmp = NULL;
  uint32_t bn_len;
  char *tmpmsg = NULL, *tmpk = NULL, *tmpres = NULL;

  bn_msg = BN_bin2bn(msg, msg_len, NULL);
  if (bn_msg == NULL) {
    toyot_log_logmsg(ERROR, "Converting msg failed.\n");
    goto err;
  }

  toyot_log_logmsg(DEBUG, "bn_msg: %s\n", get_bn_string(bn_msg, &bn_len));

  bn_k = BN_bin2bn(k, k_len, NULL);
  if (bn_k == NULL) {
    toyot_log_logmsg(ERROR, "Converting k failed.\n");
    goto err;
  }

  toyot_log_logmsg(DEBUG, "bn_k: %s\n", get_bn_string(bn_k, &bn_len));

  if (bn_res_msg == NULL) {
    toyot_log_logmsg(ERROR, "Allocated memory for bn_res_msg failed.\n");
    goto err;
  }

  tmp = BN_CTX_new();
  if (tmp == NULL) {
    toyot_log_logmsg(ERROR, "Allocating new BIGNUM CTX failed\n");
    goto err;
  }

  if (!BN_mod_add(bn_res_msg, bn_msg, bn_k, priv->n, tmp)) {
    toyot_log_logmsg(ERROR, "Adding msg and k failed.\n");
    goto err;
  }

  toyot_log_logmsg(DEBUG, "bn_res_msg = bn_msg (%s) + bn_k (%s): %s\n",
                          get_bn_string_r(bn_msg, &bn_len, &tmpmsg),
                          get_bn_string_r(bn_k, &bn_len, &tmpk),
                          get_bn_string_r(bn_res_msg, &bn_len, &tmpres));

  free(tmpmsg);
  free(tmpk);
  free(tmpres);
  BN_free(bn_msg);
  BN_free(bn_k);
  BN_CTX_free(tmp);
  return 0;
err:
  if (tmpmsg)
    free(tmpmsg);
  if (tmpk)
    free(tmpk);
  if (tmpres)
    free(tmpres);
  if (bn_msg)
    BN_free(bn_msg);
  if (bn_k)
    BN_free(bn_k);
  if (tmp)
    BN_CTX_free(tmp);
  return -1;
}

const int
recvr_get_message(BIGNUM *bn_msg, const unsigned char *k,
                  size_t k_len, RSA *pub,
                  BIGNUM *bn_res_msg)
{
  BIGNUM *bn_k = NULL;
  BN_CTX *tmp = NULL;
  uint32_t bn_len;
  char *tmpbn0=NULL, *tmpbn1=NULL, *tmpbn2=NULL;

  toyot_log_logmsg(DEBUG, "bn_msg: %s\n", get_bn_string(bn_msg, &bn_len));

  bn_k = BN_bin2bn(k, k_len, NULL);
  if (bn_k == NULL) {
    toyot_log_logmsg(ERROR, "Converting k failed.\n");
    goto err;
  }

  toyot_log_logmsg(DEBUG, "bn_k: %s\n", get_bn_string(bn_k, &bn_len));

  tmp = BN_CTX_new();
  if (tmp == NULL) {
    toyot_log_logmsg(ERROR, "Allocating new BIGNUM CTX "
                    "failed\n");
    goto err;
  }

  if (!BN_mod_sub(bn_res_msg, bn_msg, bn_k, pub->n, tmp)) {
    toyot_log_logmsg(ERROR, "Subtracting k from msg "
                    "failed\n");
    goto err;
  }

  toyot_log_logmsg(DEBUG, "bn_res_msg = bn_msg (%s) - bn_k (%s): %s\n",
                          get_bn_string_r(bn_msg, &bn_len, &tmpbn0),
                          get_bn_string_r(bn_k, &bn_len, &tmpbn1),
                          get_bn_string_r(bn_res_msg, &bn_len, &tmpbn2));

  /*if (BN_num_bytes(bn_res_msg) > sizeof(uint64_t)) {
    toyot_log_logmsg(ERROR, "res_msg not large enough! Need %d bytes. "
                  "Computing mod inverse.\n", BN_num_bytes(bn_res_msg));
    toyot_log_logmsg(ERROR, "res_msg not large enough! Need %d bytes: %s\n", BN_num_bytes(bn_res_msg), ERR_error_string(ERR_get_error(), NULL));
    goto err;*/
    /*if (BN_mod_inverse(bn_res_msg, bn_res_msg, pub->n, tmp) == NULL) {
      toyot_log_logmsg(ERROR, "mod inverse calculation failed. %s\n",
                    ERR_error_string(ERR_get_error(), NULL));
      goto err;
    }
    toyot_log_logmsg(DEBUG, "bn_res_msg: %s\n", get_bn_string(bn_res_msg, &bn_len));
  }*/
  
  BN_free(bn_k);
  BN_CTX_free(tmp);
  return 0;
err:
  if (bn_k)
    BN_free(bn_k);
  if (bn_res_msg)
    BN_free(bn_res_msg);
  if (tmp)
    BN_CTX_free(tmp);
  return -1;
}

const int
receiver_select_1_out_2(egl85_receiver_ctx_t *receiver,
                        unsigned char **q, uint32_t *q_len)
{
  BIGNUM *mb;
  uint32_t bn_len;
  char *tmpbuf0 = NULL, *tmpbuf1 = NULL;

  if (receiver->r) {
    mb = receiver->base->m1;
  } else {
    mb = receiver->base->m0;
  }

  toyot_log_logmsg(INFO, "Receiver using random messages: m0 = %s, m1 = %s\n",
                         get_bn_string_r(receiver->base->m0, &bn_len, &tmpbuf0),
                         get_bn_string_r(receiver->base->m1, &bn_len, &tmpbuf1));
  toyot_log_logmsg(INFO, "Receiver chose %s\n", receiver->r ? "m1":"m0");
  toyot_log_logmsg(INFO, "Receiver's message chosen at random (k): %x\n", receiver->k);
 
  if (recvr_encipher_message((unsigned char *)&(receiver->k),
                             sizeof(receiver->k),
                             (unsigned char *)&mb, sizeof(mb),
                             receiver->base->pub, q_len, q,
                             receiver->base->rsa_padding)) {
    toyot_log_logmsg(ERROR, "Enciphering message failed.\n");
    goto err;
  }

  return 0;
err:
  return -1;
}

const int
sender_compute_1_out_2(egl85_sender_ctx_t *sender,
                       unsigned char *q, uint32_t q_len)
{
  uint32_t *kp = NULL, k[2];
  
  sender->q = q;
  sender->q_len = q_len;

  kp = &k[0];
  if (sender_decipher_k((unsigned char *)&(sender->base->m0),
                        sizeof(sender->base->m0),
                        sender->key, (unsigned char **)&kp, sizeof(k[0]), q, q_len,
                        sender->base->rsa_padding)) {
    toyot_log_logmsg(ERROR, "Deciphering k0 failed.\n");
    return -1;
  }
  toyot_log_logmsg(INFO, "Sender deciphered k0: %x\n", k[0]);
  kp = &k[1];
  if (sender_decipher_k((unsigned char *)&(sender->base->m1),
                        sizeof(sender->base->m1),
                        sender->key, (unsigned char **)&kp, sizeof(k[1]), q, q_len,
                        sender->base->rsa_padding)) {
    toyot_log_logmsg(ERROR, "Deciphering k1 failed.\n");
    return -1;
  }
  toyot_log_logmsg(INFO, "Sender deciphered k1: %x\n", k[1]);
  memcpy(&(sender->k0), &k[0], sizeof(sender->k0));
  memcpy(&(sender->k1), &k[1], sizeof(sender->k1));

  return 0;
}

const int
sender_encode_ot_message(egl85_sender_ctx_t *sender, BIGNUM *msg0,
                         BIGNUM *msg1)
{
  uint32_t *kp0, *kp1;
  uint32_t bn_len;

  if (sender->base->destiny && sender->base->s) {
    kp0 = &(sender->k1);
    kp1 = &(sender->k0);
  } else {
    kp0 = &(sender->k0);
    kp1 = &(sender->k1);
  }

  if (sender_encode_message((unsigned char *)&(sender->msg0),
                            sizeof(sender->msg0),
                            (unsigned char *)kp0,
                            sizeof(*kp0), sender->key,
                            sender->mp0)) {
    toyot_log_logmsg(ERROR, "Encoding msg0 failed.\n");
    return -1;
  }
  toyot_log_logmsg(INFO, "Sender encoded message0: %s\n", get_bn_string(sender->mp0, &bn_len));
  if (sender_encode_message((unsigned char *)&(sender->msg1),
                            sizeof(sender->msg1),
                            (unsigned char *)kp1,
                            sizeof(*kp1), sender->key,
                            sender->mp1)) {
    toyot_log_logmsg(ERROR, "Encoding msg1 failed.\n");
    return -1;
  }
  toyot_log_logmsg(INFO, "Sender encoded message1: %s\n", get_bn_string(sender->mp1, &bn_len));
  msg0 = BN_copy(msg0, sender->mp0);
  msg1 = BN_copy(msg1, sender->mp1);
 
  return 0;
}

const int
receiver_recover_message(egl85_receiver_ctx_t *receiver,
                         BIGNUM *msg0, BIGNUM *msg1, BIGNUM *msg)
{
  uint32_t bn_len;

  if (receiver->base->s == receiver->r) {
    /*if (receiver->r) {
      mp = (unsigned char *)&(receiver->base->m1);
      mp_len = sizeof(receiver->base->m1);
      mp = (unsigned char *)msg1;
      mp_len = sizeof(*msg1);*/
      /*toyot_log_logmsg(NOTICE, "Choosing m1 (%x) with msg0 (%x) (r=%d, s=%d)\n", receiver->base->m0, *msg0, receiver->r, receiver->base->s);*/
      /*toyot_log_logmsg(NOTICE, "Choosing msg1 (%x) (r=%d, s=%d)\n", *msg1, receiver->r, receiver->base->s);
    } else {*/
      /*mp = (unsigned char *)&(receiver->base->m0);
      mp_len = sizeof(receiver->base->m0);*/
      /*mp = (unsigned char *)msg0;
      mp_len = sizeof(*msg0);*/
      /*toyot_log_logmsg(NOTICE, "Choosing m0 (%x) with msg0 (%x) (r=%d, s=%d)\n", receiver->base->m1, *msg0, receiver->r, receiver->base->s);*/
      /*toyot_log_logmsg(NOTICE, "Choosing msg0 (%x) (r=%d, s=%d)\n", *msg0, receiver->r, receiver->base->s);
    }*/
    toyot_log_logmsg(INFO, "Receiver choosing msg0 (%s) (r=%d, s=%d)\n",
                           get_bn_string(msg0, &bn_len), receiver->r,
                           receiver->base->s);
    toyot_log_logmsg(DEBUG, "k=%x\n", receiver->k);
    if (recvr_get_message(msg0, (unsigned char *)&(receiver->k),
                          sizeof(receiver->k), receiver->base->pub,
                          msg)) {
      toyot_log_logmsg(ERROR, "Decrypting message failed.\n");
      return -1;
    }
    toyot_log_logmsg(INFO, "Receiver received message 0: %s\n",
                           get_bn_string(msg, &bn_len));
  } else {
    /*if (receiver->r) {*/
      /*mp = (unsigned char *)&receiver->base->m0;
      mp_len = sizeof(receiver->base->m0);*/
      /*mp = (unsigned char *)msg0;
      mp_len = sizeof(*msg0);*/
      /*toyot_log_logmsg(NOTICE, "Choosing m0 (%x) with msg1 (%x) (r=%d, s=%d)\n", receiver->base->m0, *msg1, receiver->r, receiver->base->s);*/
      /*toyot_log_logmsg(NOTICE, "Choosing msg1 (%x) (r=%d, s=%d)\n", *msg1, receiver->r, receiver->base->s);
    } else {*/
      /*mp = (unsigned char *)&receiver->base->m1;
      mp_len = sizeof(receiver->base->m1);*/
      /*mp = (unsigned char *)msg1;
      mp_len = sizeof(*msg1);*/
      /*toyot_log_logmsg(NOTICE, "Choosing (%x) m1 with msg1 (%x) (r=%d, s=%d)\n", receiver->base->m1, *msg1, receiver->r, receiver->base->s);*/
      /*toyot_log_logmsg(NOTICE, "Choosing msg1 (%x) (r=%d, s=%d)\n", *msg1, receiver->r, receiver->base->s);
    }*/
    toyot_log_logmsg(INFO, "Receiver choosing msg1 (%s) (r=%d, s=%d)\n",
                           get_bn_string(msg1, &bn_len), receiver->r,
                           receiver->base->s);
    toyot_log_logmsg(DEBUG, "k=%x\n", receiver->k);
    if (recvr_get_message(msg1, (unsigned char *)&(receiver->k),
                          sizeof(receiver->k), receiver->base->pub,
                          msg)) {
      toyot_log_logmsg(ERROR, "Decrypting message failed.\n");
      return -1;
    }
    toyot_log_logmsg(INFO, "Receiver received message 1: %s\n",
                           get_bn_string(msg, &bn_len));
  }

  return 0;
}
