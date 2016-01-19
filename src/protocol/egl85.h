#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

/* Values shared between sender and receiver */
struct egl85_ctx_s {
  /* messages chosen at random from M_x */
  BIGNUM *m0;
  BIGNUM *m1;

  /* Bit chosen at random by sender */
  uint8_t s:1;

  /* Should Receiver or destiny choose message? */
  uint8_t destiny:1;

  /* Public key */
  RSA *pub;

  /* RSA padding type */
  int rsa_padding;
};
typedef struct egl85_ctx_s egl85_ctx_t;

/* Receiver's private values */
struct egl85_receiver_ctx_s {
  egl85_ctx_t *base;

  /* Bit chosen at random */
  uint8_t r:1;

  /* message chosen at random from M_x */
  uint32_t k;

  /* Message receiver chose */
  BIGNUM *msg;
};
typedef struct egl85_receiver_ctx_s egl85_receiver_ctx_t;

/* Sender's private values */
struct egl85_sender_ctx_s {
  egl85_ctx_t *base;
  /* Messages for transfer */
  uint32_t msg0;
  uint32_t msg1;

  /* Messages encoded using calculated k */
  BIGNUM *mp0;
  BIGNUM *mp1;

  /* Computed k sent by receiver */
  uint32_t k0;
  uint32_t k1;

  /* Encoded message */
  unsigned char *q;
  uint32_t q_len;

  /* Private key */
  RSA *key;
};
typedef struct egl85_sender_ctx_s egl85_sender_ctx_t;



const int setup_shared_values(egl85_ctx_t *shared, int padding, int destiny);
const int setup_sender(egl85_sender_ctx_t *sender, egl85_ctx_t *shared);
const int setup_receiver(egl85_receiver_ctx_t *receiver, egl85_ctx_t *shared);
const int destroy_shared_values(egl85_ctx_t *shared);
const int destroy_sender(egl85_sender_ctx_t *sender);
const int destroy_receiver(egl85_receiver_ctx_t *receiver);
const int receiver_select_1_out_2(egl85_receiver_ctx_t *receiver, unsigned char **q, uint32_t *q_len);
const int sender_compute_1_out_2(egl85_sender_ctx_t *sender, unsigned char *q, uint32_t q_len);
const int sender_encode_ot_message(egl85_sender_ctx_t *sender, BIGNUM *msg0, BIGNUM *msg1);
const int receiver_recover_message(egl85_receiver_ctx_t *receiver, BIGNUM *msg0, BIGNUM *msg1, BIGNUM *msg);


