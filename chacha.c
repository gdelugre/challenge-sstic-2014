/*
chacha-ref.c version 20080118
D. J. Bernstein
Public domain.
*/

#include "chacha.h"

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

#define U8TO16_LITTLE(p) (((uint16_t*)(p))[0])
#define U8TO32_LITTLE(p) (((uint32_t*)(p))[0])
#define U8TO64_LITTLE(p) (((uint64_t*)(p))[0])

#define U16TO8_LITTLE(p, v) (((uint16_t*)(p))[0] = (v))
#define U32TO8_LITTLE(p, v) (((uint32_t*)(p))[0] = (v))
#define U64TO8_LITTLE(p, v) (((uint64_t*)(p))[0] = (v))

static void salsa20_wordtobyte(uint8_t output[64],const uint32_t input[16])
{
  uint32_t x[16];
  int i;

  for (i = 0;i < 16;++i) x[i] = input[i];
  for (i = 8;i > 0;i -= 2) {
    QUARTERROUND( 0, 4, 8,12)
    QUARTERROUND( 1, 5, 9,13)
    QUARTERROUND( 2, 6,10,14)
    QUARTERROUND( 3, 7,11,15)
    QUARTERROUND( 0, 5,10,15)
    QUARTERROUND( 1, 6,11,12)
    QUARTERROUND( 2, 7, 8,13)
    QUARTERROUND( 3, 4, 9,14)
  }
  for (i = 0;i < 16;++i) x[i] = PLUS(x[i],input[i]);
  for (i = 0;i < 16;++i) U32TO8_LITTLE(output + 4 * i,x[i]);
}

void ECRYPT_init(void)
{
  return;
}

//static const char sigma[16] = "expand 32-byte k";
//static const char tau[16] = "expand 16-byte k";

void ECRYPT_keysetup(ECRYPT_ctx *x,const uint8_t *k,uint32_t kbits,uint32_t ivbits)
{
  //const char *constants;

  x->input[4] = U8TO32_LITTLE(k + 0);
  x->input[5] = U8TO32_LITTLE(k + 4);
  x->input[6] = U8TO32_LITTLE(k + 8);
  x->input[7] = U8TO32_LITTLE(k + 12);
  //if (kbits == 256) { /* recommended */
  //  k += 16;
  //  constants = sigma;
  //} else { /* kbits == 128 */
  //  constants = tau;
  //}
  x->input[8] = U8TO32_LITTLE(k + 0);
  x->input[9] = U8TO32_LITTLE(k + 4);
  x->input[10] = U8TO32_LITTLE(k + 8);
  x->input[11] = U8TO32_LITTLE(k + 12);
  x->input[0] = 0x61707865; //U8TO32_LITTLE(constants + 0);
  x->input[1] = 0x3120646e; //U8TO32_LITTLE(constants + 4);
  x->input[2] = 0x79622d36; //U8TO32_LITTLE(constants + 8);
  x->input[3] = 0x6b206574; //U8TO32_LITTLE(constants + 12);
}

void ECRYPT_ivsetup(ECRYPT_ctx *x,const uint8_t *iv)
{
  x->input[12] = 0;
  x->input[13] = 0;
  x->input[14] = U8TO32_LITTLE(iv + 0);
  x->input[15] = U8TO32_LITTLE(iv + 4);
}

void __attribute__((optimize("O2"))) /* Prevents generation of LDn instruction : not emulated by QEMU. */
ECRYPT_encrypt_bytes(ECRYPT_ctx *x,const uint8_t *m,uint8_t *c,uint32_t bytes)
{
  uint8_t output[64];
  int i;

  if (!bytes) return;
  for (;;) {
    salsa20_wordtobyte(output,x->input);
    x->input[12] = PLUSONE(x->input[12]);
    if (!x->input[12]) {
      x->input[13] = PLUSONE(x->input[13]);
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }
    if (bytes <= 64) {
      for (i = 0;i < bytes;++i) c[i] = m[i] ^ output[i];
      return;
    }
    for (i = 0;i < 64;++i) c[i] = m[i] ^ output[i];
    bytes -= 64;
    c += 64;
    m += 64;
  }
}

void ECRYPT_decrypt_bytes(ECRYPT_ctx *x,const uint8_t *c,uint8_t *m,uint32_t bytes)
{
  ECRYPT_encrypt_bytes(x,c,m,bytes);
}

void ECRYPT_keystream_bytes(ECRYPT_ctx *x,uint8_t *stream,uint32_t bytes)
{
  uint32_t i;
  for (i = 0;i < bytes;++i) {stream[i] = 0; asm("");}
  ECRYPT_encrypt_bytes(x,stream,stream,bytes);
}
