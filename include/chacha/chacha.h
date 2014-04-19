/* ecrypt-sync.h */

/* 
 * Header file for synchronous stream ciphers without authentication
 * mechanism.
 * 
 * *** Please only edit parts marked with "[edit]". ***
 */

#ifndef __CHACHA_H
#define __CHACHA_H

#include <stdint.h>

/*
 *  * The following macros are used to obtain exact-width results.
 *   */

#define U8V(v) ((uint8_t)(v) & (uint8_t)(0xFF))
#define U16V(v) ((uint16_t)(v) & (uint16_t)(0xFFFF))
#define U32V(v) ((uint32_t)(v) & (uint32_t)(0xFFFFFFFF))
#define U64V(v) ((uint64_t)(v) & (uint64_t)(0xFFFFFFFFFFFFFFFF))

/* ------------------------------------------------------------------------- */

/*
 *  * The following macros return words with their bits rotated over n
 *   * positions to the left/right.
 *    */

#define ECRYPT_DEFAULT_ROT

#define ROTL8(v, n) \
      (U8V((v) << (n)) | ((v) >> (8 - (n))))

#define ROTL16(v, n) \
      (U16V((v) << (n)) | ((v) >> (16 - (n))))

#define ROTL32(v, n) \
      (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define ROTL64(v, n) \
      (U64V((v) << (n)) | ((v) >> (64 - (n))))

#define ROTR8(v, n) ROTL8(v, 8 - (n))
#define ROTR16(v, n) ROTL16(v, 16 - (n))
#define ROTR32(v, n) ROTL32(v, 32 - (n))
#define ROTR64(v, n) ROTL64(v, 64 - (n))

/* ------------------------------------------------------------------------- */

/* Cipher parameters */

/* 
 * The name of your cipher.
 */
#define ECRYPT_NAME "ChaCha8"
#define ECRYPT_PROFILE "_____"

/*
 * Specify which key and IV sizes are supported by your cipher. A user
 * should be able to enumerate the supported sizes by running the
 * following code:
 *
 * for (i = 0; ECRYPT_KEYSIZE(i) <= ECRYPT_MAXKEYSIZE; ++i)
 *   {
 *     keysize = ECRYPT_KEYSIZE(i);
 *
 *     ...
 *   }
 *
 * All sizes are in bits.
 */

#define ECRYPT_MAXKEYSIZE 256                 /* [edit] */
#define ECRYPT_KEYSIZE(i) (128 + (i)*128)     /* [edit] */

#define ECRYPT_MAXIVSIZE 64                   /* [edit] */
#define ECRYPT_IVSIZE(i) (64 + (i)*64)        /* [edit] */

/* ------------------------------------------------------------------------- */

/* Data structures */

/* 
 * ECRYPT_ctx is the structure containing the representation of the
 * internal state of your cipher. 
 */

typedef struct
{
  uint32_t input[16]; /* could be compressed */
  /* 
   * [edit]
   *
   * Put here all state variable needed during the encryption process.
   */
} ECRYPT_ctx;

/* ------------------------------------------------------------------------- */

/* Mandatory functions */

/*
 * Key and message independent initialization. This function will be
 * called once when the program starts (e.g., to build expanded S-box
 * tables).
 */
void ECRYPT_init();

/*
 * Key setup. It is the user's responsibility to select the values of
 * keysize and ivsize from the set of supported values specified
 * above.
 */
void ECRYPT_keysetup(
  ECRYPT_ctx* ctx, 
  const uint8_t* key, 
  uint32_t keysize,                /* Key size in bits. */ 
  uint32_t ivsize);                /* IV size in bits. */ 

/*
 * IV setup. After having called ECRYPT_keysetup(), the user is
 * allowed to call ECRYPT_ivsetup() different times in order to
 * encrypt/decrypt different messages with the same key but different
 * IV's.
 */
void ECRYPT_ivsetup(
  ECRYPT_ctx* ctx, 
  const uint8_t* iv);

/*
 * Encryption/decryption of arbitrary length messages.
 *
 * For efficiency reasons, the API provides two types of
 * encrypt/decrypt functions. The ECRYPT_encrypt_bytes() function
 * (declared here) encrypts byte strings of arbitrary length, while
 * the ECRYPT_encrypt_blocks() function (defined later) only accepts
 * lengths which are multiples of ECRYPT_BLOCKLENGTH.
 * 
 * The user is allowed to make multiple calls to
 * ECRYPT_encrypt_blocks() to incrementally encrypt a long message,
 * but he is NOT allowed to make additional encryption calls once he
 * has called ECRYPT_encrypt_bytes() (unless he starts a new message
 * of course). For example, this sequence of calls is acceptable:
 *
 * ECRYPT_keysetup();
 *
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_bytes();
 *
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_blocks();
 *
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_bytes();
 * 
 * The following sequence is not:
 *
 * ECRYPT_keysetup();
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_bytes();
 * ECRYPT_encrypt_blocks();
 */

void ECRYPT_encrypt_bytes(
  ECRYPT_ctx* ctx, 
  const uint8_t* plaintext, 
  uint8_t* ciphertext, 
  uint32_t msglen);                /* Message length in bytes. */ 

void ECRYPT_decrypt_bytes(
  ECRYPT_ctx* ctx, 
  const uint8_t* ciphertext, 
  uint8_t* plaintext, 
  uint32_t msglen);                /* Message length in bytes. */ 

/* ------------------------------------------------------------------------- */

/* Optional features */

/* 
 * For testing purposes it can sometimes be useful to have a function
 * which immediately generates keystream without having to provide it
 * with a zero plaintext. If your cipher cannot provide this function
 * (e.g., because it is not strictly a synchronous cipher), please
 * reset the ECRYPT_GENERATES_KEYSTREAM flag.
 */

#define ECRYPT_GENERATES_KEYSTREAM
#ifdef ECRYPT_GENERATES_KEYSTREAM

void ECRYPT_keystream_bytes(
  ECRYPT_ctx* ctx,
  uint8_t* keystream,
  uint32_t length);                /* Length of keystream in bytes. */

#endif

/* ------------------------------------------------------------------------- */

/* Optional optimizations */

/* 
 * By default, the functions in this section are implemented using
 * calls to functions declared above. However, you might want to
 * implement them differently for performance reasons.
 */

/*
 * All-in-one encryption/decryption of (short) packets.
 *
 * The default definitions of these functions can be found in
 * "ecrypt-sync.c". If you want to implement them differently, please
 * undef the ECRYPT_USES_DEFAULT_ALL_IN_ONE flag.
 */
#define ECRYPT_USES_DEFAULT_ALL_IN_ONE        /* [edit] */

void ECRYPT_encrypt_packet(
  ECRYPT_ctx* ctx, 
  const uint8_t* iv,
  const uint8_t* plaintext, 
  uint8_t* ciphertext, 
  uint32_t msglen);

void ECRYPT_decrypt_packet(
  ECRYPT_ctx* ctx, 
  const uint8_t* iv,
  const uint8_t* ciphertext, 
  uint8_t* plaintext, 
  uint32_t msglen);

/*
 * Encryption/decryption of blocks.
 * 
 * By default, these functions are defined as macros. If you want to
 * provide a different implementation, please undef the
 * ECRYPT_USES_DEFAULT_BLOCK_MACROS flag and implement the functions
 * declared below.
 */

#define ECRYPT_BLOCKLENGTH 64                  /* [edit] */

#define ECRYPT_USES_DEFAULT_BLOCK_MACROS      /* [edit] */
#ifdef ECRYPT_USES_DEFAULT_BLOCK_MACROS

#define ECRYPT_encrypt_blocks(ctx, plaintext, ciphertext, blocks)  \
  ECRYPT_encrypt_bytes(ctx, plaintext, ciphertext,                 \
    (blocks) * ECRYPT_BLOCKLENGTH)

#define ECRYPT_decrypt_blocks(ctx, ciphertext, plaintext, blocks)  \
  ECRYPT_decrypt_bytes(ctx, ciphertext, plaintext,                 \
    (blocks) * ECRYPT_BLOCKLENGTH)

#ifdef ECRYPT_GENERATES_KEYSTREAM

#define ECRYPT_keystream_blocks(ctx, keystream, blocks)            \
  ECRYPT_keystream_bytes(ctx, keystream,                        \
    (blocks) * ECRYPT_BLOCKLENGTH)

#endif

#else

void ECRYPT_encrypt_blocks(
  ECRYPT_ctx* ctx, 
  const uint8_t* plaintext, 
  uint8_t* ciphertext, 
  uint32_t blocks);                /* Message length in blocks. */ 

void ECRYPT_decrypt_blocks(
  ECRYPT_ctx* ctx, 
  const uint8_t* ciphertext, 
  uint8_t* plaintext, 
  uint32_t blocks);                /* Message length in blocks. */ 

#ifdef ECRYPT_GENERATES_KEYSTREAM

void ECRYPT_keystream_blocks(
  ECRYPT_ctx* ctx,
  const uint8_t* keystream,
  uint32_t blocks);                /* Keystream length in blocks. */ 

#endif

#endif

/*
 * If your cipher can be implemented in different ways, you can use
 * the ECRYPT_VARIANT parameter to allow the user to choose between
 * them at compile time (e.g., gcc -DECRYPT_VARIANT=3 ...). Please
 * only use this possibility if you really think it could make a
 * significant difference and keep the number of variants
 * (ECRYPT_MAXVARIANT) as small as possible (definitely not more than
 * 10). Note also that all variants should have exactly the same
 * external interface (i.e., the same ECRYPT_BLOCKLENGTH, etc.). 
 */
#define ECRYPT_MAXVARIANT 1                   /* [edit] */

#ifndef ECRYPT_VARIANT
#define ECRYPT_VARIANT 1
#endif

#if (ECRYPT_VARIANT > ECRYPT_MAXVARIANT)
#error this variant does not exist
#endif

/* ------------------------------------------------------------------------- */

#endif
