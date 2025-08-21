#include <string.h>
#include "hash.h"
#include "sha256.h"
#include "ossl_sha3.h"
#include "bh_sha3.h"
#include "hss_zeroize.h"

#define ALLOW_VERBOSE 0  /* 1 -> we allow the dumping of intermediate */
                         /*      states.  Useful for debugging; horrid */
                         /*      for security */

/*
 * This is the file that implements the hashing APIs we use internally.
 * At the present, our parameter sets support only one hash function
 * (SHA-256, using full 256 bit output), however, that is likely to change
 * in the future
 */

#if ALLOW_VERBOSE
#include <stdio.h>
#include <stdbool.h>
/*
 * Debugging flag; if this is set, we chat about what we're hashing, and what
 * the result is it's useful when debugging; however we probably don't want to
 * do this if we're multithreaded...
 */
bool hss_verbose = false;
#endif

//Define counters for hash function calls
unsigned long hash_calls = 0;
unsigned long inc_hash_init = 0;
unsigned long inc_hash_update = 0;
unsigned long inc_hash_finalize = 0;

/*
 * This will hash the message, given the hash type. It assumes that the result
 * buffer is large enough for the hash
 */
void hss_hash_ctx(void *result, int hash_type, union hash_context *ctx,
          const void *message, size_t message_len) {
#if ALLOW_VERBOSE
    if (hss_verbose) {
        int i; for (i=0; i< message_len; i++) printf( " %02x%s", ((unsigned char*)message)[i], (i%16 == 15) ? "\n" : "" );
    }
#endif

    switch (hash_type) {
    case HASH_SHA256: {
        SHA256_Init(&ctx->sha256);
        SHA256_Update(&ctx->sha256, message, message_len);
        SHA256_Final(result, &ctx->sha256);
#if ALLOW_VERBOSE
        if (hss_verbose) {
            printf( " ->" );
            int i; for (i=0; i<32; i++) printf( " %02x", ((unsigned char *)result)[i] ); printf( "\n" );
        }
#endif
        break;
    }
    // Increment the hash call counter
    hash_calls++;
    case HASH_SHAKE: {
        #if USE_OPENSSL == 1
            // SHAKE is a variable-length output function, we use SHA3-256
            // as the base function, which has a 256-bit output.
            // SHAKE128 is not used here, we use SHA3-256 instead.
            ossl_sha3_init(&ctx->sha3, 0x06, 256);
            ossl_sha3_update(&ctx->sha3, message, message_len);
            ossl_sha3_final(&ctx->sha3, result, 32);
        #else
            // Use the Brainhub implementation of SHA3
            bh_sha3_Init(&ctx->sha3, 256);
            bh_sha3_Update(&ctx->sha3, message, message_len);
            const void *out = bh_sha3_Finalize(&ctx->sha3);
            memcpy(result, out, 32); // Copy the result to the buffer
        #endif 

#if ALLOW_VERBOSE
        if (hss_verbose) {
            printf( " ->" );
            int i; for (i=0; i<32; i++) printf( " %02x", ((unsigned char *)result)[i] ); printf( "\n" );
        }
#endif
        break;
    }
    }
}

void hss_hash(void *result, int hash_type,
          const void *message, size_t message_len) {
    union hash_context ctx;
    hss_hash_ctx(result, hash_type, &ctx, message, message_len);
    hss_zeroize(&ctx, sizeof ctx);
}


/*
 * This provides an API to do incremental hashing.  We use it when hashing the
 * message; since we don't know how long it could be, we don't want to
 * allocate a buffer that's long enough for that, plus the decoration we add
 */
void hss_init_hash_context(int h, union hash_context *ctx) {
    // Increment the incremental hash init counter
    inc_hash_init++;
    switch (h) {
    case HASH_SHA256:
        SHA256_Init( &ctx->sha256 );
        break;
    case HASH_SHAKE:
    #if USE_OPENSSL == 1
        ossl_sha3_init(&ctx->sha3, 0x06, 256);
    #else
        bh_sha3_Init(&ctx->sha3, 256);
    #endif
        break;
    }
}

void hss_update_hash_context(int h, union hash_context *ctx,
                         const void *msg, size_t len_msg) {
#if ALLOW_VERBOSE
    if (hss_verbose) {
        int i; for (i=0; i<len_msg; i++) printf( " %02x", ((unsigned char*)msg)[i] );
    }
#endif
    // Increment the incremental hash update counter
    inc_hash_update++;
    switch (h) {
    case HASH_SHA256:
        SHA256_Update(&ctx->sha256, msg, len_msg);
        break;
    case HASH_SHAKE:
    #if USE_OPENSSL == 1
        ossl_sha3_update(&ctx->sha3, msg, len_msg);
    #else
        bh_sha3_Update(&ctx->sha3, msg, len_msg);
    #endif
        break;
    }
}

void hss_finalize_hash_context(int h, union hash_context *ctx, void *buffer) {
    //increment the incremental hash finalize counter
    inc_hash_finalize++;
    switch (h) {
    case HASH_SHA256:
        SHA256_Final(buffer, &ctx->sha256);
#if ALLOW_VERBOSE
    if (hss_verbose) {
        printf( " -->" );
        int i; for (i=0; i<32; i++) printf( " %02x", ((unsigned char*)buffer)[i] );
        printf( "\n" );
    }
#endif
        break;
    case HASH_SHAKE:
    #if USE_OPENSSL == 1
        ossl_sha3_final(&ctx->sha3, buffer, 32);
    #else
        const void *out = bh_sha3_Finalize(&ctx->sha3);
        memcpy(buffer, out, 32); // Copy the result to the buffer
    #endif
#if ALLOW_VERBOSE
    if (hss_verbose) {
        printf( " -->" );
        int i; for (i=0; i<32; i++) printf( " %02x", ((unsigned char*)buffer)[i] );
        printf( "\n" );
    }
#endif
        break;
    }
}


unsigned hss_hash_length(int hash_type) {
    switch (hash_type) {
    case HASH_SHA256: return 32;
    case HASH_SHAKE: return 32; // SHA3-256 output size
    }
    return 0;
}

unsigned hss_hash_blocksize(int hash_type) {
    switch (hash_type) {
    case HASH_SHA256: return 64;
    case HASH_SHAKE: return 136; // SHA3-256 block size
    }
    return 0;
}

