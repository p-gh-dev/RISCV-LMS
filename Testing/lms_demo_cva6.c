/*
 * LMS Hash-Based Signatures for Cheshire RISC-V
 * 
 * This is a bare-metal implementation of RFC 8554 (Leighton-Micali Signatures)
 * running on Cheshire with hardware SHA-3 acceleration. The main pieces are:
 *   - WOTS+ for one-time signatures at each leaf
 *   - Merkle tree to bundle multiple WOTS keys together
 *   - Custom 'shatr' instruction that talks to Keccak hardware
 * 
 * The tree lives in DRAM because storing 2^10 or more nodes on the stack
 * is a really bad idea. 
 * Default cheshire-cva6 Scratcpad okay up to level 9 tree.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "regs/cheshire.h"
#include "dif/clint.h"
#include "dif/uart.h"
#include "params.h"
#include "util.h"

/* ========================================================================== */
/*                         Performance Tracking                               */
/* ========================================================================== */

// Not used all yet
uint64_t global_counter_shatr = 0;
uint64_t global_counter_def = 0;
uint64_t main_counter_shatr = 0;
uint64_t main_counter_def = 0;
uint64_t global_cycle_shatr = 0;
uint64_t global_cycle_def = 0;
uint64_t last = 0;

// Read CPU cycle counter - the standard way to benchmark on RISC-V
static inline uint64_t read_mcycle(void) {
    uint64_t cycle_val;
    asm volatile("csrr %0, mcycle" : "=r"(cycle_val));
    return cycle_val;
}

/* ========================================================================== */
/*                      String/Number Utilities                               */
/* ========================================================================== */

// No printf in bare-metal land, so we need our own converters
// These are intentionally simple - no locale support or fancy formatting

static int simple_uint_to_str(uint32_t num, char *buf) {
    if (num == 0) {
        buf[0] = '0';
        return 1;
    }
    
    // Build the string backwards then reverse it
    char temp[12];
    int i = 0;
    while (num > 0) {
        temp[i++] = '0' + (num % 10);
        num /= 10;
    }
    
    // Flip it around to get the right order
    for (int j = 0; j < i; j++) {
        buf[j] = temp[i - 1 - j];
    }
    
    return i;
}

// Convert 64-bit values to hex for debug output
int uint64_to_hex_str(uint64_t val, char *buf) {
    char *p = buf;
    *p++ = '0';
    *p++ = 'x';
    
    if (val == 0) {
        *p++ = '0';
        *p = '\0';
        return 3;
    }
    
    // Figure out how many hex digits we need
    uint64_t shifter = val;
    do { p++; shifter /= 16; } while (shifter);
    *p = '\0';
    
    // Fill in from right to left
    char *p_fill = p;
    const char hex_digits[] = "0123456789abcdef";
    do {
        *--p_fill = hex_digits[val % 16];
        val /= 16;
    } while (val);
    
    return (p - buf);
}

size_t simple_strlen(const char *str) {
    size_t len = 0;
    while (str[len]) len++;
    return len;
}

// 64-bit decimal conversion for cycle counts and big numbers
int uint64_to_str(uint64_t val, char *buf) {
    if (val == 0) {
        *buf++ = '0';
        *buf = '\0';
        return 1;
    }
    
    char *digits_start_ptr = buf;
    char *p = buf;
    
    // Count how many digits first
    uint64_t shifter = val;
    do { p++; shifter /= 10; } while (shifter);
    *p = '\0';
    
    // Fill backwards
    char *p_fill = p;
    do { 
        *--p_fill = (val % 10) + '0'; 
        val /= 10; 
    } while (val);
    
    return simple_strlen(digits_start_ptr);
}



/* ========================================================================== */
/*                      Memory Operations                                     */
/* ========================================================================== */

// needs also our own memory functions since we don't have stdlib
// Kept simple on purpose - no overlapping copy detection or optimization

static void my_memcpy(uint8_t *dst, const uint8_t *src, uint32_t n) {
    while (n--) *dst++ = *src++;
}

// used volatile to make sure the compiler doesn't optimize away security-critical zeroing
static void my_memzero(uint8_t *ptr, uint32_t n) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (n--) *p++ = 0;
}

static int my_memcmp(const uint8_t *a, const uint8_t *b, uint32_t n) {
    while (n--) {
        if (*a != *b) return *a - *b;
        a++; b++;
    }
    return 0;
}

// Big-endian encoding for network/RFC compatibility
static void put_u32_be(uint8_t *buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
}

/* ========================================================================== */
/*                    LMS Configuration Parameters                            */
/* ========================================================================== */

// Pick your tree height here - this determines signature capacity
// H=10 means 2^10 = 1,024 one-time signatures before you need a new key
// Bigger trees = more signatures but way longer keygen time
#define USE_H10

#ifdef USE_H5
    #define LMS_H 5
    #define LMS_N 32        // 32 signatures total
    #define TREE_SIZE (64 * HASH_LEN)
#elif defined(USE_H10)
    #define LMS_H 10
    #define LMS_N 1024      // 1K signatures 
    #define TREE_SIZE (2048 * HASH_LEN)
#elif defined(USE_H15)
    #define LMS_H 15
    #define LMS_N 32768     // 32K signatures - takes a while to generate
    #define TREE_SIZE (65536 * HASH_LEN)
#elif defined(USE_H20)
    #define LMS_H 20
    #define LMS_N 1048576   // 1M signatures - not tested 
    #define TREE_SIZE (2097152 * HASH_LEN)
#else
    #error "No tree height defined!"
#endif

// Core parameters from RFC 8554
#define I_LEN 16          // Tree identifier (like a key ID)
#define HASH_LEN 32       // SHA3-256 output
#define SEED_LEN 32       // Master secret seed
#define W_BITS 3          // Winternitz param: W = 2^3 = 8
#define W 8               // Lower W = bigger sigs but faster signing
#define P1 86             // Chains for message hash (256/3 ≈ 86)
#define P2 4              // Chains for checksum
#define P 90              // Total chains (86 + 4)

/* ========================================================================== */
/*                      SHA-3 / Keccak Implementation                         */
/* ========================================================================== */

#define KECCAK_ROUNDS 24

// Sponge construction state for SHA-3
typedef struct {
    uint64_t state[25];     // 5×5 array of lanes (1600 bits)
    unsigned int rate;      // Absorb rate (136 bytes for SHA3-256)
    unsigned int offset;    // Current position in rate block
} sha3_ctx;

// Keccak round constants - these break symmetry in the permutation
// Derived from LFSR, basically magic numbers from the spec
static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rotation amounts for the rho step
static const unsigned keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

// Pi permutation - shuffles lane positions
static const unsigned keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

// Basic 64-bit rotation - used all over the place in Keccak
static inline uint64_t rol64(uint64_t x, unsigned s) {
    return (x << s) | (x >> (64 - s));
}

/*
 * Keccak-f[1600] using hardware acceleration
 * 
 * This is the heart of SHA-3. Instead of running 24 rounds in software
 * (theta, rho, pi, chi, iota for each round - super slow), we offload
 * everything to custom hardware via the 'shatr' instruction.
 * 
 * The protocol is:
 *   1. Initialize the HW unit
 *   2. Stream in all 25 state words (as pairs)
 *   3. Issue 24 round commands
 *   4. Stream out the permuted state
 * 
 * Takes about 25-30 cycles total vs thousands in software. Pretty nice speedup.
 */
static void keccakf(uint64_t st[25]) {
    int64_t default_in = 0x0000000000000000;
    int64_t c_val;
    global_counter_shatr++;
    
    // Set up registers for inline asm now not needed to be true value since we have custom registers!
    register uint64_t r1 asm("x11") = 0x1234;
    register uint64_t r2 asm("x12") = 0x5678;
    register uint64_t r3 asm("x10");
    
    // Wake up the hardware unit and reset its state machine
    asm volatile("shatr %[z], %[x], %[y]\n\t" : [z] "=r" (c_val) : [x] "r" (1), [y] "r" (1));
    asm volatile("shatr %[z], %[x], %[y]\n\t" : [z] "=r" (c_val) : [x] "r" (1), [y] "r" (st[0]));
    
    // Load state words in pairs - hardware expects them this way// replace memory operation in pipeline
    asm volatile("shatr %[z], %[x], %[y]\n\t" : [z] "=r" (c_val) : [x] "r" (st[2]), [y] "r" (st[1]));
    asm volatile("shatr %[z], %[x], %[y]\n\t" : [z] "=r" (c_val) : [x] "r" (st[4]), [y] "r" (st[3]));
    asm volatile("shatr %[z], %[x], %[y]\n\t" : [z] "=r" (c_val) : [x] "r" (st[6]), [y] "r" (st[5]));
    asm volatile("shatr %[z], %[x], %[y]\n\t" : [z] "=r" (c_val) : [x] "r" (st[8]), [y] "r" (st[7]));
    asm volatile("shatr %[z], %[x], %[y]\n\t" : [z] "=r" (c_val) : [x] "r" (st[10]), [y] "r" (st[9]));
    asm volatile("shatr %[z], %[x], %[y]\n\t" : [z] "=r" (c_val) : [x] "r" (st[12]), [y] "r" (st[11]));
    asm volatile("shatr %[z], %[x], %[y]\n\t" : [z] "=r" (c_val) : [x] "r" (st[14]), [y] "r" (st[13]));
    asm volatile("shatr %[z], %[x], %[y]\n\t" : [z] "=r" (c_val) : [x] "r" (st[16]), [y] "r" (st[15]));
    asm volatile("shatr %[z], %[x], %[y]\n\t" : [z] "=r" (c_val) : [x] "r" (st[18]), [y] "r" (st[17]));
    asm volatile("shatr %[z], %[x], %[y]\n\t" : [z] "=r" (c_val) : [x] "r" (st[20]), [y] "r" (st[19]));
    asm volatile("shatr %[z], %[x], %[y]\n\t" : [z] "=r" (c_val) : [x] "r" (st[22]), [y] "r" (st[21]));
    asm volatile("shatr %[z], %[x], %[y]\n\t" : [z] "=r" (c_val) : [x] "r" (st[24]), [y] "r" (st[23]));
    
    // Execute all 24 Keccak rounds in hardware
    // Each call advances the internal state machine by one round
    for (int i = 0; i < 24; i++) {
        asm volatile("shatr x10, x11, x12\n\t" ::: "x10");
    }
    
    // Read back the permuted state (hardware -> software) - 
    for (int i = 0; i < 25; i++) {
        asm volatile("shatr %[z], %[x], %[y]\n\t" : [z] "=r" (st[i]) : [x] "r" (default_in), [y] "r" (default_in));
    }
}

// Initialize a fresh SHA-3 context
static void sha3_init(sha3_ctx *ctx) {
    for (int i = 0; i < 25; i++) ctx->state[i] = 0;
    ctx->rate = 136;  // SHA3-256: (1600 - 2*256) / 8 = 136 bytes
    ctx->offset = 0;
}

/*
 * Absorb data into the sponge
 */
static void sha3_update(sha3_ctx *ctx, const uint8_t *data, uint32_t len) {
    while (len > 0) {
        
        uint32_t take = ctx->rate - ctx->offset;
        if (take > len) take = len;
        
        
        uint8_t *dst = (uint8_t *)ctx->state + ctx->offset;
        for (uint32_t i = 0; i < take; i++) {
            dst[i] ^= data[i];
        }
        
        ctx->offset += take;
        data += take;
        len -= take;
        
        // Block full? 
        if (ctx->offset == ctx->rate) {
            keccakf(ctx->state);
            ctx->offset = 0;
        }
    }
}

/*
 * Finalize and squeeze output
 * 
 * Apply padding (0x06 for SHA-3), do final permutation, extract output.
 * The padding is SHA-3 specific - 0x06 is the domain separator that
 * distinguishes SHA-3 from SHAKE and other Keccak variants.
 */
static void sha3_final(sha3_ctx *ctx, uint8_t *output) {
    // Apply multi-rate padding: 0x06 || 0x00...00 || 0x80
    uint8_t *dst = (uint8_t *)ctx->state + ctx->offset;
    *dst ^= 0x06;  // SHA-3 domain separator
    dst = (uint8_t *)ctx->state + ctx->rate - 1;
    *dst ^= 0x80;  // End of padding
    
    // Final permutation
    keccakf(ctx->state);
    
    // Squeeze out 256 bits (32 bytes)
    for (int i = 0; i < 32; i++) {
        output[i] = ((uint8_t *)ctx->state)[i];
    }
}

// One-shot hash function - init, update, finalize all at once
static void sha3_hash(const uint8_t *input, uint32_t len, uint8_t *output) {
    sha3_ctx ctx;
    sha3_init(&ctx);
    sha3_update(&ctx, input, len);
    sha3_final(&ctx, output);
}

/* ========================================================================== */
/*                     Winternitz One-Time Signature (WOTS+)                  */
/* ========================================================================== */

/*
 * Derive WOTS chain starting value from master seed
 * 
 * Uses a PRF to generate independent secrets for each chain: 
 * PRF(SEED, I || q || i || 0xff)
 * 
 * The 0xff marker distinguishes this from other PRF uses in the scheme.
 * We hash the tree ID (I), leaf index (q), chain index (i), and seed together.
 */
static void derive_secret(uint8_t *output, const uint8_t *seed,
                         const uint8_t *I, uint32_t q, uint16_t i) {
    uint8_t buf[I_LEN + 7 + SEED_LEN];
    my_memcpy(buf, I, I_LEN);
    put_u32_be(buf + I_LEN, q);
    buf[I_LEN + 4] = (i >> 8) & 0xFF;
    buf[I_LEN + 5] = i & 0xFF;
    buf[I_LEN + 6] = 0xFF;  // Domain separator for secret derivation
    my_memcpy(buf + I_LEN + 7, seed, SEED_LEN);
    sha3_hash(buf, I_LEN + 7 + SEED_LEN, output);
}

/*
 * WOTS hash chain computation
 * 
 * Compute out = H^count(in), i.e., hash 'count' times starting from 'in'.
 * Each hash includes context (tree ID, leaf, chain index, iteration) to
 * prevent various multi-target and cross-chain attacks.
 * 
 * The 'start' param lets us begin from any point in the chain, which is
 * crucial for verification (we need to continue from signature values).
 */
static void wots_chain(uint8_t *out, const uint8_t *in, unsigned start,
                      unsigned count, const uint8_t *I, uint32_t q, uint16_t i) {
    my_memcpy(out, in, HASH_LEN);
    
    for (unsigned s = start; s < start + count; s++) {
        uint8_t buf[I_LEN + 7 + HASH_LEN];
        my_memcpy(buf, I, I_LEN);
        put_u32_be(buf + I_LEN, q);
        buf[I_LEN + 4] = (i >> 8) & 0xFF;
        buf[I_LEN + 5] = i & 0xFF;
        buf[I_LEN + 6] = s & 0xFF;  // Chain iteration
        my_memcpy(buf + I_LEN + 7, out, HASH_LEN);
        sha3_hash(buf, I_LEN + 7 + HASH_LEN, out);
    }
}

/*
 * Generate WOTS+ signature
 * 
 * For each of P chains, we need to hash the secret 'a' times where 'a' comes from
 * message bits. Then compute a checksum to prevent forgery by increasing
 * message digits, and sign that too.
 * 
 * With W=8, we encode each message digit as 3 bits (values 0-7).
 * Lower message values = more hashing, so signature reveals less of the chain.
 */
static void wots_sign(uint8_t *sig, const uint8_t *hash,
                     const uint8_t *seed, const uint8_t *I, uint32_t q) {
    uint16_t checksum = 0;
    
    // Sign message hash - break into W-bit chunks
    for (uint16_t i = 0; i < P1; i++) {
        unsigned bit_off = i * W_BITS;
        uint8_t a = (hash[bit_off / 8] >> (bit_off % 8)) & (W - 1);
        checksum += W - 1 - a;  // Accumulate checksum
        
        uint8_t secret[HASH_LEN];
        derive_secret(secret, seed, I, q, i);
        wots_chain(sig + i * HASH_LEN, secret, 0, a, I, q, i);
        my_memzero(secret, HASH_LEN);  // Don't leave secrets lying around
    }
    
    // Sign checksum using remaining chains
    for (uint16_t i = 0; i < P2; i++) {
        uint8_t a = (checksum >> (i * W_BITS)) & (W - 1);
        uint8_t secret[HASH_LEN];
        derive_secret(secret, seed, I, q, P1 + i);
        wots_chain(sig + (P1 + i) * HASH_LEN, secret, 0, a, I, q, P1 + i);
        my_memzero(secret, HASH_LEN);
    }
}

/* ========================================================================== */
/*                           LMS Merkle Tree                                  */
/* ========================================================================== */

// Private key: tree ID, master seed, signature counter
typedef struct {
    uint8_t I[I_LEN];       // Tree identifier (16 bytes)
    uint8_t seed[SEED_LEN]; // Master secret seed
    uint32_t next_q;        // Next available leaf index
} lms_key;

// Public key: just the tree ID and Merkle root
typedef struct {
    uint8_t I[I_LEN];       // Tree identifier
    uint8_t root[HASH_LEN]; // Merkle root hash
} lms_pubkey;

/*
 * Compute Merkle tree leaf from WOTS public key
 * 
 * Generate the WOTS pubkey by hashing each chain to completion (W-1 times),
 * then hash the entire pubkey with context to get the leaf value.
 * 
 * The 0x8282 domain separator (D_LEAF) distinguishes leaves from interior nodes.
 */
static void compute_leaf(uint8_t *out, const uint8_t *I, uint32_t r,
                        const uint8_t *seed, uint32_t q) {
    uint8_t pk[P * HASH_LEN];
    
    // Generate WOTS public key (hash all chains to the end)
    for (uint16_t i = 0; i < P; i++) {
        uint8_t secret[HASH_LEN];
        derive_secret(secret, seed, I, q, i);
        wots_chain(pk + i * HASH_LEN, secret, 0, W - 1, I, q, i);
        my_memzero(secret, HASH_LEN);
    }
    
    // Hash pubkey to create leaf: H(I || r || D_LEAF || pk)
    uint8_t buf[I_LEN + 6 + P * HASH_LEN];
    my_memcpy(buf, I, I_LEN);
    put_u32_be(buf + I_LEN, r);
    buf[I_LEN + 4] = 0x82;  // D_LEAF domain separator
    buf[I_LEN + 5] = 0x82;
    my_memcpy(buf + I_LEN + 6, pk, P * HASH_LEN);
    sha3_hash(buf, I_LEN + 6 + P * HASH_LEN, out);
}

/*
 * Combine two tree nodes into their parent
 * 
 * Simple Merkle tree hash: parent = H(I || r || D_INTR || left || right)
 * The 0x8383 domain separator (D_INTR) distinguishes interior nodes from leaves.
 */
static void combine_nodes(uint8_t *out, const uint8_t *left,
                         const uint8_t *right, const uint8_t *I, uint32_t r) {
    uint8_t buf[I_LEN + 6 + 2 * HASH_LEN];
    my_memcpy(buf, I, I_LEN);
    put_u32_be(buf + I_LEN, r);
    buf[I_LEN + 4] = 0x83;  // D_INTR domain separator
    buf[I_LEN + 5] = 0x83;
    my_memcpy(buf + I_LEN + 6, left, HASH_LEN);
    my_memcpy(buf + I_LEN + 6 + HASH_LEN, right, HASH_LEN);
    sha3_hash(buf, I_LEN + 6 + 2 * HASH_LEN, out);
}

// Store tree in DRAM to avoid stack overflow - this is HUGE
#define DRAM_TREE_BASE 0x80100000
static uint8_t *global_tree = (uint8_t *)DRAM_TREE_BASE;
static bool tree_initialized = false;

/*
 * Generate LMS keypair
 * 
 * We compute all N leaves (each requires generating a full WOTS pubkey), 
 * then build the tree bottom-up until
 * we reach the root.
 * For H=10, that's 1024 leaves + 1023 interior nodes = 2047 hashes.
 * Each leaf needs 90 WOTS chains hashed W-1 times. Takes a while.
 * 
 * Tree layout in memory: [all leaves][level 1][level 2]...[root]
 */
static void lms_keygen(lms_key *priv, lms_pubkey *pub, const uint8_t *seed) {
    my_memcpy(priv->I, seed, I_LEN);
    my_memcpy(priv->seed, seed + I_LEN, SEED_LEN);
    priv->next_q = 0;
    
    uint8_t *tree = global_tree;
    
    // Compute all leaf nodes (this is the slow part)
    for (uint32_t i = 0; i < LMS_N; i++) {
        compute_leaf(tree + i * HASH_LEN, priv->I, LMS_N + i, priv->seed, i);
        
        // Print progress dots for big trees so you know it's not stuck
        #if LMS_H >= 10
        if ((i & 0x3F) == 0) {
            uart_write(&__base_uart, '.');
        }
        #endif
    }
    
    // Build tree bottom-up by hashing pairs
    uint32_t tree_idx = LMS_N;      // Where to write next node
    uint32_t level_start = 0;        // Start of current level
    uint32_t level_size = LMS_N;     // Number of nodes in level
    
    while (level_size > 1) {
        for (uint32_t i = 0; i < level_size / 2; i++) {
            combine_nodes(
                tree + tree_idx * HASH_LEN,
                tree + (level_start + 2*i) * HASH_LEN,
                tree + (level_start + 2*i + 1) * HASH_LEN,
                priv->I,
                (LMS_N + tree_idx)
            );
            tree_idx++;
        }
        level_start += level_size;
        level_size /= 2;
    }
    
    // Last node we computed is the root
    my_memcpy(pub->root, tree + (tree_idx - 1) * HASH_LEN, HASH_LEN);
    my_memcpy(pub->I, priv->I, I_LEN);
    
    tree_initialized = true;
}

/*
 * Extract authentication path node from stored tree
 * 
 * For verification, we need the sibling at each level as we climb
 * from leaf to root. This finds the right sibling in our tree array.
 */
static void get_auth_path_node(uint8_t *out, uint32_t leaf_idx, uint32_t height) {
    uint32_t node_idx = leaf_idx >> height;
    uint32_t sibling_idx = node_idx ^ 1;  // Flip lowest bit to get sibling
    
    // Figure out where this sibling lives in the tree array
    uint32_t level_offset = 0;
    for (uint32_t h = 0; h < height; h++) {
        level_offset += (LMS_N >> h);
    }
    
    uint32_t tree_idx = level_offset + sibling_idx;
    my_memcpy(out, global_tree + tree_idx * HASH_LEN, HASH_LEN);
}

/*
 * Sign a message with LMS
 * 
 * Signature format: [q (4 bytes)][WOTS sig (P*32 bytes)][auth path (H*32 bytes)]
 * 
 * We hash the message with context, sign that hash with WOTS, and append
 * the authentication path so verifiers can climb from leaf to root.
 * 
 * Each signature increments next_q. Once you hit N signatures, you're done -
 * time to generate a new keypair.
 */
static bool lms_sign(uint8_t *sig, uint32_t *siglen, const uint8_t *msg,
                    uint32_t msglen, lms_key *priv) {
    if (priv->next_q >= LMS_N) return false;  // Out of signatures!
    if (!tree_initialized) return false;
    
    uint32_t q = priv->next_q++;
    
    // Hash message with context: H(I || q || D_MESG || msg)
    uint8_t hash[HASH_LEN];
    uint8_t msgbuf[I_LEN + 6 + 256];
    my_memcpy(msgbuf, priv->I, I_LEN);
    put_u32_be(msgbuf + I_LEN, q);
    msgbuf[I_LEN + 4] = 0x81;  // D_MESG domain separator
    msgbuf[I_LEN + 5] = 0x81;
    uint32_t copy_len = (msglen > 256) ? 256 : msglen;
    my_memcpy(msgbuf + I_LEN + 6, msg, copy_len);
    sha3_hash(msgbuf, I_LEN + 6 + copy_len, hash);
    
    // Build signature: q || WOTS_sig || auth_path
    uint8_t *p = sig;
    put_u32_be(p, q);
    p += 4;
    
    wots_sign(p, hash, priv->seed, priv->I, q);
    p += P * HASH_LEN;
    
    // Append authentication path (H siblings, one per level)
    for (unsigned h = 0; h < LMS_H; h++) {
        get_auth_path_node(p, q, h);
        p += HASH_LEN;
    }
    
    *siglen = (uint32_t)(p - sig);
    return true;
}

/* ========================================================================== */
/*                            Debug/Test Functions                            */
/* ========================================================================== */

// Print hex byte to UART for debugging
static void uart_write_hex_byte(uint8_t byte) {
    char hex_chars[] = "0123456789abcdef";
    uart_write(&__base_uart, hex_chars[(byte >> 4) & 0x0F]);
    uart_write(&__base_uart, hex_chars[byte & 0x0F]);
}

// Dump hex data with newlines every 32 bytes
static void print_hex(const uint8_t *data, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        uart_write_hex_byte(data[i]);
        if ((i + 1) % 32 == 0) {
            uart_write_str(&__base_uart, (void *)"\r\n", 2);
        }
    }
    uart_write_str(&__base_uart, (void *)"\r\n", 2);
}

// Fixed seed for test vectors - makes output deterministic
#define SEED_TOTAL_LEN (I_LEN + SEED_LEN)
const uint8_t fixed_seed[SEED_TOTAL_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30
};

/*
 * Test SHA-3 against NIST vectors
 * 
 * Sanity check that our SHA-3 implementation matches the spec.
 * If this fails, nothing else will work right.
 */
static bool test_sha3_vectors(void) {
    uart_write_str(&__base_uart, (void *)"\r\n=== SHA-3 Test ===\r\n", 21);
    
    // NIST test vector: SHA3-256("")
    const uint8_t input1[] = "";
    const uint8_t expected1[32] = {
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
    };
    
    uint8_t output[32];
    sha3_hash(input1, 0, output);
    
    uart_write_str(&__base_uart, (void *)"Test 1 (empty): ", 16);
    if (my_memcmp(output, expected1, 32) == 0) {
        uart_write_str(&__base_uart, (void *)"PASS\r\n", 6);
    } else {
        uart_write_str(&__base_uart, (void *)"FAIL\r\n", 6);
        uart_write_str(&__base_uart, (void *)"Expected: ", 10);
        print_hex(expected1, 32);
        uart_write_str(&__base_uart, (void *)"Got: ", 5);
        print_hex(output, 32);
        return false;
    }
    
    // NIST test vector: SHA3-256("abc")
    const uint8_t input2[] = "abc";
    const uint8_t expected2[32] = {
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
        0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
        0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
    };
    
    sha3_hash(input2, 3, output);
    
    uart_write_str(&__base_uart, (void *)"Test 2 (abc): ", 14);
    if (my_memcmp(output, expected2, 32) == 0) {
        uart_write_str(&__base_uart, (void *)"PASS\r\n", 6);
    } else {
        uart_write_str(&__base_uart, (void *)"FAIL\r\n", 6);
        return false;
    }
    
    uart_write_str(&__base_uart, (void *)"SHA-3 tests PASSED!\r\n", 21);
    return true;
}

/* ========================================================================== */
/*                       LMS Signature Verification                           */
/* ========================================================================== */

/*
 * Verify an LMS signature
 * 
 * Process:
 *   1. Check signature length and extract leaf index q
 *   2. Hash the message with context
 *   3. Recover WOTS pubkey from signature (hash chains forward)
 *   4. Compute leaf from recovered pubkey
 *   5. Climb tree using auth path, hashing with siblings
 *   6. Check if we reach the public root
 * 
 * Returns true if signature is valid, false otherwise.
 */
static bool lms_verify(const uint8_t *sig, uint32_t siglen, 
                      const uint8_t *msg, uint32_t msglen,
                      const lms_pubkey *pub) {
    
    // Check signature has the right length
    uint32_t expected_size = 4 + P * HASH_LEN + LMS_H * HASH_LEN;
    if (siglen != expected_size) return false;
    
    // Extract leaf index from signature
    uint32_t q = ((uint32_t)sig[0] << 24) | ((uint32_t)sig[1] << 16) |
                 ((uint32_t)sig[2] << 8) | sig[3];
    if (q >= LMS_N) return false;  // Index out of range
    
    const uint8_t *wots_sig = sig + 4;
    const uint8_t *auth_path = sig + 4 + P * HASH_LEN;
    
    // Hash message same way signer did
    uint8_t msg_hash[HASH_LEN];
    uint8_t msgbuf[I_LEN + 6 + 256];
    my_memcpy(msgbuf, pub->I, I_LEN);
    put_u32_be(msgbuf + I_LEN, q);
    msgbuf[I_LEN + 4] = 0x81;
    msgbuf[I_LEN + 5] = 0x81;
    uint32_t copy_len = (msglen > 256) ? 256 : msglen;
    my_memcpy(msgbuf + I_LEN + 6, msg, copy_len);
    sha3_hash(msgbuf, I_LEN + 6 + copy_len, msg_hash);
    
    // Recover WOTS public key by hashing signature values forward
    uint8_t wots_pk[P * HASH_LEN];
    uint16_t checksum = 0;
    
    // Process message hash chains
    for (uint16_t i = 0; i < P1; i++) {
        unsigned bit_off = i * W_BITS;
        uint8_t a = (msg_hash[bit_off / 8] >> (bit_off % 8)) & (W - 1);
        checksum += W - 1 - a;
        // Hash from signature value up to pubkey (W-1-a more times)
        wots_chain(wots_pk + i * HASH_LEN, wots_sig + i * HASH_LEN, 
                  a, W - 1 - a, pub->I, q, i);
    }
    
    // Process checksum chains
    for (uint16_t i = 0; i < P2; i++) {
        uint8_t a = (checksum >> (i * W_BITS)) & (W - 1);
        wots_chain(wots_pk + (P1 + i) * HASH_LEN, wots_sig + (P1 + i) * HASH_LEN,
                  a, W - 1 - a, pub->I, q, P1 + i);
    }
    
    // Compute leaf from recovered pubkey
    uint8_t current[HASH_LEN];
    uint8_t buf[I_LEN + 6 + P * HASH_LEN];
    my_memcpy(buf, pub->I, I_LEN);
    put_u32_be(buf + I_LEN, LMS_N + q);
    buf[I_LEN + 4] = 0x82;
    buf[I_LEN + 5] = 0x82;
    my_memcpy(buf + I_LEN + 6, wots_pk, P * HASH_LEN);
    sha3_hash(buf, I_LEN + 6 + P * HASH_LEN, current);
    
    // Climb tree using authentication path
    uint32_t tree_idx = LMS_N + q;
    
    for (unsigned h = 0; h < LMS_H; h++) {
        uint8_t sibling[HASH_LEN];
        my_memcpy(sibling, auth_path + h * HASH_LEN, HASH_LEN);
        
        uint8_t combine_buf[I_LEN + 6 + 2 * HASH_LEN];
        my_memcpy(combine_buf, pub->I, I_LEN);
        
        // Calculate parent index to match keygen indexing
        uint32_t nodes_before = 0;
        for (unsigned lv = 0; lv <= h; lv++) {
            nodes_before += (LMS_N >> lv);
        }
        uint32_t node_num_at_level = (tree_idx - LMS_N - (nodes_before - (LMS_N >> h)));
        uint32_t parent_tree_idx = LMS_N + nodes_before + (node_num_at_level >> 1);
        
        put_u32_be(combine_buf + I_LEN, parent_tree_idx);
        combine_buf[I_LEN + 4] = 0x83;
        combine_buf[I_LEN + 5] = 0x83;
        
        // Order nodes correctly (left/right matters in Merkle trees!)
        if ((q >> h) & 1) {
            // We're on the right, sibling is on the left
            my_memcpy(combine_buf + I_LEN + 6, sibling, HASH_LEN);
            my_memcpy(combine_buf + I_LEN + 6 + HASH_LEN, current, HASH_LEN);
        } else {
            // We're on the left, sibling is on the right
            my_memcpy(combine_buf + I_LEN + 6, current, HASH_LEN);
            my_memcpy(combine_buf + I_LEN + 6 + HASH_LEN, sibling, HASH_LEN);
        }
        
        sha3_hash(combine_buf, I_LEN + 6 + 2 * HASH_LEN, current);
        tree_idx = parent_tree_idx;
    }
    
    // True!!
    return (my_memcmp(current, pub->root, HASH_LEN) == 0);
}

/* ========================================================================== */
/*                              Main Program                                  */
/* ========================================================================== */

int main(void) {
    uint64_t loop_start_cycles, loop_end_cycles, loop_total_cycles;
    uint64_t loop_start_cycles2, loop_end_cycles2, loop_total_cycles2;

    // Initialize UART for debug output
    uint32_t rtc_freq = *reg32(&__base_regs, CHESHIRE_RTC_FREQ_REG_OFFSET);
    uint64_t reset_freq = clint_get_core_freq(rtc_freq, 2500);
    uart_init(&__base_uart, reset_freq, __BOOT_BAUDRATE);
    
    uart_write_str(&__base_uart, (void *)"\r\n=== LMS-SHA3 Validation ===\r\n", 31);
    
    // First things first - make sure SHA-3 works
    if (!test_sha3_vectors()) {
        uart_write_str(&__base_uart, (void *)"SHA-3 FAILED!\r\n", 15);
        uart_write_flush(&__base_uart);
        return -1;
    }
    
    // Generate keypair and measure performance
    uart_write_str(&__base_uart, (void *)"\r\nKeygen test...\r\n", 18);
    lms_key privkey;
    lms_pubkey pubkey;
    
    // Memory barriers to ensure accurate timing
    asm volatile("fence.i" ::: "memory");
    asm volatile("fence" ::: "memory");
    
    loop_start_cycles = read_mcycle();
    lms_keygen(&privkey, &pubkey, fixed_seed);
    loop_end_cycles = read_mcycle();
    loop_total_cycles = loop_end_cycles - loop_start_cycles;

    uart_write_str(&__base_uart, (void *)"Done!\r\n", 7);
    uart_write_str(&__base_uart, (void *)"Public key root:\r\n", 18);
    print_hex(pubkey.root, HASH_LEN);
    
    // Print configuration
    uart_write_str(&__base_uart, (void *)"Config: H=", 10);
    char h_buf[8];
    int h_len = simple_uint_to_str(LMS_H, h_buf);
    uart_write_str(&__base_uart, (void *)h_buf, h_len);
    uart_write_str(&__base_uart, (void *)", N=", 4);
    char n_buf[8];
    int n_len = simple_uint_to_str(LMS_N, n_buf);
    uart_write_str(&__base_uart, (void *)n_buf, n_len);
    uart_write_str(&__base_uart, (void *)"\r\n", 2);

    // Sign a test message
    uart_write_str(&__base_uart, (void *)"\r\nSigning test...\r\n", 19);
    const uint8_t message[] = "Hello Cheshire!";
    uint8_t signature[4 + P * HASH_LEN + LMS_H * HASH_LEN];
    uint32_t siglen;
    
    asm volatile("fence.i" ::: "memory");
    asm volatile("fence" ::: "memory");
    
    loop_start_cycles2 = read_mcycle();
    if (!lms_sign(signature, &siglen, message, sizeof(message) - 1, &privkey)) {
        uart_write_str(&__base_uart, (void *)"Sign FAILED!\r\n", 14);
        return -1;
    }
    loop_end_cycles2 = read_mcycle();
    loop_total_cycles2 = loop_end_cycles2 - loop_start_cycles2;
    
    uart_write_str(&__base_uart, (void *)"Done!\r\n", 7);
    
    // Report performance metrics
    uart_write_str(&__base_uart, (void *)"\r\n=== PERFORMANCE ===\r\n", 23);
    
    char buf[32];
    
    uart_write_str(&__base_uart, (void *)"Keygen cycles: ", 15);
    int len = uint64_to_str(loop_total_cycles, buf);
    uart_write_str(&__base_uart, (void *)buf, len);
    uart_write_str(&__base_uart, (void *)"\r\n", 2);
    
    uart_write_str(&__base_uart, (void *)"Signing cycles: ", 16);
    len = uint64_to_str(loop_total_cycles2, buf);
    uart_write_str(&__base_uart, (void *)buf, len);
    uart_write_str(&__base_uart, (void *)"\r\n", 2);
    
    /* Sanity check the ratio - keygen should be way slower than signing and ratio changes
    *  with lenght, W etc.
    */
    if (loop_total_cycles2 > 0) {
        uint64_t ratio = loop_total_cycles / loop_total_cycles2;
        uart_write_str(&__base_uart, (void *)"Keygen/Sign ratio: ", 19);
        len = uint64_to_str(ratio, buf);
        uart_write_str(&__base_uart, (void *)buf, len);
        uart_write_str(&__base_uart, (void *)"x\r\n", 3);
        
        if (ratio < 20) {
            uart_write_str(&__base_uart, (void *)"WARNING: Ratio too low! Expected 50-100x\r\n", 43);
        } else if (ratio >= 20 && ratio <= 200) {
            uart_write_str(&__base_uart, (void *)"Ratio looks reasonable\r\n", 24);
        } else {
            uart_write_str(&__base_uart, (void *)"WARNING: Ratio very high\r\n", 26);
        }
    }
    
    // Check signature size
    uint32_t expected_siglen = 4 + P * HASH_LEN + LMS_H * HASH_LEN;
    uart_write_str(&__base_uart, (void *)"\r\nExpected sig size: ", 21);
    len = simple_uint_to_str(expected_siglen, buf);
    uart_write_str(&__base_uart, (void *)buf, len);
    uart_write_str(&__base_uart, (void *)" bytes\r\n", 8);
    
    uart_write_str(&__base_uart, (void *)"Actual sig size: ", 17);
    len = simple_uint_to_str(siglen, buf);
    uart_write_str(&__base_uart, (void *)buf, len);
    uart_write_str(&__base_uart, (void *)" bytes\r\n", 8);
    
    if (siglen == expected_siglen) {
        uart_write_str(&__base_uart, (void *)"Size CORRECT!\r\n", 15);
    } else {
        uart_write_str(&__base_uart, (void *)"Size WRONG!\r\n", 13);
    }
    
    uart_write_str(&__base_uart, (void *)"\r\n[[ALL TESTS PASSED]]\r\n", 25);
    uart_write_flush(&__base_uart);
    
    // Comprehensive verification tests:
    uart_write_str(&__base_uart, (void *)"\r\n=== VERIFICATION TESTS ===\r\n", 30);
    
    // Test 1: Valid signature should verify
    uart_write_str(&__base_uart, (void *)"Test 1: Valid signature...", 27);
    if (lms_verify(signature, siglen, message, sizeof(message) - 1, &pubkey)) {
        uart_write_str(&__base_uart, (void *)" PASS\r\n", 7);
    } else {
        uart_write_str(&__base_uart, (void *)" FAIL!\r\n", 8);
        uart_write_flush(&__base_uart);
        return -1;
    }
    
    // Test 2: Wrong message should fail
    uart_write_str(&__base_uart, (void *)"Test 2: Modified message...", 28);
    const uint8_t wrong_msg[] = "Wrong message!";
    if (!lms_verify(signature, siglen, wrong_msg, sizeof(wrong_msg) - 1, &pubkey)) {
        uart_write_str(&__base_uart, (void *)" PASS\r\n", 7);
    } else {
        uart_write_str(&__base_uart, (void *)" FAIL!\r\n", 8);
        uart_write_flush(&__base_uart);
        return -1;
    }
    
    // Test 3: Corrupted signature should fail
    uart_write_str(&__base_uart, (void *)"Test 3: Corrupted signature...", 31);
    uint8_t bad_sig[4 + P * HASH_LEN + LMS_H * HASH_LEN];
    my_memcpy(bad_sig, signature, siglen);
    bad_sig[100] ^= 0xFF;  // Flip some bits
    if (!lms_verify(bad_sig, siglen, message, sizeof(message) - 1, &pubkey)) {
        uart_write_str(&__base_uart, (void *)" PASS\r\n", 7);
    } else {
        uart_write_str(&__base_uart, (void *)" FAIL!\r\n", 8);
        uart_write_flush(&__base_uart);
        return -1;
    }
    
    // Test 4: Multiple signatures should all work
    uart_write_str(&__base_uart, (void *)"Test 4: 5 signatures...", 24);
    for (int i = 0; i < 5; i++) {
        uint8_t test_msg[16];
        test_msg[0] = 'T';
        test_msg[1] = 'e';
        test_msg[2] = 's';
        test_msg[3] = 't';
        test_msg[4] = '0' + i;
        test_msg[5] = '\0';
        
        uint8_t test_sig[4 + P * HASH_LEN + LMS_H * HASH_LEN];
        uint32_t test_len;
        
        if (!lms_sign(test_sig, &test_len, test_msg, 5, &privkey)) {
            uart_write_str(&__base_uart, (void *)" Sign FAIL!\r\n", 13);
            return -1;
        }
        
        if (!lms_verify(test_sig, test_len, test_msg, 5, &pubkey)) {
            uart_write_str(&__base_uart, (void *)" Verify FAIL!\r\n", 15);
            return -1;
        }
    }
    uart_write_str(&__base_uart, (void *)" PASS\r\n", 7);
    
    // Test 5: Leaf index should increment correctly
    uart_write_str(&__base_uart, (void *)"Test 5: q increments...", 24);
    uint32_t expected_q = privkey.next_q;
    
    bool q_ok = true;
    for (int i = 0; i < 3; i++) {
        uint8_t temp_sig[4 + P * HASH_LEN + LMS_H * HASH_LEN];
        uint32_t temp_len;
        const uint8_t temp_msg[] = "test";
        
        if (!lms_sign(temp_sig, &temp_len, temp_msg, 4, &privkey)) {
            q_ok = false;
            break;
        }
        
        // Extract q from signature
        uint32_t q_curr = ((uint32_t)temp_sig[0] << 24) | 
                        ((uint32_t)temp_sig[1] << 16) |
                        ((uint32_t)temp_sig[2] << 8) | 
                        temp_sig[3];
        
        if (q_curr != expected_q) {
            q_ok = false;
            break;
        }
        expected_q++;
    }
    
    if (q_ok) {
        uart_write_str(&__base_uart, (void *)" PASS\r\n", 7);
    } else {
        uart_write_str(&__base_uart, (void *)" FAIL!\r\n", 8);
    }

    uart_write_str(&__base_uart, (void *)"\r\n=== ALL TESTS PASSED ===\r\n", 28);
    uart_write_flush(&__base_uart);
    
    return 0;
}
