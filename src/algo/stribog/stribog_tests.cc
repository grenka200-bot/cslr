// streebog_tests.cc
// White-box tests for streebog.c (GOST R 34.11-2012 "Streebog", 512-bit).
// Build separately from streebog.c: it is included via #include.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

// Include the implementation as a translation unit, so static tables
// (A, Sbox, Tau, C) and static helpers (S, P, L, E, g_N, hash_512)
// are visible to the tests.
#include "stribog.c"

// ------------------------------------------------------------------
//  Helpers
// ------------------------------------------------------------------

static std::string bytes_to_hex(const uint8_t *data, size_t len) {
    std::string s;
    char buf[4];
    for (size_t i = 0; i < len; i++) {
        std::snprintf(buf, sizeof(buf), "%02x", data[i]);
        s += buf;
    }
    return s;
}

// Convert a hex string to bytes. Returns false on odd length or bad char.
static bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = std::strlen(hex);
    if (hex_len != out_len * 2) return false;
    for (size_t i = 0; i < out_len; i++) {
        unsigned v = 0;
        if (std::sscanf(hex + i * 2, "%2x", &v) != 1) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

// ------------------------------------------------------------------
//  A.1: empty message -> 512-bit hash
// ------------------------------------------------------------------
TEST(Streebog, EmptyMessage) {
    const char *expected_hex =
        "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7"
        "362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a";

    uint8_t digest[CSLR_STREEBOG_512_DIGEST_SIZE];
    ASSERT_EQ(cslr_streebog_512(nullptr, 0, digest), 0);

    std::string got = bytes_to_hex(digest, sizeof(digest));
    std::printf("[test] empty: %s\n", got.c_str());
    EXPECT_EQ(got, std::string(expected_hex));
}

// ------------------------------------------------------------------
//  A.1: 63-byte ASCII message -> 512-bit hash
// ------------------------------------------------------------------
TEST(Streebog, Message63Bytes) {
    const char *msg = "012345678901234567890123456789012345678901234567890123456789012";
    const size_t msg_len = 63;

    const char *expected_hex =
        "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa"
        "00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48";

    uint8_t digest[CSLR_STREEBOG_512_DIGEST_SIZE];
    ASSERT_EQ(cslr_streebog_512((const uint8_t *)msg, msg_len, digest), 0);

    std::string got = bytes_to_hex(digest, sizeof(digest));
    std::printf("[test] 63 bytes: %s\n", got.c_str());
    EXPECT_EQ(got, std::string(expected_hex));
}

// ------------------------------------------------------------------
//  Determinism: two calls on the same data give the same digest
// ------------------------------------------------------------------
TEST(Streebog, Deterministic) {
    const uint8_t msg[100] = {0};   // all zeros, 100 bytes
    uint8_t d1[CSLR_STREEBOG_512_DIGEST_SIZE];
    uint8_t d2[CSLR_STREEBOG_512_DIGEST_SIZE];

    ASSERT_EQ(cslr_streebog_512(msg, sizeof(msg), d1), 0);
    ASSERT_EQ(cslr_streebog_512(msg, sizeof(msg), d2), 0);
    EXPECT_EQ(std::memcmp(d1, d2, sizeof(d1)), 0);
}

// ------------------------------------------------------------------
//  Different inputs -> different digests (basic sanity)
// ------------------------------------------------------------------
TEST(Streebog, DifferentInputsDifferentDigests) {
    const uint8_t a[10] = {1,2,3,4,5,6,7,8,9,10};
    const uint8_t b[10] = {1,2,3,4,5,6,7,8,9,11};   // last byte differs
    uint8_t da[CSLR_STREEBOG_512_DIGEST_SIZE];
    uint8_t db[CSLR_STREEBOG_512_DIGEST_SIZE];

    ASSERT_EQ(cslr_streebog_512(a, sizeof(a), da), 0);
    ASSERT_EQ(cslr_streebog_512(b, sizeof(b), db), 0);
    EXPECT_NE(std::memcmp(da, db, sizeof(da)), 0);
}

// ------------------------------------------------------------------
//  NULL handling
// -----------------------------------------------------------------
TEST(Streebog, NullArgs) {
    uint8_t digest[CSLR_STREEBOG_512_DIGEST_SIZE];

    // NULL digest -> -1
    EXPECT_EQ(cslr_streebog_512((const uint8_t *)"x", 1, nullptr), -1);

    // NULL data with len != 0 -> -1
    EXPECT_EQ(cslr_streebog_512(nullptr, 1, digest), -1);

    // NULL data with len == 0 -> OK (empty message is valid)
    EXPECT_EQ(cslr_streebog_512(nullptr, 0, digest), 0);
}

// ------------------------------------------------------------------
//  Input of exactly 64 bytes (one full block) must not crash and
//  must produce a deterministic digest.
// ------------------------------------------------------------------
TEST(Streebog, Exactly64Bytes) {
    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;

    uint8_t d1[CSLR_STREEBOG_512_DIGEST_SIZE];
    uint8_t d2[CSLR_STREEBOG_512_DIGEST_SIZE];
    ASSERT_EQ(cslr_streebog_512(msg, sizeof(msg), d1), 0);
    ASSERT_EQ(cslr_streebog_512(msg, sizeof(msg), d2), 0);
    EXPECT_EQ(std::memcmp(d1, d2, sizeof(d1)), 0);

    std::printf("[test] 64 bytes: %s\n",
                bytes_to_hex(d1, sizeof(d1)).c_str());
}

// ------------------------------------------------------------------
//  Input larger than one block (e.g. 128 bytes) must not crash
//  and must be deterministic.
// ------------------------------------------------------------------
TEST(Streebog, LargerThanOneBlock) {
    uint8_t msg[128];
    for (int i = 0; i < 128; i++) msg[i] = (uint8_t)(i * 7 + 3);

    uint8_t d1[CSLR_STREEBOG_512_DIGEST_SIZE];
    uint8_t d2[CSLR_STREEBOG_512_DIGEST_SIZE];
    ASSERT_EQ(cslr_streebog_512(msg, sizeof(msg), d1), 0);
    ASSERT_EQ(cslr_streebog_512(msg, sizeof(msg), d2), 0);
    EXPECT_EQ(std::memcmp(d1, d2, sizeof(d1)), 0);

    std::printf("[test] 128 bytes: %s\n",
                bytes_to_hex(d1, sizeof(d1)).c_str());
}

