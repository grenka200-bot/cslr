// kuznyechik_test.cc
// White-box тесты для kuznyechik.c (ГОСТ Р 34.12-2015).
// Собирать ОТДЕЛЬНО от kuznyechik.c: он включается как #include.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>

// Подключаем реализацию как единицу трансляции — так видны static-функции:
// gen_round_keys, S, S_reverse, R, L, encrypt_block, decrypt_block и т.д.
#include "kuznyechik.c"

// ------------------------------------------------------------------
//  Вспомогательные функции
// ------------------------------------------------------------------

static void hex_to_bytes(const char* hex, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned v = 0;
        std::sscanf(hex + i * 2, "%2x", &v);
        out[i] = static_cast<uint8_t>(v);
    }
}

static std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::string s;
    char buf[4];
    for (size_t i = 0; i < len; i++) {
        std::snprintf(buf, sizeof(buf), "%02x", data[i]);
        s += buf;
    }
    return s;
}

// Печать 16-байтного блока в hex — удобно для отладки раундовых ключей
static void print_block(const char* label, const uint8_t b[16]) {
    std::printf("%s: %s\n", label, bytes_to_hex(b, 16).c_str());
}

// ------------------------------------------------------------------
//  keygen: повторные вызовы должны давать разные ключи
// ------------------------------------------------------------------
TEST(KuznyechikPublicAPI, KeygenProducesDistinctKeys) {
    uint8_t k1[32], k2[32];

    ASSERT_EQ(cslr_kuznyechik_keygen(k1), 0);
    ASSERT_EQ(cslr_kuznyechik_keygen(k2), 0);

    // Вероятность совпадения двух независимых 256-битных ключей ~ 2^-256,
    // так что тест детерминирован на практике.
    EXPECT_NE(std::memcmp(k1, k2, 32), 0)
        << "two keygen() calls returned identical keys";

    // Дополнительно: ключ не должен быть полностью нулевым
    bool all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (k1[i] != 0) { all_zero = false; break; }
    }
    EXPECT_FALSE(all_zero) << "keygen() returned all-zero key";
}

// ------------------------------------------------------------------
//  А.1.1 — преобразование S
// ------------------------------------------------------------------
TEST(KuznyechikTransform, S) {
    struct Case { const char* in; const char* out; };
    const Case cases[] = {
        {"ffeeddccbbaa99881122334455667700", "b66cd8887d38e8d77765aeea0c9a7efc"},
        {"b66cd8887d38e8d77765aeea0c9a7efc", "559d8dd7bd06cbfe7e7b262523280d39"},
        {"559d8dd7bd06cbfe7e7b262523280d39", "0c3322fed531e4630d80ef5c5a81c50b"},
        {"0c3322fed531e4630d80ef5c5a81c50b", "23ae65633f842d29c5df529c13f5acda"},
    };
    for (const auto& c : cases) {
        uint8_t b[16];
        hex_to_bytes(c.in, b, 16);
        S(b);
        EXPECT_EQ(bytes_to_hex(b, 16), std::string(c.out)) << "input = " << c.in;
    }
}

// А.1.1 (обратное) — S_reverse ∘ S == id
TEST(KuznyechikTransform, S_reverse_roundtrip) {
    uint8_t b[16];
    hex_to_bytes("ffeeddccbbaa99881122334455667700", b, 16);
    uint8_t orig[16];
    std::memcpy(orig, b, 16);
    S(b);
    S_reverse(b);
    EXPECT_EQ(bytes_to_hex(b, 16), bytes_to_hex(orig, 16));
}

// ------------------------------------------------------------------
//  А.1.2 — преобразование R
// ------------------------------------------------------------------
TEST(KuznyechikTransform, R) {
    struct Case { const char* in; const char* out; };
    const Case cases[] = {
        {"00000000000000000000000000000100", "94000000000000000000000000000001"},
        {"94000000000000000000000000000001", "a5940000000000000000000000000000"},
        {"a5940000000000000000000000000000", "64a59400000000000000000000000000"},
        {"64a59400000000000000000000000000", "0d64a594000000000000000000000000"},
    };
    for (const auto& c : cases) {
        uint8_t b[16];
        hex_to_bytes(c.in, b, 16);
        R(b);
        EXPECT_EQ(bytes_to_hex(b, 16), std::string(c.out)) << "input = " << c.in;
    }
}

TEST(KuznyechikTransform, R_reverse_roundtrip) {
    uint8_t b[16];
    hex_to_bytes("00000000000000000000000000000100", b, 16);
    uint8_t orig[16];
    std::memcpy(orig, b, 16);
    R(b);
    R_reverse(b);
    EXPECT_EQ(bytes_to_hex(b, 16), bytes_to_hex(orig, 16));
}

// ------------------------------------------------------------------
//  А.1.3 — преобразование L
// ------------------------------------------------------------------
TEST(KuznyechikTransform, L) {
    struct Case { const char* in; const char* out; };
    const Case cases[] = {
        {"64a59400000000000000000000000000", "d456584dd0e3e84cc3166e4b7fa2890d"},
       {"d456584dd0e3e84cc3166e4b7fa2890d", "79d26221b87b584cd42fbc4ffea5de9a"},
        {"79d26221b87b584cd42fbc4ffea5de9a", "0e93691a0cfc60408b7b68f66b513c13"},
        {"0e93691a0cfc60408b7b68f66b513c13", "e6a8094fee0aa204fd97bcb0b44b8580"},
    };
    for (const auto& c : cases) {
        uint8_t b[16];
        hex_to_bytes(c.in, b, 16);
        L(b);
        EXPECT_EQ(bytes_to_hex(b, 16), std::string(c.out)) << "input = " << c.in;
    }
}

TEST(KuznyechikTransform, L_reverse_roundtrip) {
    uint8_t b[16];
    hex_to_bytes("64a59400000000000000000000000000", b, 16);
    uint8_t orig[16];
    std::memcpy(orig, b, 16);
    L(b);
    L_reverse(b);
    EXPECT_EQ(bytes_to_hex(b, 16), bytes_to_hex(orig, 16));
}

// ------------------------------------------------------------------
//  А.1.4 — развёртка ключа: K1..K10
// ------------------------------------------------------------------
TEST(KuznyechikKeyExpansion, RoundKeys) {
    uint8_t key[32];
    hex_to_bytes("8899aabbccddeeff0011223344556677"
                 "fedcba98765432100123456789abcdef", key, 32);

    uint8_t rk[10][16];
    gen_round_keys(key, rk);

    const char* expected[10] = {
        "8899aabbccddeeff0011223344556677",  // K1
        "fedcba98765432100123456789abcdef",  // K2
        "db31485315694343228d6aef8cc78c44",  // K3
        "3d4553d8e9cfec6815ebadc40a9ffd04",  // K4
        "57646468c44a5e28d3e59246f429f1ac",  // K5
        "bd079435165c6432b532e82834da581b",  // K6
        "51e640757e8745de705727265a0098b1",  // K7
        "5a7925017b9fdd3ed72a91a22286f984",  // K8
        "bb44e25378c73123a5f32f73cdb6e517",  // K9
        "72e9dd7416bcf45b755dbaa88e4a4043",  // K10
    };

    for (int i = 0; i < 10; i++) {
        // Печатаем — удобно глазами сверить с таблицей ГОСТ
        char label[16];
        std::snprintf(label, sizeof(label), "K%d", i + 1);
        print_block(label, rk[i]);

        EXPECT_EQ(bytes_to_hex(rk[i], 16), std::string(expected[i]))
            << "mismatch at K" << (i + 1);
    }
}

// ------------------------------------------------------------------
//  А.1.5 — шифрование одного блока
// ------------------------------------------------------------------
TEST(KuznyechikECB, EncryptBlock) {
    uint8_t key[32];
    hex_to_bytes("8899aabbccddeeff0011223344556677"
                 "fedcba98765432100123456789abcdef", key, 32);

    uint8_t rk[10][16];
    gen_round_keys(key, rk);

    uint8_t pt[16], ct[16];
    hex_to_bytes("1122334455667700ffeeddccbbaa9988", pt, 16);
    encrypt_block(rk, pt, ct);

    EXPECT_EQ(bytes_to_hex(ct, 16),
              std::string("7f679d90bebc24305a468d42b9d4edcd"));
}

// ------------------------------------------------------------------
//  А.1.6 — расшифрование одного блока
// ------------------------------------------------------------------
TEST(KuznyechikECB, DecryptBlock) {
    uint8_t key[32];
    hex_to_bytes("8899aabbccddeeff0011223344556677"
                 "fedcba98765432100123456789abcdef", key, 32);

    uint8_t rk[10][16];
    gen_round_keys(key, rk);

    uint8_t ct[16], pt[16];
    hex_to_bytes("7f679d90bebc24305a468d42b9d4edcd", ct, 16);
    decrypt_block(rk, ct, pt);

    EXPECT_EQ(bytes_to_hex(pt, 16),
              std::string("1122334455667700ffeeddccbbaa9988"));
}

// ------------------------------------------------------------------
//  Полный цикл через публичный API (ECB + нулевой паддинг)
// ------------------------------------------------------------------
TEST(KuznyechikPublicAPI, EncryptDecryptRoundtrip) {
    uint8_t key[32];
    hex_to_bytes("8899aabbccddeeff0011223344556677"
                 "fedcba98765432100123456789abcdef", key, 32);

    // Ровно один блок — без паддинга
    uint8_t in[16];
    hex_to_bytes("1122334455667700ffeeddccbbaa9988", in, 16);
    uint8_t ct[16], pt[16];
    size_t ct_len = 0;

    ASSERT_EQ(cslr_kuznyechik_encrypt(key, in, 16, ct, &ct_len), 0);
    EXPECT_EQ(ct_len, 16u);
    EXPECT_EQ(bytes_to_hex(ct, 16),
              std::string("7f679d90bebc24305a468d42b9d4edcd"));

    ASSERT_EQ(cslr_kuznyechik_decrypt(key, ct, ct_len, pt), 0);
    EXPECT_EQ(bytes_to_hex(pt, 16), bytes_to_hex(in, 16));
}

TEST(KuznyechikPublicAPI, ZeroPadding) {
    uint8_t key[32];
    hex_to_bytes("8899aabbccddeeff0011223344556677"
                 "fedcba98765432100123456789abcdef", key, 32);

    // 20 байт -> 32 байта шифртекста (2 блока), хвост добит нулями
    uint8_t in[20];
    std::memset(in, 0xAB, sizeof(in));
    uint8_t out[32];
    size_t out_len = 0;

    ASSERT_EQ(cslr_kuznyechik_encrypt(key, in, sizeof(in), out, &out_len), 0);
    EXPECT_EQ(out_len, 32u);

    // Обратно: получаем 32 байта; первые 20 совпадают, хвост — нули
    uint8_t back[32];
    ASSERT_EQ(cslr_kuznyechik_decrypt(key, out, out_len, back), 0);
    EXPECT_EQ(std::memcmp(back, in, 20), 0);
    for (int i = 20; i < 32; i++) EXPECT_EQ(back[i], 0);
}

TEST(KuznyechikPublicAPI, NullAndInvalidArgs) {
    uint8_t key[32] = {0};
    uint8_t buf[16];
    size_t len = 0;

    EXPECT_EQ(cslr_kuznyechik_encrypt(NULL, buf, 16, buf, &len), -1);
    EXPECT_EQ(cslr_kuznyechik_encrypt(key, buf, 16, NULL, &len), -1);
    EXPECT_EQ(cslr_kuznyechik_encrypt(key, buf, 16, buf, NULL), -1);
    EXPECT_EQ(cslr_kuznyechik_decrypt(NULL, buf, 16, buf), -1);
    EXPECT_EQ(cslr_kuznyechik_decrypt(key, NULL, 16, buf), -1);
    EXPECT_EQ(cslr_kuznyechik_decrypt(key, buf, 0, buf), -1);     // 0 не кратно... но и не >0
    EXPECT_EQ(cslr_kuznyechik_decrypt(key, buf, 15, buf), -1);    // не кратно 16
}

TEST(KuznyechikPublicAPI, Keygen) {
    uint8_t key[32];
    ASSERT_EQ(cslr_kuznyechik_keygen(NULL), -1);
    ASSERT_EQ(cslr_kuznyechik_keygen(key), 0);

    // Ключ не должен быть полностью нулевым (вероятность 2^-256)
    bool all_zero = true;
    for (int i = 0; i < 32; i++) if (key[i] != 0) { all_zero = false; break; }
    EXPECT_FALSE(all_zero);
} 
