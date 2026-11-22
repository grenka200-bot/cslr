// rsa_test.cc
// Два теста для rsa.c:
//   1) генерация пары ключей;
//   2) генерация + шифрование + расшифрование (roundtrip).
//
// CSLR_RSA_NUM_PRIMES переопределён ДО включения rsa.c (u=32),
// чтобы "честный" keygen в тесте завершался за секунды-минуты.
//
// Тела generate_prime и keygen СКОПИРОВАНЫ в тест с отладочными
// выводами (по запросу). Оригиналы в rsa.c молчат.
// Решето (конструктор) не дублируется — используется g_sieve_primes
// из rsa.c, видимое через #include.

#include <gtest/gtest.h>

#include <gmp.h>
#include <pthread.h>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

// ---- Переопределение u ДО включения rsa.c ----
#undef  CSLR_RSA_NUM_PRIMES
#define CSLR_RSA_NUM_PRIMES 8
#include "rsa.c"
// ----------------------------------------------

// ------------------------------------------------------------------
//  Копия generate_prime с отладочными выводами
// ------------------------------------------------------------------
static int generate_prime_verbose(mpz_t out, size_t bits, size_t thread_idx)
{
    const size_t bytes = (bits + 7) / 8;
    const auto t_start = std::chrono::steady_clock::now();

    uint8_t  *rbuf     = NULL;
    uint32_t *residues = NULL;
    uint8_t  *sieve    = NULL;

    mpz_t base, cand, nm1, r, two;
    mpz_inits(base, cand, nm1, r, two, NULL);
    mpz_set_ui(two, 2);

    int rc = -1;
    size_t total_tested = 0;
    size_t total_fermat = 0;
    size_t windows = 0;

    rbuf = (uint8_t *)malloc(bytes);
    if (!rbuf) goto cleanup;
    residues = (uint32_t *)malloc(g_sieve_count * sizeof(uint32_t));
    if (!residues) goto cleanup;
    sieve = (uint8_t *)malloc(SIEVE_WINDOW);
    if (!sieve) goto cleanup;

    std::printf("[t%zu] старт: поиск простого %zu бит\n", thread_idx, bits);
    std::fflush(stdout);

    while (1) {
        windows++;
        if (fill_random(rbuf, bytes) != 0) goto cleanup;

        os2ip(base, rbuf, bytes);
        mpz_tdiv_r_2exp(base, base, bits);
        for (size_t b = 1; b <= 8; b++) mpz_setbit(base, bits - b);
        mpz_setbit(base, 0);

        for (size_t k = 0; k < g_sieve_count; k++)
            residues[k] = (uint32_t)mpz_fdiv_ui(base, g_sieve_primes[k]);

        memset(sieve, 0, SIEVE_WINDOW);
        for (size_t k = 0; k < g_sieve_count; k++) {
            uint64_t p  = g_sieve_primes[k];
            uint64_t r0 = residues[k];
            uint64_t i0 = ((p - r0) % p) * ((p + 1) / 2) % p;
            for (uint64_t i = i0; i < SIEVE_WINDOW; i += p)
                sieve[i] = 1;
        }
        {
            uint64_t r0 = mpz_fdiv_ui(base, RSA_E);
            uint64_t i0 = ((1 + RSA_E - r0) % RSA_E) * ((RSA_E + 1) / 2) % RSA_E;
            for (uint64_t i = i0; i < SIEVE_WINDOW; i += RSA_E)
                sieve[i] = 1;
        }

        size_t survivors = 0;
        for (uint32_t i = 0; i < SIEVE_WINDOW; i++) if (!sieve[i]) survivors++;
        total_tested += survivors;

        for (uint32_t i = 0; i < SIEVE_WINDOW; i++) {
            if (sieve[i]) continue;
            mpz_add_ui(cand, base, 2ul * i);
            if (mpz_sizeinbase(cand, 2) != bits) continue;

            mpz_sub_ui(nm1, cand, 1);
            mpz_powm(r, two, nm1, cand);
            if (mpz_cmp_ui(r, 1) != 0) continue;
            total_fermat++;

            if (mpz_probab_prime_p(cand, 25) == 0) continue;

            mpz_set(out, cand);
            rc = 0;
            {
                auto dt = std::chrono::duration<double>(
                    std::chrono::steady_clock::now() - t_start).count();
                std::printf("[t%zu] НАЙДЕНО простое %zu бит за %.2f c "
                            "(окон=%zu, кандидатов=%zu, Ферм�=%zu)\n",
                            thread_idx, bits, dt, windows, total_tested, total_fermat);
                std::fflush(stdout);
            }
            goto cleanup;
        }

        if ((windows & 0x0F) == 0) {
            auto dt = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - t_start).count();
            std::printf("[t%zu] %zu бит: %zu окон, %zu кандидатов, %.1f c...\n",
                        thread_idx, bits, windows, total_tested, dt);
            std::fflush(stdout);
        }
    }

cleanup:
    free(rbuf);
    free(residues);
    free(sieve);
    wipe_mpz(base); wipe_mpz(cand); wipe_mpz(nm1); wipe_mpz(r); wipe_mpz(two);
    mpz_clears(base, cand, nm1, r, two, NULL);
    return rc;
}

// ------------------------------------------------------------------
//  Обёртка для потока: печатает старт/финиш
// ------------------------------------------------------------------
struct verbose_job {
    mpz_t  *out;
    size_t  bits;
    size_t  index;
    int     rc;
};

static void *prime_thread_verbose(void *arg)
{
    verbose_job *job = (verbose_job *)arg;
    std::printf("[t%zu] поток запущен\n", job->index);
    std::fflush(stdout);
    job->rc = generate_prime_verbose(*job->out, job->bits, job->index);
    std::printf("[t%zu] поток завершён (%s)\n",
                job->index, job->rc == 0 ? "OK" : "ОШИБКА");
    std::fflush(stdout);
    return NULL;
}

// ------------------------------------------------------------------
//  Копия keygen с отладочными выводами
// ------------------------------------------------------------------
static int keygen_verbose(struct cslr_rsa_pub_key *pub,
                          struct cslr_rsa_priv_key *priv)
{
    if (!pub || !priv) return -1;
    if (CSLR_RSA_NUM_PRIMES < 2 || CSLR_RSA_NUM_PRIMES > 64) return -1;
    if (CSLR_RSA_KEY_BITS % CSLR_RSA_NUM_PRIMES != 0) return -1;

    const size_t u     = CSLR_RSA_NUM_PRIMES;
    const size_t pbits = CSLR_RSA_KEY_BITS / u;

    std::printf("[keygen] u=%zu, простые по %zu бит\n", u, pbits);
    std::fflush(stdout);

    mpz_t *primes = (mpz_t *)malloc(u * sizeof(mpz_t));
    if (!primes) return -1;
    for (size_t i = 0; i < u; i++) mpz_init(primes[i]);

    pthread_t    *threads = (pthread_t *)malloc(u * sizeof(pthread_t));
    verbose_job  *jobs    = (verbose_job *)malloc(u * sizeof(verbose_job));
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);
    mpz_set_ui(e, RSA_E);

    int rc = -1;
    if (!threads || !jobs) goto cleanup;

    {
        int attempt = 0;
        while (1) {
            attempt++;
            std::printf("[keygen] попытка %d\n", attempt);
            std::fflush(stdout);

            for (size_t i = 0; i < u; i++) {
                jobs[i].out   = &primes[i];
                jobs[i].bits  = pbits;
                jobs[i].index = i;
                jobs[i].rc    = -1;
            }
            size_t started = 0;
            for (; started < u; started++) {
                if (pthread_create(&threads[started], NULL,
                                   prime_thread_verbose, &jobs[started]) != 0)
                    break;
            }
            for (size_t j = 0; j < started; j++) pthread_join(threads[j], NULL);
            if (started != u) goto cleanup;
            for (size_t i = 0; i < u; i++) if (jobs[i].rc != 0) goto cleanup;

            int distinct = 1;
            for (size_t i = 0; i < u && distinct; i++)
                for (size_t j = i + 1; j < u && distinct; j++)
                    if (mpz_cmp(primes[i], primes[j]) == 0) distinct = 0;
            if (!distinct) {
                std::printf("[keygen] простые совпали, перегенерация\n");
                std::fflush(stdout);
                continue;
            }

            if (assemble_key(n, d, primes, u) != 0) {
                std::printf("[keygen] assemble_key failed, перегенерация\n");
                std::fflush(stdout);
                continue;
            }
            if (mpz_sizeinbase(n, 2) != CSLR_RSA_KEY_BITS) {
                std::printf("[keygen] n = %zu бит (нужно %d), перегенерация\n",
                            mpz_sizeinbase(n, 2), CSLR_RSA_KEY_BITS);
                std::fflush(stdout);
                continue;
            }
            std::printf("[keygen] все простые + ключ собраны (попытка %d)\n", attempt);
            std::fflush(stdout);
            break;
        }
    }

    if (i2osp(pub->n,   CSLR_RSA_KEY_BYTES, n) != 0) goto cleanup;
    if (i2osp(pub->e,   CSLR_RSA_KEY_BYTES, e) != 0) goto cleanup;
    if (i2osp(priv->n,  CSLR_RSA_KEY_BYTES, n) != 0) goto cleanup;
    if (i2osp(priv->d,  CSLR_RSA_KEY_BYTES, d) != 0) goto cleanup;

    rc = 0;

cleanup:
    for (size_t i = 0; i < u; i++) { wipe_mpz(primes[i]); mpz_clear(primes[i]); }
    free(primes); free(threads); free(jobs);
    wipe_mpz(n); wipe_mpz(e); wipe_mpz(d);
    mpz_clears(n, e, d, NULL);
    return rc;
}

// ------------------------------------------------------------------
//  Тест 1: генерация пары ключей
// ------------------------------------------------------------------
TEST(RSA, Keygen) {
    struct cslr_rsa_pub_key  pub;
    struct cslr_rsa_priv_key priv;
    std::memset(&pub,  0, sizeof(pub));
    std::memset(&priv, 0, sizeof(priv));

    auto t0 = std::chrono::steady_clock::now();
    ASSERT_EQ(keygen_verbose(&pub, &priv), 0);
    auto dt = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();
    std::printf("[test] keygen занял %.2f c\n", dt);
    std::fflush(stdout);

    EXPECT_NE(pub.n[0], 0) << "n has leading zero byte (not 32768 bits)";
    EXPECT_EQ(std::memcmp(pub.n, priv.n, CSLR_RSA_KEY_BYTES), 0);

    EXPECT_EQ(pub.e[CSLR_RSA_KEY_BYTES - 1], 0x01);
    EXPECT_EQ(pub.e[CSLR_RSA_KEY_BYTES - 2], 0x00);
    EXPECT_EQ(pub.e[CSLR_RSA_KEY_BYTES - 3], 0x01);
    EXPECT_EQ(pub.e[CSLR_RSA_KEY_BYTES - 4], 0x00);

    bool d_nonzero = false;
    for (size_t i = 0; i < CSLR_RSA_KEY_BYTES; i++)
        if (priv.d[i] != 0) { d_nonzero = true; break; }
    EXPECT_TRUE(d_nonzero);

    std::printf("[test] n[0..7] = ");
    for (int i = 0; i < 8; i++) std::printf("%02x", pub.n[i]);
    std::printf("...\n");
    std::printf("[test] d[0..7] = ");
    for (int i = 0; i < 8; i++) std::printf("%02x", priv.d[i]);
    std::printf("...\n");
    std::fflush(stdout);
}

// ------------------------------------------------------------------
//  Тест 2: генерация + шифрование + расшифрование
// ------------------------------------------------------------------
TEST(RSA, KeygenEncryptDecryptRoundtrip) {
    struct cslr_rsa_pub_key  pub;
    struct cslr_rsa_priv_key priv;
    std::memset(&pub,  0, sizeof(pub));
    std::memset(&priv, 0, sizeof(priv));

    ASSERT_EQ(keygen_verbose(&pub, &priv), 0);

    uint8_t msg[100];
    for (int i = 0; i < 100; i++) msg[i] = (uint8_t)(i + 1);

    uint8_t ct[CSLR_RSA_KEY_BYTES];
    uint8_t pt[CSLR_RSA_KEY_BYTES];
    size_t  ct_len = 0, pt_len = 0;

    std::printf("[test] encrypt 100 байт...\n");
    std::fflush(stdout);
    ASSERT_EQ(cslr_rsa_encrypt(&pub, msg, sizeof(msg), ct, &ct_len), 0);
    EXPECT_EQ(ct_len, CSLR_RSA_KEY_BYTES);
    std::printf("[test] encrypt OK (%zu байт)\n", ct_len);
    std::fflush(stdout);

    std::printf("[test] decrypt...\n");
    std::fflush(stdout);
    ASSERT_EQ(cslr_rsa_decrypt(&priv, ct, ct_len, pt, &pt_len), 0);
    EXPECT_EQ(pt_len, CSLR_RSA_KEY_BYTES);
    std::printf("[test] decrypt OK (%zu байт)\n", pt_len);
    std::fflush(stdout);

    const size_t pad = CSLR_RSA_KEY_BYTES - sizeof(msg);
    EXPECT_EQ(std::memcmp(pt + pad, msg, sizeof(msg)), 0);
    for (size_t i = 0; i < pad; i++)
        EXPECT_EQ(pt[i], 0) << "byte " << i << " not zero";

    std::printf("[test] roundtrip OK\n");
    std::fflush(stdout);
}
// ------------------------------------------------------------------
//  Test 3: generate_prime returns an actual prime of the requested size
// ------------------------------------------------------------------
TEST(RSA, PrimeIsActuallyPrime) {
    const size_t bits = 1024;   // fast; change to 4096 and wait for slower run

    mpz_t p;
    mpz_init(p);

    auto t0 = std::chrono::steady_clock::now();
    ASSERT_EQ(generate_prime(p, bits), 0);
    auto dt = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();

    // 1. Exactly `bits` bits
    EXPECT_EQ(mpz_sizeinbase(p, 2), bits)
        << "p has wrong bit length";

    // 2. Odd
    EXPECT_EQ(mpz_tstbit(p, 0), 1)
        << "p is even";

    // 3. p != 1 (mod e), otherwise gcd(e, p-1) != 1
    EXPECT_NE(mpz_fdiv_ui(p, RSA_E), 1u)
        << "p is 1 mod e";

    // 4. Actually prime (25 Miller-Rabin rounds)
    EXPECT_NE(mpz_probab_prime_p(p, 25), 0)
        << "p is composite";

    std::printf("[test] generate_prime(%zu bits) took %.2f s, p = ",
                bits, dt);
    {
        char *hex = mpz_get_str(nullptr, 16, p);
        std::printf("%.8s...\n", hex);
        free(hex);
    }
    std::fflush(stdout);

    mpz_clear(p);
}

// ------------------------------------------------------------------
//  Test 4: d is a valid inverse of e modulo lambda(n)
//
//  lambda(n) is not exposed by keygen, but the equivalent property
//  m^(e*d) == m (mod n) for all m can be checked directly.
//  This test builds a small key manually (u=4, 256-bit primes, n=1024
//  bits), so it does NOT depend on CSLR_RSA_NUM_PRIMES and runs fast
//  regardless of the #define in this file.
// ------------------------------------------------------------------
TEST(RSA, DIsValidInverse) {
    // Generate 4 small primes (256 bits each), assemble n = 1024 bits.
    const size_t u = 4;
    const size_t pbits = 256;

    mpz_t primes[4];
    for (size_t i = 0; i < u; i++) {
        mpz_init(primes[i]);
        ASSERT_EQ(generate_prime(primes[i], pbits), 0)
            << "generate_prime failed for prime " << i;
    }

    mpz_t n, d;
    mpz_inits(n, d, NULL);
    ASSERT_EQ(assemble_key(n, d, primes, u), 0)
        << "assemble_key failed";

    mpz_t e;
    mpz_init_set_ui(e, RSA_E);

    // Verify m^(e*d) == m (mod n) for several m
    mpz_t ed;
    mpz_init(ed);
    mpz_mul(ed, e, d);

    const unsigned long test_ms[] = {0, 1, 2, 12345, 0xDEADBEEF, 0xFFFFFFFF};
    for (unsigned long m_val : test_ms) {
        mpz_t m, check;
        mpz_inits(m, check, NULL);
        mpz_set_ui(m, m_val);
        mpz_powm(check, m, ed, n);
        EXPECT_EQ(mpz_cmp(check, m), 0)
            << "m^(e*d) != m (mod n) for m = " << m_val;
        mpz_clears(m, check, NULL);
    }

    std::printf("[test] d is a valid inverse: m^(e*d) == m (mod n) "
                "for %zu values of m\n",
                sizeof(test_ms) / sizeof(test_ms[0]));
    std::fflush(stdout);

    for (size_t i = 0; i < u; i++) { wipe_mpz(primes[i]); mpz_clear(primes[i]); }
    mpz_clears(n, d, e, ed, NULL);
}

