 // rsa.c
// RSA-32768 (многопростой, RFC 8017 §3) на базе GNU MP.
//
// Внутренние детали реализации:
//   - Длинная арифметика — GNU MP (GMP).
//   - Многопростой RSA: n = r_1 * ... * r_u, u = CSLR_RSA_NUM_PRIMES
//     (из rsa.h, по умолчанию 4). Каждое простое — 32768/u бит.
//   - Поиск простых ускорен решетом Эратосфена по малым простым
//     до SIEVE_LIMIT = 2^24. Таблица строится один раз при загрузке
//     модуля через __attribute__((constructor)) — GCC/Clang-расширение,
//     для Ubuntu + gcc допустимо. При переносе на другую платформу
//     заменить на pthread_once.
//   - Само решето и его размер — static-переменные внутри этого файла.
//     В тестах доступны через #include "rsa.c" (white-box).
//   - Генерация u простых распараллелена по потокам (по одному на
//     простое). Задача embarrassingly parallel: потоки не разделяют
//     записываемых данных, только читают общую таблицу простых.
//
// Режим — raw RSA (RSAEP/RSADP по RFC 8017 §5.1), без паддинга.
// Это учебная реализация, криптостойкости без паддинга нет.

#include "rsa.h"

#include <gmp.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/* Открытая экспонента фиксирована (как в эталоне rsa.cpp / rsa_gmp.hpp). */
#define RSA_E 65537UL

/* Верхняя граница решета малых простых: 2^24 = 16 777 216. */
#define SIEVE_LIMIT (1u << 24)

/* Окно нечётных кандидатов, проверяемых за один проход решета. */
#define SIEVE_WINDOW (1u << 16)

/* ------------------------------------------------------------------ */
/*  Решето малых простых (static, строится конструктором до main())   */
/* ------------------------------------------------------------------ */

/* ~1.08 млн простых до 2^24, с запасом. */
static uint32_t g_sieve_primes[1200000];
static size_t   g_sieve_count = 0;

__attribute__((constructor))
static void rsa_sieve_init(void)
{
    if (g_sieve_count != 0) return;

    /* comp[i] == 1, если i составное. 16 МБ в BSS. */
    static uint8_t comp[SIEVE_LIMIT + 1];

    for (uint32_t i = 3; i <= SIEVE_LIMIT; i += 2) {
        if (comp[i]) continue;
        g_sieve_primes[g_sieve_count++] = i;
        for (uint64_t j = (uint64_t)i * i; j <= SIEVE_LIMIT; j += 2ull * i)
            comp[j] = 1;
    }
}

/* ------------------------------------------------------------------ */
/*  Вспомогательные функции                                           */
/* ------------------------------------------------------------------ */

/* Затирает лимбы mpz_t перед освобождением (секретные данные). */
static void wipe_mpz(mpz_t v)
{
    size_t n = mpz_size(v);
    if (n == 0) { mpz_set_ui(v, 0); return; }
    mp_limb_t *d = mpz_limbs_modify(v, n);
    volatile mp_limb_t *vd = d;
    for (size_t i = 0; i < n; i++) vd[i] = 0;
    mpz_set_ui(v, 0);
}

/* Читает len байт из /dev/urandom. Возвращает 0 при успехе, -1 при ошибке. */
static int fill_random(uint8_t *buf, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t got = fread(buf, 1, len, f);
    fclose(f);
    return (got == len) ? 0 : -1;
}

/* Big-endian bytes -> mpz_t. */
static void os2ip(mpz_t out, const uint8_t *data, size_t len)
{
    mpz_import(out, len, 1, 1, 1, 0, data);
}

/* mpz_t -> big-endian bytes фиксированной длины len.
 * Возвращает 0, если число влезает в len байт, -1 иначе. */
static int i2osp(uint8_t *out, size_t len, const mpz_t x)
{
    size_t need = (mpz_sizeinbase(x, 2) + 7) / 8;
    if (mpz_sgn(x) == 0) need = 0;
    if (need > len) return -1;

    memset(out, 0, len);
    if (need == 0) return 0;

    size_t written = 0;
    mpz_export(out + (len - need), &written, 1, 1, 1, 0, x);
    return (written == need) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/*  Генерация одного простого числа                                   */
/* ------------------------------------------------------------------ */

/* Генерирует простое p ровно bits бит, p ≡ 1 (mod RSA_E) не допускается.
 * Четыре старших бита = 1 — гарантия, что произведение u таких чисел
 * даст ровно bits*u бит.
 *
 * Возвращает 0 при успехе, -1 при ошибке. */
static int generate_prime(mpz_t out, size_t bits)
{
    const size_t bytes = (bits + 7) / 8;

    uint8_t  *rbuf     = NULL;
    uint32_t *residues = NULL;
    uint8_t  *sieve    = NULL;

    mpz_t base, cand, nm1, r, two;
    mpz_inits(base, cand, nm1, r, two, NULL);
    mpz_set_ui(two, 2);

    int rc = -1;

    rbuf = (uint8_t *)malloc(bytes);
    if (!rbuf) goto cleanup;

    residues = (uint32_t *)malloc(g_sieve_count * sizeof(uint32_t));
    if (!residues) goto cleanup;

    sieve = (uint8_t *)malloc(SIEVE_WINDOW);
    if (!sieve) goto cleanup;

    while (1) {
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

        for (uint32_t i = 0; i < SIEVE_WINDOW; i++) {
            if (sieve[i]) continue;
            mpz_add_ui(cand, base, 2ul * i);
            if (mpz_sizeinbase(cand, 2) != bits) continue;

            mpz_sub_ui(nm1, cand, 1);
            mpz_powm(r, two, nm1, cand);
            if (mpz_cmp_ui(r, 1) != 0) continue;

            if (mpz_probab_prime_p(cand, 25) == 0) continue;

            mpz_set(out, cand);
            rc = 0;
            goto cleanup;
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

/* ------------------------------------------------------------------ */
/*  Параллельная генерация u простых                                  */
/* ------------------------------------------------------------------ */

struct prime_job {
    mpz_t  *out;
    size_t  bits;
    int     rc;
};

static void *prime_thread(void *arg)
{
    struct prime_job *job = (struct prime_job *)arg;
    job->rc = generate_prime(*job->out, job->bits);
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Сборка ключа из u простых                                         */
/* ------------------------------------------------------------------ */

/* По массиву primes[0..u-1] вычисляет n и d (d = e^{-1} mod λ(n),
 * λ(n) = НОК(r_i - 1)). Возвращает 0 при успехе, -1 при ошибке. */
static int assemble_key(mpz_t n, mpz_t d, const mpz_t *primes, size_t u)
{
    mpz_t lambda, pm1, e;
    mpz_inits(lambda, pm1, e, NULL);
    mpz_set_ui(lambda, 1);
    mpz_set_ui(n, 1);
    mpz_set_ui(e, RSA_E);

    int rc = 0;
    for (size_t i = 0; i < u; i++) {
        mpz_mul(n, n, primes[i]);
        mpz_sub_ui(pm1, primes[i], 1);
        mpz_lcm(lambda, lambda, pm1);
    }
    if (mpz_invert(d, e, lambda) == 0) rc = -1;
    if (rc == 0 && mpz_sizeinbase(d, 2) <= mpz_sizeinbase(n, 2) / 2) rc = -1;

    wipe_mpz(e); wipe_mpz(lambda); wipe_mpz(pm1);
    mpz_clears(lambda, pm1, e, NULL);
    return rc;
}

/* ------------------------------------------------------------------ */
/*  Примитивы RSAEP / RSADP                                           */
/* ------------------------------------------------------------------ */

/* c = m^e mod n. Требует 0 <= m < n. */
static void rsaep(mpz_t c, const mpz_t n, const mpz_t e, const mpz_t m)
{
    mpz_powm(c, m, e, n);
}

/* m = c^d mod n. Требует 0 <= c < n. */
static void rsadp(mpz_t m, const mpz_t n, const mpz_t d, const mpz_t c)
{
    mpz_powm(m, c, d, n);
}

/* ------------------------------------------------------------------ */
/*  Публичный API                                                     */
/* ------------------------------------------------------------------ */

int cslr_rsa_keygen(struct cslr_rsa_pub_key *pub,
                    struct cslr_rsa_priv_key *priv)
{
    if (!pub || !priv) return -1;
    if (CSLR_RSA_NUM_PRIMES < 2 || CSLR_RSA_NUM_PRIMES > 64) return -1;
    if (CSLR_RSA_KEY_BITS % CSLR_RSA_NUM_PRIMES != 0) return -1;

    const size_t u     = CSLR_RSA_NUM_PRIMES;
    const size_t pbits = CSLR_RSA_KEY_BITS / u;

    mpz_t *primes = (mpz_t *)malloc(u * sizeof(mpz_t));
    if (!primes) return -1;
    for (size_t i = 0; i < u; i++) mpz_init(primes[i]);

    pthread_t        *threads = (pthread_t *)malloc(u * sizeof(pthread_t));
    struct prime_job *jobs    = (struct prime_job *)malloc(u * sizeof(struct prime_job));
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);
    mpz_set_ui(e, RSA_E);

    int rc = -1;
    if (!threads || !jobs) goto cleanup;

    while (1) {
        for (size_t i = 0; i < u; i++) {
            jobs[i].out  = &primes[i];
            jobs[i].bits = pbits;
            jobs[i].rc   = -1;
        }
        size_t started = 0;
        for (; started < u; started++) {
            if (pthread_create(&threads[started], NULL, prime_thread, &jobs[started]) != 0)
                break;
        }
        for (size_t j = 0; j < started; j++) pthread_join(threads[j], NULL);
        if (started != u) goto cleanup;
        for (size_t i = 0; i < u; i++) if (jobs[i].rc != 0) goto cleanup;

        int distinct = 1;
        for (size_t i = 0; i < u && distinct; i++)
            for (size_t j = i + 1; j < u && distinct; j++)
                if (mpz_cmp(primes[i], primes[j]) == 0) distinct = 0;
        if (!distinct) continue;

        if (assemble_key(n, d, primes, u) != 0) continue;
        if (mpz_sizeinbase(n, 2) != CSLR_RSA_KEY_BITS) continue;
        break;
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

int cslr_rsa_encrypt(const struct cslr_rsa_pub_key *pub,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len)
{
    if (!pub || !out || !out_len) return -1;
    if (!in && in_len != 0) return -1;
    if (in_len == 0) { *out_len = 0; return 0; }

    const size_t block   = CSLR_RSA_KEY_BYTES;
    const size_t nblocks = (in_len + block - 1) / block;

    mpz_t n, e, m, c;
    mpz_inits(n, e, m, c, NULL);
    os2ip(n, pub->n, block);
    os2ip(e, pub->e, block);

    int rc = -1;
    for (size_t b = 0; b < nblocks; b++) {
        size_t off = b * block;
        size_t len = (in_len - off < block) ? (in_len - off) : block;

        uint8_t buf[CSLR_RSA_KEY_BYTES];
        memset(buf, 0, block);
        memcpy(buf + (block - len), in + off, len);

        os2ip(m, buf, block);
        if (mpz_cmp(m, n) >= 0) { rc = -1; goto done; }

        rsaep(c, n, e, m);
        if (i2osp(out + off, block, c) != 0) { rc = -1; goto done; }
    }
    *out_len = nblocks * block;
    rc = 0;

done:
    wipe_mpz(n); wipe_mpz(e); wipe_mpz(m); wipe_mpz(c);
    mpz_clears(n, e, m, c, NULL);
    return rc;
}

int cslr_rsa_decrypt(const struct cslr_rsa_priv_key *priv,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len)
{
    if (!priv || !in || !out || !out_len) return -1;
    if (in_len == 0 || (in_len % CSLR_RSA_KEY_BYTES) != 0) return -1;

    const size_t block   = CSLR_RSA_KEY_BYTES;
    const size_t nblocks = in_len / block;

    mpz_t n, d, c, m;
    mpz_inits(n, d, c, m, NULL);
    os2ip(n, priv->n, block);
    os2ip(d, priv->d, block);

    int rc = -1;
    for (size_t b = 0; b < nblocks; b++) {
        size_t off = b * block;
        os2ip(c, in + off, block);
        if (mpz_cmp(c, n) >= 0) { rc = -1; goto done; }

        rsadp(m, n, d, c);
        if (i2osp(out + off, block, m) != 0) { rc = -1; goto done; }
    }
    *out_len = in_len;
    rc = 0;

done:
    wipe_mpz(n); wipe_mpz(d); wipe_mpz(c); wipe_mpz(m);
    mpz_clears(n, d, c, m, NULL);
    return rc;
}

