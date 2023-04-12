/*
 * Copyright [2023] International Business Machines Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <err.h>
#include <strings.h>
#include <string.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "p_ibmca.h"

#ifdef SIXTY_FOUR_BIT_LONG
    #define BN_MASK2        (0xffffffffffffffffL)
#endif
#ifdef SIXTY_FOUR_BIT
    #define BN_MASK2        (0xffffffffffffffffLL)
#endif
#ifdef THIRTY_TWO_BIT
    #error "Not supported"
#endif

/*
 * Provider context used by mod-expo callback function for generating the
 * blinding factor by BN_BLINDING_create_param() or within BN_BLINDING_update()
 * when a new blinding factor is generated after 32 requests.
 * This variable must be thread local!
 */
static __thread const struct ibmca_prov_ctx *ibmca_mod_expo_provctx = NULL;

static int ibmca_rsa_blinding_bn_mod_exp(BIGNUM *r, const BIGNUM *a,
                                         const BIGNUM *p, const BIGNUM *m,
                                         BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    const struct ibmca_prov_ctx *provctx = ibmca_mod_expo_provctx;
    ica_rsa_key_mod_expo_t ica_mode_expo;
    unsigned char *buffer, *in, *out;
    size_t size;
    int rc = 0;

    if (provctx == NULL)
        return 0;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);

    size = BN_num_bytes(m);
    buffer = P_ZALLOC(provctx, 4 * size);
    if (buffer == NULL) {
        ibmca_debug_ctx(provctx,
                        "Failed to allocate a buffer for libica mod-expo");
        goto out;
    }

    ica_mode_expo.key_length = size;
    ica_mode_expo.modulus = buffer;
    ica_mode_expo.exponent = buffer + size;

    in = buffer + 2 * size;
    out = buffer + 3 * size;

    if (BN_bn2binpad(a, in, size) == -1 ||
        BN_bn2binpad(p, ica_mode_expo.exponent, size) == -1 ||
        BN_bn2binpad(m, ica_mode_expo.modulus, size) == -1) {
        ibmca_debug_ctx(provctx, "BN_bn2binpad failed");
        goto out;
    }

    rc = ica_rsa_mod_expo(provctx->ica_adapter, in, &ica_mode_expo, out);
    if (rc != 0) {
        ibmca_debug_ctx(provctx, "ica_rsa_mod_expo failed with: %s",
                        strerror(rc));
        rc = 0;
        goto out;
    }

    if (BN_bin2bn(out, size, r) == NULL) {
        ibmca_debug_ctx(provctx, "BN_bin2bn failed");
        goto out;
    }

    rc = 1;

out:
    P_CLEAR_FREE(provctx, buffer, 4 * size);

    ibmca_debug_ctx(provctx, "rc: %d", rc);

    /* Use software fallback if libica operation failed */
    return rc != 1 ? BN_mod_exp_mont(r, a, p, m, ctx, m_ctx) : 1;
}

static BN_BLINDING *ibmca_rsa_setup_blinding(struct ibmca_key *key)
{
    BIGNUM *n = NULL, *e = NULL;
    BN_CTX *bn_ctx = NULL;
    BN_BLINDING *blinding = NULL;
#ifndef HAVE_ALT_FIX_FOR_CVE2022_4304
    BIGNUM *R = NULL, *Ri = NULL, *tmod = NULL;
    BN_ULONG word;
#endif
    int rc;

    ibmca_debug_key(key, "key: %p", key);

    bn_ctx = BN_CTX_new_ex(key->provctx->libctx);
    if (bn_ctx == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_CTX_new_ex failed");
        goto out;
    }

    rc =  ibmca_keymgmt_rsa_pub_as_bn(key, &n, &e);
    if (rc == 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "No public key available");
        goto out;
    }

    BN_set_flags(n, BN_FLG_CONSTTIME);

    /*
     * Setup the BN_MONT_CTX if needed, it is required by for the mod-expo
     * callback passed to BN_BLINDING_create_param(). The callback won't be
     * called if BN_MONT_CTX is NULL.
     * We hold the write lock on blinding_lock when this function is called,
     * so no need to use BN_MONT_CTX_set_locked().
     */
    if (key->rsa.blinding_mont_ctx == NULL) {
        key->rsa.blinding_mont_ctx = BN_MONT_CTX_new();
        if (key->rsa.blinding_mont_ctx == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "BN_MONT_CTX_new failed");
            goto out;
        }

        if (BN_MONT_CTX_set(key->rsa.blinding_mont_ctx, n, bn_ctx) != 1) {
            BN_MONT_CTX_free(key->rsa.blinding_mont_ctx);
            key->rsa.blinding_mont_ctx = NULL;

            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "BN_MONT_CTX_new failed");
            goto out;
        }

#ifndef HAVE_ALT_FIX_FOR_CVE2022_4304
        /* Calculate blinding_mont_ctx_n0, BN_MONT_CTX is opaque */
        R = BN_CTX_get(bn_ctx);
        Ri = BN_CTX_get(bn_ctx);
        tmod = BN_CTX_get(bn_ctx);
        if (R == NULL || Ri == NULL || tmod == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_CTX_get failed");
            goto out;
        }

        BN_zero(R);
        if (!BN_set_bit(R, BN_BITS2)) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_set_bit failed");
            goto out;
        }

        memcpy(&word, key->rsa.public.modulus + key->rsa.public.key_length -
                      sizeof(BN_ULONG), sizeof(word));
        if (!BN_set_word(tmod, word)) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_set_word failed");
            goto out;
        }

        if (BN_is_one(tmod))
            BN_zero(Ri);
        else if ((BN_mod_inverse(Ri, R, tmod, bn_ctx)) == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_mod_inverse failed");
            goto out;
        }
        if (!BN_lshift(Ri, Ri, BN_BITS2)) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_lshift failed");
            goto out;
        }

        if (!BN_is_zero(Ri)) {
            if (!BN_sub_word(Ri, 1)) {
                put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_sub_word failed");
                goto out;
            }
        } else {
            if (!BN_set_word(Ri, BN_MASK2)) {
                put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_set_word failed");
                goto out;
            }
        }

        if (!BN_div(Ri, NULL, Ri, tmod, bn_ctx)) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_div failed");
            goto out;
        }

        key->rsa.blinding_mont_ctx_n0 = BN_get_word(Ri);
#endif
    }

    /*
     * BN_BLINDING_create_param() calls the ibmca_rsa_blinding_bn_mod_exp()
     * callback which needs to know the provider context.
     */
    ibmca_mod_expo_provctx = key->provctx;

    blinding = BN_BLINDING_create_param(NULL, e, n, bn_ctx,
                                        ibmca_rsa_blinding_bn_mod_exp,
                                        key->rsa.blinding_mont_ctx);
    if (blinding == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "BN_BLINDING_create_param failed");
        goto out;
    }

    BN_BLINDING_set_current_thread(blinding);

out:
    BN_free(n);
    BN_free(e);
    BN_CTX_free(bn_ctx);

    ibmca_debug_key(key, "blinding: %p", blinding);

    return blinding;
}

static BN_BLINDING *ibmca_rsa_get_blinding(struct ibmca_key *key, bool *local)
{
    BN_BLINDING *blinding = NULL;

    ibmca_debug_key(key, "key: %p", key);

    if (pthread_rwlock_rdlock(&key->rsa.blinding_lock) != 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "pthread_rwlock_rdlock failed: %s", strerror(errno));
        goto out;
    }

    while (1) {
        blinding = key->rsa.blinding;
        if (blinding != NULL) {
            if (BN_BLINDING_is_current_thread(blinding)) {
                *local = true;
            } else {
                /*
                 * BN_BLINDING is shared, meaning that accesses require locks,
                 * and that the blinding factor must be stored outside the
                 * BN_BLINDING
                 */
                *local = false;
                blinding = key->rsa.mt_blinding;
            }
        }

        pthread_rwlock_unlock(&key->rsa.blinding_lock);

        if (blinding != NULL)
            break;

        /* WR-lock the blinding lock while setting up the blinding */
        if (pthread_rwlock_wrlock(&key->rsa.blinding_lock) != 0) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "pthread_rwlock_wrlock failed: %s", strerror(errno));
            goto out;
        }

        if (key->rsa.blinding == NULL) {
            key->rsa.blinding = ibmca_rsa_setup_blinding(key);
            if (key->rsa.blinding == NULL) {
                pthread_rwlock_unlock(&key->rsa.blinding_lock);
                goto out;
            }

            continue;
        }

        if (key->rsa.mt_blinding == NULL) {
            key->rsa.mt_blinding = ibmca_rsa_setup_blinding(key);
            if (key->rsa.mt_blinding == NULL) {
                pthread_rwlock_unlock(&key->rsa.blinding_lock);
                goto out;
            }

            continue;
        }
    }

out:
    ibmca_debug_key(key, "blinding: %p local: %d", blinding, *local);

    return blinding;
}

static int ibmca_rsa_blinding_convert(struct ibmca_key *key,
                                      BN_BLINDING *blinding,
                                      BIGNUM *unblind, BN_CTX *bn_ctx,
                                      const unsigned char *in,
                                      unsigned char *out,
                                      size_t rsa_size, bool local)
{
    BIGNUM *bn_in;
    int rc = 0;

    ibmca_debug_key(key, "key: %p rsa_size: %lu local: %d",
                    key, rsa_size, local);

    bn_in = BN_CTX_get(bn_ctx);
    if (bn_in == NULL ||
        BN_bin2bn(in, (int)rsa_size, bn_in) == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                     "BN_CTX_get/BN_bin2bn failed");
        goto out;
    }

    if (!local) {
        /* Shared blinding requires locks */
        if (!BN_BLINDING_lock(blinding)) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "BN_BLINDING_lock failed");
            goto out;
        }
    }

    /* BN_BLINDING_convert_ex() calls BN_BLINDING_update() which may call
     * BN_BLINDING_create_param() to generate a new blinding factor. This
     * calls the ibmca_rsa_blinding_bn_mod_exp() callback which needs to know
     * the provider context.
     */
    ibmca_mod_expo_provctx = key->provctx;

    rc = BN_BLINDING_convert_ex(bn_in, unblind, blinding, bn_ctx);

    if (!local)
        BN_BLINDING_unlock(blinding);

    if (rc != 1) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "BN_BLINDING_convert_ex failed");
        goto out;
    }

    rc = BN_bn2binpad(bn_in, out, rsa_size);
    if (rc != (int)rsa_size) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_bn2binpad failed");
        goto out;
    }

    rc = 1;

out:
    ibmca_debug_key(key, "rc: %d", rc);

    return rc;
}

static int ibmca_rsa_blinding_invert(struct ibmca_key *key,
                                     BN_BLINDING *blinding,
                                     BIGNUM *unblind, BN_CTX *bn_ctx,
                                     const unsigned char *in,
                                     unsigned char *out,
                                     size_t rsa_size)
{
    int rc;
#ifdef HAVE_ALT_FIX_FOR_CVE2022_4304
    BIGNUM *bn_data = NULL;
#endif

    ibmca_debug_key(key, "key: %p rsa_size: %lu", key, rsa_size);

#ifdef HAVE_ALT_FIX_FOR_CVE2022_4304
    bn_data = BN_CTX_get(bn_ctx);
    if (bn_data == NULL ||
        BN_bin2bn(in, rsa_size, bn_data) == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "BN_CTX_get/BN_bin2bn failed");
        rc = 0;
        goto out;
    }
    BN_set_flags(bn_data, BN_FLG_CONSTTIME);

    /*
     * BN_BLINDING_invert_ex is constant-time since OpenSSL commit
     * https://github.com/openssl/openssl/commit/f06ef1657a3d4322153b26231a7afa3d55724e52
     * "Alternative fix for CVE-2022-4304". Care must be taken that bn_data
     * has flag BN_FLG_CONSTTIME set.
     *
     * Commits for OpenSSL releases:
     * - OpenSSL 1.1.1u:
     *   https://github.com/openssl/openssl/commit/3f499b24f3bcd66db022074f7e8b4f6ee266a3ae
     * - OpenSSL 3.0.9:
     *   https://github.com/openssl/openssl/commit/a00d757d9ca212994625d1a02c81cc5edd27e13b
     * - OpenSSl 3.1.1:
     *   https://github.com/openssl/openssl/commit/550a16247e899363ef973aa08623f9b19bb636fb
     */
    rc = BN_BLINDING_invert_ex(bn_data, unblind, blinding, bn_ctx);
    if (rc != 1) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "BN_BLINDING_invert_ex failed");
        rc = 0;
        goto out;
    }

    if (BN_bn2binpad(bn_data, out, rsa_size) != (int)rsa_size) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_bn2binpad failed");
        rc = 0;
        goto out;
    }
#else
    UNUSED(blinding);
    UNUSED(bn_ctx);

    rc = ossl_bn_rsa_do_unblind(in, unblind, key->rsa.public.modulus,
                                out, rsa_size, key->rsa.blinding_mont_ctx,
                                key->rsa.blinding_mont_ctx_n0);
    if (rc <= 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "ossl_bn_rsa_do_unblind failed");
        rc = 0;
        goto out;
    }
#endif

    rc = 1;

out:
    ibmca_debug_key(key, "rc: %d", rc);

    return rc;
}

int ibmca_rsa_crt_with_blinding(struct ibmca_key *key, const unsigned char *in,
                                unsigned char *out, size_t rsa_size)
{
    BN_BLINDING *blinding;
    bool local_blinding = false;
    BIGNUM *unblind = NULL;
    BN_CTX *bn_ctx = NULL;
    unsigned char *buf = NULL;
    int rc = 0;

    ibmca_debug_key(key, "key: %p rsa_size: %lu", key, rsa_size);

    if (rsa_size != key->rsa.private.key_length) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "rsa_size is not modulus size");
        goto out;
    }

    bn_ctx = BN_CTX_new_ex(key->provctx->libctx);
    if (bn_ctx == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_CTX_new_ex failed");
        goto out;
    }

    buf = P_SECURE_ZALLOC(key->provctx, rsa_size * 2);
    if (buf == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate blinding buffer");
        goto out;
    }

    blinding = ibmca_rsa_get_blinding(key, &local_blinding);
    if (blinding == NULL) {
        ibmca_debug_key(key, "ERROR: ibmca_keymgmt_rsa_get_blinding failed");
        goto out;
    }

    unblind = BN_CTX_get(bn_ctx);
    if (unblind == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_CTX_get failed");
        goto out;
    }

    BN_set_flags(unblind, BN_FLG_CONSTTIME);

    rc = ibmca_rsa_blinding_convert(key, blinding, unblind, bn_ctx,
                                    in, buf, rsa_size, local_blinding);
    if (rc == 0) {
        ibmca_debug_key(key,
                        "ERROR: ibmca_keymgmt_rsa_blinding_convert failed");
        goto out;
    }

    rc = ica_rsa_crt(key->provctx->ica_adapter, buf,
                     &key->rsa.private, buf + rsa_size);
    if (rc != 0) {
        ibmca_debug_key(key, "ERROR: ica_rsa_crt failed with: %s",
                        strerror(rc));
        rc = 0;
        goto out;
    }

    rc = ibmca_rsa_blinding_invert(key, blinding, unblind, bn_ctx,
                                   buf + rsa_size, out, rsa_size);
    if (rc == 0) {
        ibmca_debug_key(key,
                        "ERROR: ibmca_rsa_blinding_invert failed");
        goto out;
    }

    rc = 1;

out:
    if (buf != NULL)
        P_SECURE_CLEAR_FREE(key->provctx, buf, rsa_size * 2);
    if (bn_ctx != NULL)
        BN_CTX_free(bn_ctx);

    ibmca_debug_key(key, "rc: %d", rc);

    return rc;
}

