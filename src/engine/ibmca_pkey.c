/*
 * Copyright 2019-2021 International Business Machines Corp.
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
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/obj_mac.h>

#include "ibmca.h"
#include "e_ibmca_err.h"

#include "openssl-compat.h"

ica_x25519_ctx_new_t		p_ica_x25519_ctx_new;
ica_x448_ctx_new_t		p_ica_x448_ctx_new;
ica_ed25519_ctx_new_t		p_ica_ed25519_ctx_new;
ica_ed448_ctx_new_t		p_ica_ed448_ctx_new;
ica_x25519_key_set_t		p_ica_x25519_key_set;
ica_x448_key_set_t		p_ica_x448_key_set;
ica_ed25519_key_set_t		p_ica_ed25519_key_set;
ica_ed448_key_set_t		p_ica_ed448_key_set;
ica_x25519_key_get_t		p_ica_x25519_key_get;
ica_x448_key_get_t		p_ica_x448_key_get;
ica_ed25519_key_get_t		p_ica_ed25519_key_get;
ica_ed448_key_get_t		p_ica_ed448_key_get;
ica_x25519_key_gen_t		p_ica_x25519_key_gen;
ica_x448_key_gen_t		p_ica_x448_key_gen;
ica_ed25519_key_gen_t		p_ica_ed25519_key_gen;
ica_ed448_key_gen_t		p_ica_ed448_key_gen;
ica_x25519_derive_t		p_ica_x25519_derive;
ica_x448_derive_t		p_ica_x448_derive;
ica_ed25519_sign_t		p_ica_ed25519_sign;
ica_ed448_sign_t		p_ica_ed448_sign;
ica_ed25519_verify_t		p_ica_ed25519_verify;
ica_ed448_verify_t		p_ica_ed448_verify;
ica_x25519_ctx_del_t		p_ica_x25519_ctx_del;
ica_x448_ctx_del_t		p_ica_x448_ctx_del;
ica_ed25519_ctx_del_t		p_ica_ed25519_ctx_del;
ica_ed448_ctx_del_t		p_ica_ed448_ctx_del;

static EVP_PKEY_METHOD *ibmca_x25519_pmeth = NULL;
static EVP_PKEY_METHOD *ibmca_x448_pmeth = NULL;
static EVP_PKEY_METHOD *ibmca_ed25519_pmeth = NULL;
static EVP_PKEY_METHOD *ibmca_ed448_pmeth = NULL;

/* X25519 */

static int ibmca_x25519_keygen(EVP_PKEY_CTX *c, EVP_PKEY *pkey)
{
    unsigned char priv[32], pub[32], *private = NULL;
    ECX_KEY *key = NULL;
    ICA_X25519_CTX *ctx = NULL;
    int rc = 0;

    if (p_ica_x25519_ctx_new(&ctx) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_X25519_KEYGEN, IBMCA_R_PKEY_INTERNAL_ERROR);
        goto ret;
    }
    if (p_ica_x25519_key_gen(ctx) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_X25519_KEYGEN, IBMCA_R_PKEY_KEYGEN_FAILED);
        goto ret;
    }
    if (p_ica_x25519_key_get(ctx, priv, pub) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_X25519_KEYGEN, IBMCA_R_PKEY_KEYGEN_FAILED);
        goto ret;
    }

    key = ossl_ecx_key_new_simple(ECX_KEY_TYPE_X25519);
    private = calloc(1, sizeof(priv));
    if (key == NULL || private == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_X25519_KEYGEN, IBMCA_R_PKEY_KEYGEN_FAILED);
        goto ret;
    }

    memcpy(private, priv, sizeof(priv));
    ossl_ecx_copypubkey(key, pub, sizeof(pub));
    ossl_ecx_set0_privkey(key, private);

    EVP_PKEY_assign(pkey, NID_X25519, key);
    rc = 1;
ret:
    if (rc == 0) {
        free(key);
        free(private);
    }
    if (ctx != NULL)
        p_ica_x25519_ctx_del(&ctx);
    return rc;
}

static int ibmca_x25519_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    if (type == EVP_PKEY_CTRL_PEER_KEY)
        return 1;

    return -2;
}

static int ibmca_x25519_derive(EVP_PKEY_CTX *pkey_ctx, unsigned char *key, size_t *keylen)
{
    ICA_X25519_CTX *ctx = NULL;
    ECX_KEY *key_ecx = NULL, *peerkey_ecx = NULL;
    EVP_PKEY *key_pkey = NULL, *peerkey_pkey = NULL;
    int rc = 0;

    *keylen = 32;
    if (key == NULL) {
        rc = 1;
        goto ret;
    }

    key_pkey = EVP_PKEY_CTX_get0_pkey(pkey_ctx);
    peerkey_pkey = EVP_PKEY_CTX_get0_peerkey(pkey_ctx);
    if (key_pkey == NULL || peerkey_pkey == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_X25519_DERIVE, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    key_ecx = EVP_PKEY_get0(key_pkey);
    peerkey_ecx = EVP_PKEY_get0(peerkey_pkey);
    if (key_ecx == NULL || peerkey_ecx == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_X25519_DERIVE, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    if (p_ica_x25519_ctx_new(&ctx) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_X25519_DERIVE, IBMCA_R_PKEY_INTERNAL_ERROR);
        goto ret;
    }

    if (p_ica_x25519_key_set(ctx, ossl_ecx_get0_privkey(key_ecx), NULL) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_X25519_DERIVE, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    if (p_ica_x25519_derive(ctx, key, ossl_ecx_get0_pubkey(peerkey_ecx)) != 0)
        goto ret;

    rc = 1;
ret:
    if (ctx != NULL)
        p_ica_x25519_ctx_del(&ctx);
    return rc;
}

/* X448 */

static int ibmca_x448_keygen(EVP_PKEY_CTX *c, EVP_PKEY *pkey)
{
    unsigned char priv[56], pub[56], *private = NULL;
    ECX_KEY *key = NULL;
    ICA_X448_CTX *ctx = NULL;
    int rc = 0;

    if (p_ica_x448_ctx_new(&ctx) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_X448_KEYGEN, IBMCA_R_PKEY_INTERNAL_ERROR);
        goto ret;
    }
    if (p_ica_x448_key_gen(ctx) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_X448_KEYGEN, IBMCA_R_PKEY_KEYGEN_FAILED);
        goto ret;
    }
    if (p_ica_x448_key_get(ctx, priv, pub) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_X448_KEYGEN, IBMCA_R_PKEY_KEYGEN_FAILED);
        goto ret;
    }

    key = ossl_ecx_key_new_simple(ECX_KEY_TYPE_X448);
    private = calloc(1, sizeof(priv));
    if (key == NULL || private == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_X448_KEYGEN, IBMCA_R_PKEY_KEYGEN_FAILED);
        goto ret;
    }

    memcpy(private, priv, sizeof(priv));
    ossl_ecx_copypubkey(key, pub, sizeof(pub));
    ossl_ecx_set0_privkey(key, private);

    EVP_PKEY_assign(pkey, NID_X448, key);
    rc = 1;
ret:
    if (rc == 0) {
        free(key);
        free(private);
    }
    if (ctx != NULL)
        p_ica_x448_ctx_del(&ctx);
    return rc;
}

static int ibmca_x448_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    if (type == EVP_PKEY_CTRL_PEER_KEY)
        return 1;

    return -2;
}

static int ibmca_x448_derive(EVP_PKEY_CTX *pkey_ctx, unsigned char *key, size_t *keylen)
{
    ICA_X448_CTX *ctx = NULL;
    ECX_KEY *key_ecx = NULL, *peerkey_ecx = NULL;
    EVP_PKEY *key_pkey = NULL, *peerkey_pkey = NULL;
    int rc = 0;

    *keylen = 56;
    if (key == NULL) {
        rc = 1;
        goto ret;
    }

    key_pkey = EVP_PKEY_CTX_get0_pkey(pkey_ctx);
    peerkey_pkey = EVP_PKEY_CTX_get0_peerkey(pkey_ctx);
    if (key_pkey == NULL || peerkey_pkey == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_X448_DERIVE, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    key_ecx = EVP_PKEY_get0(key_pkey);
    peerkey_ecx = EVP_PKEY_get0(peerkey_pkey);
    if (key_ecx == NULL || peerkey_ecx == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_X448_DERIVE, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    if (p_ica_x448_ctx_new(&ctx) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_X448_DERIVE, IBMCA_R_PKEY_INTERNAL_ERROR);
        goto ret;
    }

    if (p_ica_x448_key_set(ctx, ossl_ecx_get0_privkey(key_ecx), NULL) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_X448_DERIVE, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    if (p_ica_x448_derive(ctx, key, ossl_ecx_get0_pubkey(peerkey_ecx)) != 0)
        goto ret;

    rc = 1;
ret:
    if (ctx != NULL)
        p_ica_x448_ctx_del(&ctx);
    return rc;
}

/* ED25519 */

static int ibmca_ed25519_copy(EVP_PKEY_CTX *to, const EVP_PKEY_CTX *from)
{
    return 1;
}

static int ibmca_ed25519_keygen(EVP_PKEY_CTX *c, EVP_PKEY *pkey)
{
    unsigned char priv[32], pub[32], *private = NULL;
    ECX_KEY *key = NULL;
    ICA_ED25519_CTX *ctx = NULL;
    int rc = 0;

    if (p_ica_ed25519_ctx_new(&ctx) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_ED25519_KEYGEN, IBMCA_R_PKEY_INTERNAL_ERROR);
        goto ret;
    }
    if (p_ica_ed25519_key_gen(ctx) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_ED25519_KEYGEN, IBMCA_R_PKEY_KEYGEN_FAILED);
        goto ret;
    }
    if (p_ica_ed25519_key_get(ctx, priv, pub) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_ED25519_KEYGEN, IBMCA_R_PKEY_KEYGEN_FAILED);
        goto ret;
    }

    key = ossl_ecx_key_new_simple(ECX_KEY_TYPE_ED25519);
    private = calloc(1, sizeof(priv));
    if (key == NULL || private == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ED25519_KEYGEN, IBMCA_R_PKEY_KEYGEN_FAILED);
        goto ret;
    }

    memcpy(private, priv, sizeof(priv));
    ossl_ecx_copypubkey(key, pub, sizeof(pub));
    ossl_ecx_set0_privkey(key, private);

    EVP_PKEY_assign(pkey, NID_ED25519, key);
    rc = 1;
ret:
    if (rc == 0) {
        free(key);
        free(private);
    }
    if (ctx != NULL)
        p_ica_ed25519_ctx_del(&ctx);
    return rc;
}

static int ibmca_ed25519_sign(EVP_MD_CTX *md_ctx, unsigned char *sig,
                              size_t *siglen, const unsigned char *tbs,
                              size_t tbslen)
{
    ICA_ED25519_CTX *ctx = NULL;
    ECX_KEY *key_ecx = NULL;
    EVP_PKEY *key_pkey = NULL;
    int rc = 0;

    if (sig == NULL) {
        *siglen = 2 * 32;
        return 1;
    }

    if (*siglen < 2 * 32)
        goto ret;

    key_pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(md_ctx));
    if (key_pkey == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ED25519_SIGN, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    key_ecx = EVP_PKEY_get0(key_pkey);
    if (key_ecx == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ED25519_SIGN, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    if (p_ica_ed25519_ctx_new(&ctx) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_ED25519_SIGN, IBMCA_R_PKEY_INTERNAL_ERROR);
        goto ret;
    }

    if (p_ica_ed25519_key_set(ctx, ossl_ecx_get0_privkey(key_ecx), NULL) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_ED25519_SIGN, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    if (p_ica_ed25519_sign(ctx, sig, tbs, tbslen) != 0)
        goto ret;

    *siglen = 2 * 32;
    rc = 1;
ret:
    if (ctx != NULL)
        p_ica_ed25519_ctx_del(&ctx);
    return rc;
}

static int ibmca_ed25519_verify(EVP_MD_CTX *md_ctx, const unsigned char *sig,
                                size_t siglen, const unsigned char *tbv,
                                size_t tbvlen)
{
    ICA_ED25519_CTX *ctx = NULL;
    ECX_KEY *key_ecx = NULL;
    EVP_PKEY *key_pkey = NULL;
    int rc = 0;

    if (sig == NULL || siglen != 2 * 32)
        goto ret;

    key_pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(md_ctx));
    if (key_pkey == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ED25519_VERIFY, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    key_ecx = EVP_PKEY_get0(key_pkey);
    if (key_ecx == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ED25519_VERIFY, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    if (p_ica_ed25519_ctx_new(&ctx) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_ED25519_VERIFY, IBMCA_R_PKEY_INTERNAL_ERROR);
        goto ret;
    }

    if (p_ica_ed25519_key_set(ctx, NULL, ossl_ecx_get0_pubkey(key_ecx)) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_ED25519_VERIFY, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    if (p_ica_ed25519_verify(ctx, sig, tbv, tbvlen) != 0)
        goto ret;

    rc = 1;
ret:
    if (ctx != NULL)
        p_ica_ed25519_ctx_del(&ctx);
    return rc;
}

/* ED448 */

static int ibmca_ed448_copy(EVP_PKEY_CTX *to, const EVP_PKEY_CTX *from)
{
    return 1;
}

static int ibmca_ed448_keygen(EVP_PKEY_CTX *c, EVP_PKEY *pkey)
{
    unsigned char priv[57], pub[57], *private = NULL;
    ECX_KEY *key = NULL;
    ICA_ED448_CTX *ctx = NULL;
    int rc = 0;

    if (p_ica_ed448_ctx_new(&ctx) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_ED448_KEYGEN, IBMCA_R_PKEY_INTERNAL_ERROR);
        goto ret;
    }
    if (p_ica_ed448_key_gen(ctx) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_ED448_KEYGEN, IBMCA_R_PKEY_KEYGEN_FAILED);
        goto ret;
    }
    if (p_ica_ed448_key_get(ctx, priv, pub) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_ED448_KEYGEN, IBMCA_R_PKEY_KEYGEN_FAILED);
        goto ret;
    }

    key = ossl_ecx_key_new_simple(ECX_KEY_TYPE_ED448);
    private = calloc(1, sizeof(priv));
    if (key == NULL || private == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ED448_KEYGEN, IBMCA_R_PKEY_KEYGEN_FAILED);
        goto ret;
    }

    memcpy(private, priv, sizeof(priv));
    ossl_ecx_copypubkey(key, pub, sizeof(pub));
    ossl_ecx_set0_privkey(key, private);

    EVP_PKEY_assign(pkey, NID_ED448, key);
    rc = 1;
ret:
    if (rc == 0) {
        free(key);
        free(private);
    }
    if (ctx != NULL)
        p_ica_ed448_ctx_del(&ctx);
    return rc;
}

static int ibmca_ed448_sign(EVP_MD_CTX *md_ctx, unsigned char *sig,
                              size_t *siglen, const unsigned char *tbs,
                              size_t tbslen)
{
    ICA_ED448_CTX *ctx = NULL;
    ECX_KEY *key_ecx = NULL;
    EVP_PKEY *key_pkey = NULL;
    int rc = 0;

    if (sig == NULL) {
        *siglen = 2 * 57;
        return 1;
    }

    if (*siglen < 2 * 57)
        goto ret;

    key_pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(md_ctx));
    if (key_pkey == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ED448_SIGN, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    key_ecx = EVP_PKEY_get0(key_pkey);
    if (key_ecx == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ED448_SIGN, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    if (p_ica_ed448_ctx_new(&ctx) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_ED448_SIGN, IBMCA_R_PKEY_INTERNAL_ERROR);
        goto ret;
    }

    if (p_ica_ed448_key_set(ctx, ossl_ecx_get0_privkey(key_ecx), NULL) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_ED448_SIGN, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    if (p_ica_ed448_sign(ctx, sig, tbs, tbslen) != 0)
        goto ret;

    *siglen = 2 * 57;
    rc = 1;
ret:
    if (ctx != NULL)
        p_ica_ed448_ctx_del(&ctx);
    return rc;
}

static int ibmca_ed448_verify(EVP_MD_CTX *md_ctx, const unsigned char *sig,
                                size_t siglen, const unsigned char *tbv,
                                size_t tbvlen)
{
    ICA_ED448_CTX *ctx = NULL;
    ECX_KEY *key_ecx = NULL;
    EVP_PKEY *key_pkey = NULL;
    int rc = 0;

    if (sig == NULL || siglen != 2 * 57)
        goto ret;

    key_pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(md_ctx));
    if (key_pkey == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ED448_VERIFY, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    key_ecx = EVP_PKEY_get0(key_pkey);
    if (key_ecx == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ED448_VERIFY, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    if (p_ica_ed448_ctx_new(&ctx) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_ED448_VERIFY, IBMCA_R_PKEY_INTERNAL_ERROR);
        goto ret;
    }

    if (p_ica_ed448_key_set(ctx, NULL, ossl_ecx_get0_pubkey(key_ecx)) != 0) {
        IBMCAerr(IBMCA_F_IBMCA_ED448_VERIFY, IBMCA_R_PKEY_KEYS_NOT_SET);
        goto ret;
    }

    if (p_ica_ed448_verify(ctx, sig, tbv, tbvlen) != 0)
        goto ret;

    rc = 1;
ret:
    if (ctx != NULL)
        p_ica_ed448_ctx_del(&ctx);
    return rc;
}

/* Methods */

static int ibmca_ed_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    switch (type) {
    case EVP_PKEY_CTRL_MD:
        /* Only NULL allowed as digest */
        if (p2 == NULL || (const EVP_MD *)p2 == EVP_md_null())
            return 1;
        return 0;

    case EVP_PKEY_CTRL_DIGESTINIT:
        return 1;
    }
    return -2;
}

const EVP_PKEY_METHOD *ibmca_x25519(void)
{
    if (ibmca_x25519_pmeth != NULL)
        goto ret;

    ibmca_x25519_pmeth = EVP_PKEY_meth_new(NID_X25519, 0);
    if (ibmca_x25519_pmeth == NULL)
        goto ret;

    EVP_PKEY_meth_set_ctrl(ibmca_x25519_pmeth, ibmca_x25519_ctrl, NULL);
    EVP_PKEY_meth_set_keygen(ibmca_x25519_pmeth, NULL, ibmca_x25519_keygen);
    EVP_PKEY_meth_set_derive(ibmca_x25519_pmeth, NULL, ibmca_x25519_derive);

ret:
    return ibmca_x25519_pmeth;
}

const EVP_PKEY_METHOD *ibmca_x448(void)
{
    if (ibmca_x448_pmeth != NULL)
        goto ret;

    ibmca_x448_pmeth = EVP_PKEY_meth_new(NID_X448, 0);
    if (ibmca_x448_pmeth == NULL)
        goto ret;

    EVP_PKEY_meth_set_ctrl(ibmca_x448_pmeth, ibmca_x448_ctrl, NULL);
    EVP_PKEY_meth_set_keygen(ibmca_x448_pmeth, NULL, ibmca_x448_keygen);
    EVP_PKEY_meth_set_derive(ibmca_x448_pmeth, NULL, ibmca_x448_derive);

ret:
    return ibmca_x448_pmeth;
}

const EVP_PKEY_METHOD *ibmca_ed25519(void)
{
    if (ibmca_ed25519_pmeth != NULL)
        goto ret;

    ibmca_ed25519_pmeth = EVP_PKEY_meth_new(NID_ED25519, EVP_PKEY_FLAG_SIGCTX_CUSTOM);
    if (ibmca_ed25519_pmeth == NULL)
        goto ret;

    EVP_PKEY_meth_set_ctrl(ibmca_ed25519_pmeth, ibmca_ed_ctrl, NULL);
    EVP_PKEY_meth_set_copy(ibmca_ed25519_pmeth, ibmca_ed25519_copy);
    EVP_PKEY_meth_set_keygen(ibmca_ed25519_pmeth, NULL, ibmca_ed25519_keygen);
    EVP_PKEY_meth_set_digestsign(ibmca_ed25519_pmeth, ibmca_ed25519_sign);
    EVP_PKEY_meth_set_digestverify(ibmca_ed25519_pmeth, ibmca_ed25519_verify);

ret:
    return ibmca_ed25519_pmeth;
}

const EVP_PKEY_METHOD *ibmca_ed448(void)
{
    if (ibmca_ed448_pmeth != NULL)
        goto ret;

    ibmca_ed448_pmeth = EVP_PKEY_meth_new(NID_ED448, EVP_PKEY_FLAG_SIGCTX_CUSTOM);
    if (ibmca_ed448_pmeth == NULL)
        goto ret;

    EVP_PKEY_meth_set_ctrl(ibmca_ed448_pmeth, ibmca_ed_ctrl, NULL);
    EVP_PKEY_meth_set_copy(ibmca_ed448_pmeth, ibmca_ed448_copy);
    EVP_PKEY_meth_set_keygen(ibmca_ed448_pmeth, NULL, ibmca_ed448_keygen);
    EVP_PKEY_meth_set_digestsign(ibmca_ed448_pmeth, ibmca_ed448_sign);
    EVP_PKEY_meth_set_digestverify(ibmca_ed448_pmeth, ibmca_ed448_verify);

ret:
    return ibmca_ed448_pmeth;
}

void ibmca_x25519_destroy(void)
{
    if (ibmca_x25519_pmeth != NULL) {
        EVP_PKEY_meth_free(ibmca_x25519_pmeth);
        ibmca_x25519_pmeth = NULL;
    }
}

void ibmca_x448_destroy(void)
{
    if (ibmca_x448_pmeth != NULL) {
        EVP_PKEY_meth_free(ibmca_x448_pmeth);
        ibmca_x448_pmeth = NULL;
    }
}

void ibmca_ed25519_destroy(void)
{
    if (ibmca_ed25519_pmeth != NULL) {
        EVP_PKEY_meth_free(ibmca_ed25519_pmeth);
        ibmca_ed25519_pmeth = NULL;
    }
}

void ibmca_ed448_destroy(void)
{
    if (ibmca_ed448_pmeth != NULL) {
        EVP_PKEY_meth_free(ibmca_ed448_pmeth);
        ibmca_ed448_pmeth = NULL;
    }
}
