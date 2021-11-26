/*
 * Copyright [2021-2022] International Business Machines Corp.
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

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>

#include "p_ibmca.h"

const OSSL_ITEM ibmca_rsa_padding_table[] = {
    { RSA_PKCS1_PADDING,        OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    { RSA_NO_PADDING,           OSSL_PKEY_RSA_PAD_MODE_NONE },
    { RSA_PKCS1_OAEP_PADDING,   OSSL_PKEY_RSA_PAD_MODE_OAEP },
    { RSA_PKCS1_OAEP_PADDING,   "oeap"   },
    { RSA_X931_PADDING,         OSSL_PKEY_RSA_PAD_MODE_X931 },
    { RSA_PKCS1_PSS_PADDING,    OSSL_PKEY_RSA_PAD_MODE_PSS },
    { RSA_PKCS1_WITH_TLS_PADDING, "" }, /* Will only be set as integer param */
    { 0,                        NULL     }
};

#define ASN1_SEQUENCE        0x30
#define ASN1_OCTET_STRING    0x04

int ibmca_rsa_build_digest_info(const struct ibmca_prov_ctx *provctx,
                                const EVP_MD *md, const unsigned char *data,
                                size_t data_len, unsigned char *out,
                                size_t outsize, size_t *outlen)
{
    X509_ALGOR *algid;
    int aid_len, md_len, seq_len, rc = 0;
    unsigned char *p;

    ibmca_debug_ctx(provctx, "md: '%s' data_len: %lu outsize: %lu",
                    EVP_MD_get0_name(md), data_len, outsize);

    /*
     DigestInfo ::= SEQUENCE {
           digestAlgorithm AlgorithmIdentifier,
           digest OCTET STRING
     }
     */

    md_len = EVP_MD_get_size(md);
    if (md_len <= 0 || md_len > 0x7F) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_MD_get_size failed or invalid digest size");
        return 0;
    }

    if (data_len != (size_t)md_len) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Input data size is incorrect, it must match the digest size: data size: %lu expected: %d",
                      data_len, md_len);
        return 0;
    }

    algid = X509_ALGOR_new();
    if (algid == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                       "X509_ALGOR_new failed");
        goto out;
    }

    X509_ALGOR_set0(algid, OBJ_nid2obj(EVP_MD_get_type(md)),
                    V_ASN1_NULL, NULL);
    aid_len = i2d_X509_ALGOR(algid, NULL);
    if (aid_len <= 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "i2d_X509_ALGOR failed");
        goto out;
    }

    seq_len = aid_len + 2 + md_len;
    if (seq_len > 0x7F)
        *outlen = 4 + seq_len;
    else
        *outlen = 2 + seq_len;

    if (outsize < *outlen) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Output buffer size too small");
        goto out;
    }

    p = out;
    *(p++) = ASN1_SEQUENCE;
    if (seq_len > 0x7F) {
        *(p++) = 0x82;
        *(p++) = (seq_len >> 8);
        *(p++) = (seq_len & 0xff);
    } else {
        *(p++) = seq_len;
    }

    if (i2d_X509_ALGOR(algid, &p) != aid_len) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "i2d_X509_ALGOR failed");
        goto out;
    }

    *(p++) = ASN1_OCTET_STRING;
    *(p++) = md_len;
    memcpy(p, data, md_len);

    ibmca_debug_ctx(provctx, "outlen: %lu", *outlen);

    rc = 1;

out:
    if (algid != NULL)
        X509_ALGOR_free(algid);

    return rc;
}

int ibmca_rsa_add_pkcs1_padding(const struct ibmca_prov_ctx *provctx, int type,
                                const unsigned char *in, size_t inlen,
                                unsigned char *out, size_t outlen)
{
    int i, pad_len;
    unsigned char *p;

    ibmca_debug_ctx(provctx, "type: %d inlen: %lu outlen: %lu", type,
                    inlen, outlen);

    /*
     * The format is
     * 00 || BT || PS || 00 || D
     * BT - block type
     * PS - padding string, at least 8 bytes of FF for BT = 1 or at least 8
     *      bytes of random non-zero data for BT = 2
     * D  - data.
     */
    if (outlen < (inlen + RSA_PKCS1_PADDING_SIZE)) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Data too large for the key type");
        return 0;
    }

    pad_len = outlen - 3 - inlen;
    if (pad_len < 8) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Data too large for the key type");
        return 0;
    }

    p = out;

    *(p++) = 0;
    *(p++) = type;

    switch (type) {
    case 1:
        memset(p, 0xff, pad_len);
        p += pad_len;
        break;

    case 2:
        if (RAND_bytes_ex(provctx->libctx, p, pad_len, 0) <= 0) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                                  "RAND_bytes_ex failed");
            return 0;
        }

        for (i = 0; i < pad_len; i++, p++) {
            while (*p == '\0') {
                if (RAND_bytes_ex(provctx->libctx, p, 1, 0) <= 0) {
                    put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                                  "RAND_bytes_ex failed");
                    return 0;
                }
            }
        }
        break;

    default:
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                       "Invalid PKCS1 block type: %d", type);
        return 0;
    }

    *(p++) = 0;
    memcpy(p, in, inlen);

    return 1;
}

int ibmca_rsa_check_pkcs1_padding(const struct ibmca_prov_ctx *provctx,
                                  int type,
                                  const unsigned char *in, size_t inlen,
                                  unsigned char *out, size_t outsize,
                                  unsigned char **outptr, size_t *outlen)
{
    const unsigned char *p;
    int found = 0;

    ibmca_debug_ctx(provctx, "type: %d inlen: %lu outsize: %lu", type,
                    inlen, outsize);

    /*
     * The format is
     * 00 || BT || PS || 00 || D
     * BT - block type
     * PS - padding string, at least 8 bytes of FF for BT = 1 or at least 8
     *      bytes of random non-zero data for BT = 2
     * D  - data.
     */
    if (inlen < RSA_PKCS1_PADDING_SIZE) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM, "PKCS1 encoding error");
        return 0;
    }

    p = in;

    if (*(p++) != 0 || *(p++) != type) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM, "PKCS1 encoding error");
        return 0;
    }

    switch (type) {
    case 1:
        while (p < in + inlen) {
            if (*p != 0xff) {
                if (*p == 0x00) {
                    found = 1;
                    break;
                }

                put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                              "PKCS1 encoding error");
                return 0;
            }
            p++;
        }
        break;

    case 2:
        while (p < in + inlen) {
            if (*p == 0x00) {
                found = 1;
                break;
            }
            p++;
        }
        break;

    default:
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                       "Invalid PKCS1 block type: %d", type);
        return 0;
    }

    if (!found) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "PKCS1 encoding error");
        return 0;
    }

    p++;

    *outlen = inlen - (p - in);

    if (outsize < *outlen) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Output buffer too small");
        return 0;
    }

    if (out != NULL)
        memcpy(out, p, *outlen);
    if (outptr != NULL)
        *outptr = (unsigned char *)p;

    ibmca_debug_ctx(provctx, "outlen: %lu", *outlen);

    return 1;
}

static int ibmca_rsa_pkcs1_mgf1(const struct ibmca_prov_ctx *provctx,
                                unsigned char *mask, long mask_len,
                                const unsigned char *seed, long seed_len,
                                const EVP_MD *mgf1_md)
{
    long i, outlen = 0;
    unsigned char cnt[4];
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    unsigned char md[EVP_MAX_MD_SIZE];
    int mdlen;
    int rc = 0;

    if (md_ctx == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_MD_CTX_new failed");
        return 0;
    }

    mdlen = EVP_MD_get_size(mgf1_md);
    if (mdlen < 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_MD_get_size failed");
        goto err;
    }

    /* step 4 */
    for (i = 0; outlen < mask_len; i++) {
        /* step 4a: D = I2BS(counter, 4) */
        cnt[0] = (unsigned char)((i >> 24) & 255);
        cnt[1] = (unsigned char)((i >> 16) & 255);
        cnt[2] = (unsigned char)((i >> 8)) & 255;
        cnt[3] = (unsigned char)(i & 255);

        /* step 4b: T =T || hash(mgfSeed || D) */
        if (!EVP_DigestInit_ex(md_ctx, mgf1_md, NULL)
            || !EVP_DigestUpdate(md_ctx, seed, seed_len)
            || !EVP_DigestUpdate(md_ctx, cnt, 4)) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "EVP_DigestInit_ex/EVP_DigestUpdate failed");
            goto err;
        }

        if (outlen + mdlen <= mask_len) {
            if (!EVP_DigestFinal_ex(md_ctx, mask + outlen, NULL)) {
                put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                              "EVP_DigestFinal_ex failed");
                goto err;
            }

            outlen += mdlen;
        } else {
            if (!EVP_DigestFinal_ex(md_ctx, md, NULL)) {
                put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                              "EVP_DigestFinal_ex failed");
                goto err;
            }

            memcpy(mask + outlen, md, mask_len - outlen);
            outlen = mask_len;
        }
    }

    rc = 1;

 err:
    OPENSSL_cleanse(md, sizeof(md));
    EVP_MD_CTX_free(md_ctx);

    return rc;
}

int ibmca_rsa_add_oaep_mgf1_padding(const struct ibmca_prov_ctx *provctx,
                                    const unsigned char *in, size_t inlen,
                                    unsigned char *out, size_t outlen,
                                    const EVP_MD *oaep_md,
                                    const EVP_MD *mgf1_md,
                                    const unsigned char *label,
                                    size_t label_len)
{
    int ps_len;
    size_t oaep_md_len, dbmask_len = 0, i;
    unsigned char *masked_seed, *masked_db, *dbmask = NULL;
    unsigned char seed[EVP_MAX_MD_SIZE];
    int rc = 0;

    if (oaep_md == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "No OAEP digest available");
        return 0;
    }

    if (mgf1_md == NULL)
        mgf1_md = oaep_md;

    ibmca_debug_ctx(provctx,
                    "inlen: %lu outlen: %lu oaep_md: '%s' mgf1_md: '%s' label_len: %lu",
                    inlen, outlen, EVP_MD_get0_name(oaep_md),
                    EVP_MD_get0_name(mgf1_md), label_len);

    oaep_md_len = EVP_MD_get_size(oaep_md);
    if (oaep_md_len <= 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_MD_get_size failed");
        goto done;
    }

    if (inlen > outlen - (2 * oaep_md_len) - 2) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Data too large for the key type");
        return 0;
    }

    /*
     * pkcs1v2.2 Step i:
     * The encoded messages is a concatenated single octet, 0x00 with
     * maskedSeed and maskedDB to create encoded message EM.
     * So lets mark of the places in our output buffer.
     */
    memset(out, 0, outlen);
    masked_seed = out + 1;
    masked_db = out + oaep_md_len + 1;

    /*
     * pkcs1v2.2, Step b:
     * Generate an octet string PS and concatenate to DB.
     */
    ps_len = outlen - inlen - (2 * oaep_md_len) - 2;
    if (EVP_Digest((void *)label, label_len, masked_db, NULL,
                   oaep_md, NULL) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR, "EVP_Digest failed");
        goto done;
    }
    memset(masked_db + oaep_md_len, 0, ps_len);

    /*
     * pkcs1v2.2, Step c:
     * We have already concatenated hash and PS to maskedDB.
     * Now just concatenate 0x01 and message.
     */
    masked_db[oaep_md_len + ps_len] = 0x01;
    memcpy(masked_db + (oaep_md_len + ps_len + 1), in, inlen);

    /*
     * pkcs1v2.2, Step d:
     * Generate a random seed.
     */
    if (RAND_bytes_ex(provctx->libctx, seed, oaep_md_len, 0) <= 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR, "RAND_bytes_ex failed");
        goto done;
    }

    /* pkcs1v2.2, Step e:
     * Compute dbmask using MGF1.
     */
    dbmask_len = outlen - oaep_md_len - 1;
    dbmask = P_ZALLOC(provctx, dbmask_len);
    if (dbmask == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate mask buffer");
        goto done;
    }

    if (ibmca_rsa_pkcs1_mgf1(provctx, dbmask, dbmask_len, seed, oaep_md_len,
                             mgf1_md) == 0)
        goto done;

    /* pkcs1v2.2, Step f:
     * Compute maskedDB.
     */
    for (i = 0; i < dbmask_len; i++)
        masked_db[i] ^= dbmask[i];

    /* pkcs1v2.2, Step g:
     * Compute seedMask using MGF1.
     */
    memset(masked_seed, 0, oaep_md_len);
    if (ibmca_rsa_pkcs1_mgf1(provctx, masked_seed, oaep_md_len, masked_db,
                             dbmask_len, mgf1_md) == 0)
        goto done;

    /* pkcs1v2.2, Step h:
     * Compute maskedSeed.
     */
    for (i = 0; i < oaep_md_len; i++)
        masked_seed[i] ^= seed[i];

    rc = 1;

done:
    if (dbmask)
        P_CLEAR_FREE(provctx, dbmask, dbmask_len);
    P_CLEANSE(provctx, seed, sizeof(seed));

    return rc;
}

int ibmca_rsa_check_oaep_mgf1_padding(const struct ibmca_prov_ctx *provctx,
                                      const unsigned char *in, size_t inlen,
                                      unsigned char *out, size_t outsize,
                                      unsigned char **outptr, size_t *outlen,
                                      const EVP_MD *oaep_md,
                                      const EVP_MD *mgf1_md,
                                      const unsigned char *label,
                                      size_t label_len)
{
    int rc = 0, error = 0;
    size_t dbmask_len = 0, ps_len, i, oaep_md_len;
    const unsigned char *masked_seed, *masked_db;
    unsigned char *dbmask = NULL, *seed_mask = NULL;
    unsigned char hash[EVP_MAX_MD_SIZE];

    if (oaep_md == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "No OAEP digest available");
        return 0;
    }

    if (mgf1_md == NULL)
        mgf1_md = oaep_md;

    ibmca_debug_ctx(provctx,
                    "inlen: %lu outsize: %lu oaep_md: '%s' mgf1_md: '%s' label_len: %lu",
                    inlen, outsize, EVP_MD_get0_name(oaep_md),
                    EVP_MD_get0_name(mgf1_md), label_len);

    oaep_md_len = EVP_MD_get_size(oaep_md);
    if (oaep_md_len <= 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_MD_get_size failed");
        goto done;
    }

    if (inlen < oaep_md_len + 2) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Input size too small");
        goto done;
    }

    /* allocate memory now for later use */
    dbmask_len = outsize - oaep_md_len - 1;
    dbmask = P_ZALLOC(provctx, dbmask_len);
    seed_mask = P_ZALLOC(provctx, oaep_md_len);
    if ((seed_mask == NULL) || (dbmask == NULL)) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate mask or seed buffer");
        goto done;
    }

    /* pkcs1v2.2, section 7.1.2, Step 3b:
     * Separate the encoded message EM and process the decrypted message.
     *
     * To mitigate fault and timing attacks, just flag errors and
     * keep going.
     */
    masked_seed = in + 1;
    masked_db = in + oaep_md_len + 1;

    /* pkcs1v2.2, section 7.1.2, Step 3c:
     * Compute seedMask using MGF1.
     */
    if (ibmca_rsa_pkcs1_mgf1(provctx, seed_mask, oaep_md_len, masked_db,
                             dbmask_len, mgf1_md) == 0)
        error++;

    /* pkcs1v2.2, section 7.1.2, Step 3d:
     * Compute seed using MGF1.
     */
    for (i = 0; i < oaep_md_len; i++)
        seed_mask[i] ^= masked_seed[i];

    /* pkcs1v2.2, section 7.1.2, Step 3e:
     * Compute dbmask using MGF1.
     */
    if (ibmca_rsa_pkcs1_mgf1(provctx, dbmask, dbmask_len, seed_mask,
                             oaep_md_len, mgf1_md) == 0)
        error++;

    /* pkcs1v2.2, section 7.1.2, Step 3f:
     * Compute db using MGF1.
     */
    for (i = 0; i < dbmask_len; i++)
        dbmask[i] ^= masked_db[i];

    /* pkcs1v2.2, section 7.1.2, Step 3g:
     * DB = lHash� || PS || 0x01 || M .
     *
     * If there is no octet with hexadecimal value 0x01 to separate
     * PS from M, if lHash does not equal lHash�, output "decryption
     * error" and stop.
     */
    if (EVP_Digest((void *)label, label_len, hash, NULL,
                   oaep_md, NULL) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR, "EVP_Digest failed");
        goto done;
    }
    if (memcmp(dbmask, hash, oaep_md_len))
        error++;

    ps_len = oaep_md_len;
    while ((ps_len < dbmask_len) && (dbmask[ps_len] == 0x00))
        ps_len++;

    if (ps_len >= dbmask_len ||
        (ps_len < dbmask_len && dbmask[ps_len] != 0x01) ||
        in[0] != 0)
        error++;

    if (error)
        goto done;

    ps_len++;
    *outlen = dbmask_len - ps_len;

    if (outsize < *outlen) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Output buffer too small");
        goto done;
    }

    if (out != NULL)
        memcpy(out, dbmask + ps_len, *outlen);
    if (outptr != NULL)
        *outptr = dbmask + ps_len;

    ibmca_debug_ctx(provctx, "outlen: %lu", *outlen);

    rc = 1;

done:
    if (seed_mask)
        P_CLEAR_FREE(provctx, seed_mask, oaep_md_len);
    if (dbmask)
        P_CLEAR_FREE(provctx, dbmask, dbmask_len);

    return rc;
}

int ibmca_rsa_check_pkcs1_tls_padding(const struct ibmca_prov_ctx *provctx,
                                      unsigned int client_version,
                                      unsigned int alt_version,
                                      const unsigned char *in, size_t inlen,
                                      unsigned char *out, size_t outsize,
                                      size_t *outlen)
{
    size_t i;
    bool ok, alt_ok;

    ibmca_debug_ctx(provctx,
                    "inlen: %lu outsize: %lu client_version: 0x%04x alt_version: 0x%04x" ,
                    inlen, outsize, client_version, alt_version);

    /*
     * The format is
     * 00 || 02 || PS || 00 || PreMasterSecret
     * BT - block type
     * PS - at least 8 bytes of random non-zero data for BT = 2
     * D  - data = PreMasterSecret (48 bytes)
     * PreMasterSecret:  Version-major | Version-minor | 64 bytes secret
     */

    if (inlen < RSA_PKCS1_PADDING_SIZE + IBMCA_SSL_MAX_MASTER_KEY_LENGTH) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM, "PKCS1 encoding error");
        return 0;
    }
    if (outsize < IBMCA_SSL_MAX_MASTER_KEY_LENGTH) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Output buffer too small");
        return 0;
    }

    /* Check PKCA#1 type 2 padding */
    if (in[0] != 0x00 || in[1] != 0x02) {
        ibmca_debug_ctx(provctx, "ERROR: PKCS1 encoding error");
        goto error;
    }
    for (i = 2; i < inlen - IBMCA_SSL_MAX_MASTER_KEY_LENGTH - 1; i++) {
        if (in[i] == 0x00) {
            ibmca_debug_ctx(provctx, "ERROR: PKCS1 encoding error");
            goto error;
        }
    }
    if (in[inlen - IBMCA_SSL_MAX_MASTER_KEY_LENGTH - 1] != 0x00) {
        ibmca_debug_ctx(provctx, "ERROR: PKCS1 encoding error");
        goto error;
    }

    /* Check version */
    ok = (in[inlen - IBMCA_SSL_MAX_MASTER_KEY_LENGTH] ==
                                            ((client_version >> 8) & 0xff));
    ok &= (in[inlen - IBMCA_SSL_MAX_MASTER_KEY_LENGTH] ==
                                            (client_version & 0xff));

    if (alt_version != 0) {
        alt_ok = (in[inlen - IBMCA_SSL_MAX_MASTER_KEY_LENGTH] ==
                                                ((alt_version >> 8) & 0xff));
        alt_ok &= (in[inlen - IBMCA_SSL_MAX_MASTER_KEY_LENGTH] ==
                                                (alt_version & 0xff));
        ok |= alt_ok;
    }
    if (!ok) {
        ibmca_debug_ctx(provctx, "ERROR: Version check failed");
        goto error;
    }

    *outlen = IBMCA_SSL_MAX_MASTER_KEY_LENGTH;
    if (out != NULL)
        memcpy(out, &in[inlen - IBMCA_SSL_MAX_MASTER_KEY_LENGTH],
               IBMCA_SSL_MAX_MASTER_KEY_LENGTH);

    ibmca_debug_ctx(provctx, "outlen: %lu", *outlen);

    return 1;

error:
    /*
     * We must not leak whether a decryption failure occurs because of
     * Bleichenbacher's attack on PKCS #1 v1.5 RSA padding (see RFC 2246,
     * section 7.4.7.1). The code follows that advice of the TLS RFC and
     * generates a random premaster secret for the case that the decrypt
     * fails. See https://tools.ietf.org/html/rfc5246#section-7.4.7.1
     * So, whether we actually succeeded or not, return success.
     */
    *outlen = IBMCA_SSL_MAX_MASTER_KEY_LENGTH;
    if (out != NULL) {
        if (RAND_priv_bytes_ex(provctx->libctx, out,
                               IBMCA_SSL_MAX_MASTER_KEY_LENGTH, 0) <= 0) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "RAND_priv_bytes_ex failed");
            return 0;
        }
    }

    ibmca_debug_ctx(provctx, "outlen: %lu", *outlen);

    return 1;
}

static int ibmca_rsa_x931_padding_hash_id(int nid)
{
    switch (nid) {
    case NID_sha1:
        return 0x33;
    case NID_sha256:
        return 0x34;
    case NID_sha384:
        return 0x36;
    case NID_sha512:
        return 0x35;
    }
    return -1;
}

int ibmca_rsa_add_x931_padding(const struct ibmca_prov_ctx *provctx,
                               const unsigned char *in, size_t inlen,
                               unsigned char *out, size_t outlen,
                               int digest_nid)
{
    int j, hash_id;
    unsigned char *p;

    ibmca_debug_ctx(provctx, "inlen: %lu outlen: %lu digest_nid: %d",
                    inlen, outlen, digest_nid);

    hash_id = ibmca_rsa_x931_padding_hash_id(digest_nid);
    if (hash_id == -1) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Unsupported signature digest: %d", digest_nid);
        return 0;
    }

    /*
     * Absolute minimum amount of padding is 1 header nibble, 1 padding
     * nibble and 2 trailer bytes.
     */
    j = outlen - inlen - 3;

    if (j < 0) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Data too large for the key type");
        return 0;
    }

    p = out;

    /* If no padding start and end nibbles are in one byte */
    if (j == 0) {
        *p++ = 0x6A;
    } else {
        *p++ = 0x6B;
        if (j > 1) {
            memset(p, 0xBB, j - 1);
            p += j - 1;
        }
        *p++ = 0xBA;
    }
    memcpy(p, in, inlen);
    p += inlen;
    *p++ = hash_id;
    *p = 0xCC;
    return 1;
}

int ibmca_rsa_check_X931_padding(const struct ibmca_prov_ctx *provctx,
                                 const unsigned char *in, int inlen,
                                 unsigned char *out, size_t outsize,
                                 unsigned char **outptr, size_t *outlen,
                                 int digest_nid)
{
    int i = 0, j, hash_id;
    const unsigned char *p;

    ibmca_debug_ctx(provctx, "inlen: %lu outsize: %lu digest_nid: %d",
                    inlen, outsize, digest_nid);

    hash_id = ibmca_rsa_x931_padding_hash_id(digest_nid);
    if (hash_id == -1) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Unsupported signature digest: %d", digest_nid);
        return 0;
    }

    p = in;
    if (((*p != 0x6A) && (*p != 0x6B))) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR, "Invalid X931 padding");
        return 0;
    }

    if (*p++ == 0x6B) {
        j = inlen - 3;
        for (i = 0; i < j; i++) {
            unsigned char c = *p++;
            if (c == 0xBA)
                break;
            if (c != 0xBB) {
                put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                              "Invalid X931 padding");
                return 0;
            }
        }

        j -= i;

        if (i == 0) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "Invalid X931 padding");
            return 0;
        }

    } else {
        j = inlen - 2;
    }

    if (p[j - 1] != hash_id || p[j] != 0xCC) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR, "Invalid X931 trailer");
        return 0;
    }

    *outlen = j - 1;

    if (outsize < *outlen) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Output buffer size too small");
        return 0;
    }

    if (out != NULL)
        memcpy(out, p, *outlen);
    if (outptr != NULL)
        *outptr = (unsigned char *)p;

    ibmca_debug_ctx(provctx, "outlen: %lu", *outlen);

    return 1;
}

int ibmca_rsa_add_pss_mgf1_padding(const struct ibmca_prov_ctx *provctx,
                                   const unsigned char *in, size_t inlen,
                                   unsigned char *out, size_t outlen,
                                   const EVP_MD *pss_md, const EVP_MD *mgf1_md,
                                   int saltlen)
{
    int i, rc = 0, maskeddb_len, msbits;
    unsigned char *h, *salt = NULL, *p;
    EVP_MD_CTX *ctx = NULL;
    static const unsigned char zeroes[] = { 0, 0, 0, 0, 0, 0, 0, 0 };

    if (pss_md == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "No PSS digest available");
        return 0;
    }

    if (mgf1_md == NULL)
        mgf1_md = pss_md;

    ibmca_debug_ctx(provctx,
                    "inlen: %lu outlen: %lu pss_md: '%s' mgf1_md: '%s' saltlen: %d",
                    inlen, outlen, EVP_MD_get0_name(pss_md),
                    EVP_MD_get0_name(mgf1_md), saltlen);

    msbits = ((outlen * 8) - 1) & 0x7;
    if (msbits == 0) {
        *out++ = 0;
        outlen--;
    }

    if (outlen < inlen + 2) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                              "Data too large for the key type");
        goto err;
    }

    if (inlen != (size_t)EVP_MD_get_size(pss_md)) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                       "Data size is not the size of the digest");
        goto err;
    }

    switch (saltlen) {
    case RSA_PSS_SALTLEN_DIGEST:
        saltlen = EVP_MD_get_size(pss_md);
        break;
    case RSA_PSS_SALTLEN_MAX_SIGN:
    case RSA_PSS_SALTLEN_MAX:
        saltlen = outlen - inlen - 2;
        break;
    default:
        if (saltlen < 0) {
            put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                          "Invalid salt len: %d", saltlen);
            goto err;
        }
    }
    if ((size_t)saltlen > outlen - inlen - 2) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Data too large for the key type");
        goto err;
    }

    ibmca_debug_ctx(provctx,"saltlen: %d", saltlen);

    if (saltlen > 0) {
        salt = P_MALLOC(provctx, saltlen);
        if (salt == NULL) {
            put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                          "Failed to allocate salt buffer");
            goto err;
        }
        if (RAND_bytes_ex(provctx->libctx, salt, saltlen, 0) <= 0) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "RAND_bytes_ex failed");
            goto err;
        }
    }

    maskeddb_len = outlen - inlen - 1;
    h = out + maskeddb_len;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_MD_CTX_new failed");
        goto err;
    }

    if (EVP_DigestInit_ex(ctx, pss_md, NULL) == 0 ||
        EVP_DigestUpdate(ctx, zeroes, sizeof(zeroes)) == 0 ||
        EVP_DigestUpdate(ctx, in, inlen) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_DigestInit_ex/EVP_DigestUpdate failed");
        goto err;
    }

    if (saltlen != 0 && EVP_DigestUpdate(ctx, salt, saltlen) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_DigestUpdate failed");
        goto err;
    }
    if (EVP_DigestFinal_ex(ctx, h, NULL) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_DigestFinal_ex failed");
        goto err;
    }

    /* Generate dbMask in place then perform XOR on it */
    if (ibmca_rsa_pkcs1_mgf1(provctx, out, maskeddb_len, h, inlen,
                             mgf1_md) == 0)
        goto err;

    p = out;
    p += outlen - saltlen - inlen - 2;

    *p++ ^= 0x1;

    if (saltlen > 0) {
        for (i = 0; i < saltlen; i++)
            *p++ ^= salt[i];
    }

    if (msbits != 0)
        out[0] &= 0xFF >> (8 - msbits);

    out[outlen - 1] = 0xbc;

    rc = 1;

err:
    if (ctx != NULL)
        EVP_MD_CTX_free(ctx);
    if (salt != NULL)
        P_CLEAR_FREE(provctx, salt, (size_t)saltlen);

    return rc;
}

int ibmca_rsa_check_pss_mgf1_padding(const struct ibmca_prov_ctx *provctx,
                                     const unsigned char *in, size_t inlen,
                                     const unsigned char *data, size_t datalen,
                                     const EVP_MD *pss_md,
                                     const EVP_MD *mgf1_md,
                                     int saltlen)
{
    int i, rc = 0, maskeddb_len, msbits;
    const unsigned char *h;
    unsigned char *db = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned char h_[EVP_MAX_MD_SIZE];
    static const unsigned char zeroes[] = { 0, 0, 0, 0, 0, 0, 0, 0 };

    if (pss_md == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "No PSS digest available");
        return 0;
    }

    if (mgf1_md == NULL)
        mgf1_md = pss_md;

    ibmca_debug_ctx(provctx,
                    "inlen: %lu datalen: %lu pss_md: '%s' mgf1_md: '%s' saltlen: %d",
                    inlen, datalen, EVP_MD_get0_name(pss_md),
                    EVP_MD_get0_name(mgf1_md), saltlen);

    if (datalen != (size_t)EVP_MD_get_size(pss_md)) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                       "Data size is not the size of the digest");
        goto err;
    }

    msbits = ((inlen * 8) - 1) & 0x7;
    if (in[0] & (0xFF << msbits)) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "Invalid PSS encoding");
        goto err;
    }
    if (msbits == 0) {
        in++;
        inlen--;
    }

    switch (saltlen) {
    case RSA_PSS_SALTLEN_DIGEST:
        saltlen = EVP_MD_get_size(pss_md);
        break;
    case RSA_PSS_SALTLEN_MAX:
        saltlen = inlen - datalen - 2;
        break;
    case RSA_PSS_SALTLEN_AUTO:
        break;
    default:
        if (saltlen < 0) {
            put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                          "Invalid salt len: %d", saltlen);
            goto err;
        }
    }
    ibmca_debug_ctx(provctx,"saltlen: %d", saltlen);

    if (saltlen > (int)(inlen - datalen - 2)) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Data too large for the key type");
        goto err;
    }

    if (in[inlen - 1] != 0xbc) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "Invalid PSS encoding");
        goto err;
    }

    maskeddb_len = inlen - datalen - 1;
    h = in + maskeddb_len;

    db = P_MALLOC(provctx, maskeddb_len);
    if (db == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate DB buffer");
        goto err;
    }

    if (ibmca_rsa_pkcs1_mgf1(provctx, db, maskeddb_len, h, datalen,
                             mgf1_md) < 0)
        goto err;

    for (i = 0; i < maskeddb_len; i++)
        db[i] ^= in[i];

    if (msbits != 0)
        db[0] &= 0xFF >> (8 - msbits);

    for (i = 0; db[i] == 0 && i < (maskeddb_len - 1); i++)
        ;

    if (db[i++] != 0x1) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                              "Saltlen recovery failed");
        goto err;
    }

    if (saltlen != RSA_PSS_SALTLEN_AUTO && (maskeddb_len - i) != saltlen) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "Saltlen check failed. Expected: %d retrieved: %d",
                      saltlen, maskeddb_len - i);
        goto err;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_MD_CTX_new failed");
        goto err;
    }

    if (EVP_DigestInit_ex(ctx, pss_md, NULL) == 0 ||
        EVP_DigestUpdate(ctx, zeroes, sizeof(zeroes)) == 0 ||
        EVP_DigestUpdate(ctx, data, datalen) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_DigestInit_ex/EVP_DigestUpdate failed");
        goto err;
    }

    if (maskeddb_len - i > 0) {
        if (EVP_DigestUpdate(ctx, db + i, maskeddb_len - i) == 0) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "EVP_DigestUpdate failed");
            goto err;
        }
    }

    if (EVP_DigestFinal_ex(ctx, h_, NULL) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_DigestFinal_exe failed");
        goto err;
    }

    if (memcmp(h_, h, datalen)) {
        put_error_ctx(provctx, IBMCA_ERR_SIGNATURE_BAD, "Bad signature");
        rc = 0;
    } else {
        rc = 1;
    }

    ibmca_debug_ctx(provctx, "rc: %d", rc);

err:
    if (db != NULL)
        P_CLEAR_FREE(provctx, db, maskeddb_len);
    if (ctx != NULL)
        EVP_MD_CTX_free(ctx);

    return rc;
}