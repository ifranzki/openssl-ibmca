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
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/obj_mac.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include <ica_api.h>

#define UNUSED(var)                             ((void)(var))

static void setup(void)
{
    OPENSSL_load_builtin_modules();

    CONF_modules_load_file(NULL, NULL,
                           CONF_MFLAGS_DEFAULT_SECTION|
                           CONF_MFLAGS_IGNORE_MISSING_FILE);
}

static int check_provider(EVP_PKEY_CTX *ctx, const char *expected_provider)
{
    const OSSL_PROVIDER *provider;
    const char *provname;

    if (expected_provider == NULL)
        expected_provider = "default";

    provider = EVP_PKEY_CTX_get0_provider(ctx);
    if (provider == NULL) {
        fprintf(stderr, "Context is not a provider-context\n");
        return 0;
    }

    provname = OSSL_PROVIDER_get0_name(provider);
    if (strcmp(provname, expected_provider) != 0) {
        fprintf(stderr, "Context is not using the %s provider, but '%s'\n",
                expected_provider, provname);
        return 0;
    }

    return 1;
}

static int generate_key(const char* provider, const char *algo, int nid,
                        const char *name, const OSSL_PARAM *params,
                        EVP_PKEY *template, EVP_PKEY **dh_pkey)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    if (template != NULL) {
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, template, props);
        if (ctx == NULL) {
            fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
            goto out;
        }
    } else {
        ctx = EVP_PKEY_CTX_new_from_name(NULL, algo, props);
        if (ctx == NULL) {
            fprintf(stderr, "EVP_PKEY_CTX_new_from_name failed\n");
            goto out;
        }
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;

    if (template == NULL) {
        if (EVP_PKEY_CTX_set_dh_nid(ctx, nid) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_dh_nid failed\n");
            goto out;
        }
    }

    if (params != NULL) {
        if (EVP_PKEY_CTX_set_params(ctx, params) != 1) {
            fprintf(stderr, "EVP_PKEY_CTX_set_params failed\n");
            goto out;
        }
    }

    if (EVP_PKEY_keygen(ctx, dh_pkey) <= 0) {
        if (ERR_GET_REASON(ERR_peek_last_error()) == 7) {
            /* group not supported => test passed */
            fprintf(stderr, "Group %s not supported by OpenSSL\n", name);
            ok = 1;
        } else {
            fprintf(stderr, "EVP_PKEY_keygen failed\n");
        }
        goto out;
    }

    ok = 1;

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ok;
}

static int derive_key(const char* provider, EVP_PKEY *dh_pkey,
                      EVP_PKEY *peer_pkey, int kdf, const char *kdf_md,
                      int kdf_nid, size_t kdf_outlen,
                      unsigned char *derived_key, size_t *derived_key_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_pkey, props);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive_init failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;

    if (kdf != 0 && kdf_md != NULL && kdf_nid != 0 && kdf_outlen != 0) {
        if (EVP_PKEY_CTX_set_dh_kdf_type(ctx, kdf) != 1) {
            fprintf(stderr, "EVP_PKEY_CTX_set_dh_kdf_type failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_dh_kdf_md(ctx, EVP_get_digestbyname(kdf_md)) != 1) {
            fprintf(stderr, "EVP_PKEY_CTX_set_dh_kdf_md failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set0_dh_kdf_oid(ctx, OBJ_nid2obj(kdf_nid)) != 1) {
            fprintf(stderr, "EVP_PKEY_CTX_set0_dh_kdf_oid failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_dh_kdf_outlen(ctx, kdf_outlen) != 1) {
            fprintf(stderr, "EVP_PKEY_CTX_set_dh_kdf_outlen failed\n");
            goto out;
        }
    }

    if (EVP_PKEY_derive_set_peer_ex(ctx, peer_pkey, 1) != 1) {
        fprintf(stderr, "EVP_PKEY_derive_set_peer_ex failed\n");
        goto out;
    }

    if (EVP_PKEY_derive(ctx, derived_key, derived_key_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive failed\n");
        goto out;
    }

    ok = 1;

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ok;
}

static int check_dhkey(int nid, const char *name, const char *algo)
{
    int            ok = 0;
    EVP_PKEY      *dh_pkey = NULL;
    EVP_PKEY      *peer_pkey = NULL;
    size_t         keylen1, keylen2;
    unsigned char  keybuf1[1024], keybuf2[1024];

    /* Keygen with IBMCA provider */
    if (!generate_key("ibmca", algo, nid, name, NULL, NULL, &dh_pkey))
        goto out;
    if (dh_pkey == NULL) {
        ok = 1; /* Group not supported, skip */
        goto out;
    }

    /* Keygen with IBMCA provider (using dh_pkey as template) */
    if (!generate_key("ibmca", algo, nid, name, NULL, dh_pkey, &peer_pkey))
        goto out;

    /* Derive with IBMCA provider (no KDF) */
    keylen1 = sizeof(keybuf1);
    if (!derive_key("ibmca", dh_pkey, peer_pkey, 0, NULL, 0, 0,
                    keybuf1, &keylen1))
        goto out;

    /* Derive with default provider (no KDF) */
    keylen2 = sizeof(keybuf2);
    if (!derive_key(NULL, dh_pkey, peer_pkey, 0, NULL, 0, 0,
                    keybuf2, &keylen2))
        goto out;

    if (keylen1 != keylen2 || memcmp(keybuf1, keybuf2, keylen1) != 0) {
        fprintf(stderr, "Derived keys are not equal\n");
        goto out;
    }

    /* Derive with IBMCA provider (X9_63 KDF) */
    keylen1 = sizeof(keybuf1);
    if (!derive_key("ibmca", dh_pkey, peer_pkey,
                    EVP_PKEY_DH_KDF_X9_42, "SHA256", NID_id_aes256_wrap,
                    sizeof(keybuf1), keybuf1, &keylen1))
        goto out;

    /* Derive with default provider (X9_63 KDF) */
    keylen2 = sizeof(keybuf2);
    if (!derive_key(NULL, dh_pkey, peer_pkey,
                    EVP_PKEY_DH_KDF_X9_42, "SHA256", NID_id_aes256_wrap,
                    sizeof(keybuf2), keybuf2, &keylen2))
        goto out;

    if (keylen1 != keylen2 || memcmp(keybuf1, keybuf2, keylen1) != 0) {
        fprintf(stderr, "Derived keys are not equal\n");
        goto out;
    }

    ok = 1;

 out:
    if (peer_pkey)
       EVP_PKEY_free(peer_pkey);
    if (dh_pkey)
       EVP_PKEY_free(dh_pkey);

    ERR_print_errors_fp(stderr);

    return ok;
}

static const unsigned int required_ica_mechs[] = { RSA_ME };
static const unsigned int required_ica_mechs_len =
                        sizeof(required_ica_mechs) / sizeof(unsigned int);

typedef unsigned int (*ica_get_functionlist_t)(libica_func_list_element *,
                                               unsigned int *);

static int check_libica()
{
    unsigned int mech_len, i, k, found = 0;
    libica_func_list_element *mech_list = NULL;
    void *ibmca_dso;
    ica_get_functionlist_t p_ica_get_functionlist;
    int rc;

    ibmca_dso = dlopen(LIBICA_NAME, RTLD_NOW);
    if (ibmca_dso == NULL) {
        fprintf(stderr, "Failed to load libica '%s'!\n", LIBICA_NAME);
        return 77;
    }

    p_ica_get_functionlist =
            (ica_get_functionlist_t)dlsym(ibmca_dso, "ica_get_functionlist");
    if (p_ica_get_functionlist == NULL) {
        fprintf(stderr, "Failed to get ica_get_functionlist from '%s'!\n",
                LIBICA_NAME);
        return 77;
    }

    rc = p_ica_get_functionlist(NULL, &mech_len);
    if (rc != 0) {
        fprintf(stderr, "Failed to get function list from libica!\n");
        return 77;
    }

    mech_list = calloc(sizeof(libica_func_list_element), mech_len);
    if (mech_list == NULL) {
        fprintf(stderr, "Failed to allocate memory for function list!\n");
        return 77;
    }

    rc = p_ica_get_functionlist(mech_list, &mech_len);
    if (rc != 0) {
        fprintf(stderr, "Failed to get function list from libica!\n");
        free(mech_list);
        return 77;
    }

    for (i = 0; i < mech_len; i++) {
        for (k = 0; k < required_ica_mechs_len; k++) {
            if (mech_list[i].mech_mode_id == required_ica_mechs[k]) {
                if (mech_list[i].flags &
                    (ICA_FLAG_SW | ICA_FLAG_SHW | ICA_FLAG_DHW))
                    found++;
            }
        }
    }

    free(mech_list);

    if (found < required_ica_mechs_len) {
        fprintf(stderr,
               "Libica does not support the required algorithms, skipping.\n");
        return 77;
    }

    return 0;
}

int main(int argc, char **argv)
{
    static const struct testparams {
        int         nid;
        const char *name;
    } params[] = {
                {NID_ffdhe2048,        "NID_ffdhe2048"},
                {NID_ffdhe3072,        "NID_ffdhe3072"},
                {NID_ffdhe4096,        "NID_ffdhe4096"},
                {NID_ffdhe6144,        "NID_ffdhe6144"},
                {NID_ffdhe8192,        "NID_ffdhe8192"},
                {NID_modp_1536,        "NID_modp_1536"},
                {NID_modp_2048,        "NID_modp_2048"},
                {NID_modp_3072,        "NID_modp_3072"},
                {NID_modp_4096,        "NID_modp_4096"},
                {NID_modp_6144,        "NID_modp_6144"},
                {NID_modp_8192,        "NID_modp_8192"},
    };

    UNUSED(argc);
    UNUSED(argv);

    int ret = 0, i;
    /* First fix the environment */
    char *testcnf = getenv("IBMCA_OPENSSL_TEST_CONF");
    char *testpath = getenv("IBMCA_TEST_PATH");

    /* Do not overwrite a user-provided OPENSSL_CONF in the
       environment.  This allows us to execute this test also on an
       installation with a user-provided engine configuration. */
    if (testcnf && setenv("OPENSSL_CONF", testcnf, 0)) {
        fprintf(stderr, "Failed to set OPENSSL_CONF environment variable!\n");
        return 77;
    }
    
    if (testpath && setenv("OPENSSL_MODULES", testpath, 0)) {
        fprintf(stderr, "Failed to set OPENSSL_MODULES environment variable!\n");
        return 77;
    }

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    ret = check_libica();
    if (ret != 0)
        return ret;

    setup();
    for (i = 0; i < (int)(sizeof(params) / sizeof(struct testparams)); ++i) {
        if (!check_dhkey(params[i].nid, params[i].name, "DH")) {
            fprintf(stderr, "Failure for %s (DH)\n", params[i].name);
            ret = 99;
        }
        if (!check_dhkey(params[i].nid, params[i].name, "DHX")) {
            fprintf(stderr, "Failure for %s (DHX)\n", params[i].name);
            ret = 99;
        }
    }
    return ret;
}
