/*
 * Portions of this code are derived from tests/util.c in the pkcs11-provider project,
 * with permission granted by Simo Sorce for reuse in this file.
 */

%{
#include <stdio.h>
#include <stdbool.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
%}

%apply Pointer NONNULL { const char * };

%inline %{
static void ossl_err_print(void)
{
    bool first = true;
    unsigned long err = 0;
    while (true) {
        const char *file, *func, *data;
        int line;
        err = ERR_get_error_all(&file, &line, &func, &data, NULL);
        if (err == 0) {
            break;
        }

        char buf[1024];
        ERR_error_string_n(err, buf, sizeof(buf));

        const char *fmt =
            first ? ": %s (in function %s in %s:%d): %s\n"
                  : "  caused by: %s (in function %s in %s:%d): %s\n";
        fprintf(stderr, fmt, buf, func, file, line, data);

        first = false;
    }
    if (first) {
        fprintf(stderr, "[No errors on the OpenSSL stack]\n");
    }
    fflush(stderr);
}

EVP_PKEY *provider_load_key(const char *uri)
{
    OSSL_STORE_CTX *store;
    OSSL_STORE_INFO *info;
    EVP_PKEY *key = NULL;

    if (!uri) {
        fprintf(stderr, "Invalid NULL uri");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    store = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
    if (store == NULL) {
        fprintf(stderr, "Failed to open store: %s\n", uri);
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    if ((strncmp(uri, "pkcs11:", 7) == 0)
        && strstr(uri, "type=private") == NULL) {
        /* This is a workaround for OpenSSL < 3.2.0 where the code fails
         * to correctly source public keys unless explicitly requested
         * via an expect hint */
        if (OSSL_STORE_expect(store, OSSL_STORE_INFO_PUBKEY) != 1) {
            fprintf(stderr, "Failed to expect Public Key File\n");
            exit(EXIT_FAILURE);
        }
    }

    for (info = OSSL_STORE_load(store); info != NULL;
         info = OSSL_STORE_load(store)) {
        int type = OSSL_STORE_INFO_get_type(info);

        if (key != NULL) {
            fprintf(stderr, "Multiple keys matching URI: %s\n", uri);
            exit(EXIT_FAILURE);
        }

        switch (type) {
        case OSSL_STORE_INFO_PUBKEY:
            key = OSSL_STORE_INFO_get1_PUBKEY(info);
            break;
        case OSSL_STORE_INFO_PKEY:
            key = OSSL_STORE_INFO_get1_PKEY(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    if (key == NULL) {
        fprintf(stderr, "Failed to load key from URI: %s\n", uri);
        ossl_err_print();
        exit(EXIT_FAILURE);
    }
    OSSL_STORE_close(store);

    return key;
}

X509 * provider_load_certificate(const char *uri)
{
    OSSL_STORE_CTX *store;
    OSSL_STORE_INFO *info;
    X509 *cert = NULL;

    if (!uri) {
        fprintf(stderr, "Invalid NULL uri");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    store = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
    if (store == NULL) {
        fprintf(stderr, "Failed to open store: %s\n", uri);
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    for (info = OSSL_STORE_load(store); info != NULL;
         info = OSSL_STORE_load(store)) {
        int type = OSSL_STORE_INFO_get_type(info);

        if (cert != NULL) {
            fprintf(stderr, "Multiple certs matching URI: %s\n", uri);
            exit(EXIT_FAILURE);
        }

        switch (type) {
        case OSSL_STORE_INFO_CERT:
            cert = OSSL_STORE_INFO_get1_CERT(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    if (cert == NULL) {
        fprintf(stderr, "Failed to load cert from URI: %s\n", uri);
        ossl_err_print();
        exit(EXIT_FAILURE);
    }
    OSSL_STORE_close(store);

    return cert;
}

OSSL_PROVIDER *provider_load(const char *name)
{
    OSSL_PROVIDER *provider = NULL;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_end()
    };

    /* Load providers */
    provider = OSSL_PROVIDER_load_ex(NULL, name, params);
    if (!provider) {
        fprintf(stderr, "Failed to load pkcs11 provider\n");
    }

    return provider;
}

void provider_unload(OSSL_PROVIDER *provider)
{
    OSSL_PROVIDER_unload(provider);
}
%}
