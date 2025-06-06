#include "sm2_utils.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sm2.h>
#include <QByteArray>
#include <QBuffer>

bool generate_sm2_keypair(QByteArray &privateKeyPem, QByteArray &publicKeyPem) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, nullptr);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0) return false;

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) return false;

    BIO *bio_priv = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio_priv, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char *priv_data = nullptr;
    long priv_len = BIO_get_mem_data(bio_priv, &priv_data);
    privateKeyPem = QByteArray(priv_data, priv_len);
    BIO_free(bio_priv);

    BIO *bio_pub = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio_pub, pkey);
    char *pub_data = nullptr;
    long pub_len = BIO_get_mem_data(bio_pub, &pub_data);
    publicKeyPem = QByteArray(pub_data, pub_len);
    BIO_free(bio_pub);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return true;
}

