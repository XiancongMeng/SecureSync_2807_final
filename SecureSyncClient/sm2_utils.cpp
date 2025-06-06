// ------------------------------
// 文件：sm2_utils.cpp
// ------------------------------

#include "sm2_utils.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <QByteArray>
#include <QBuffer>

bool generate_sm2_keypair(QByteArray &privateKeyOut, QByteArray &publicKeyOut) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx) return false;

    if (EVP_PKEY_keygen_init(pctx) <= 0) return false;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2) <= 0) return false;

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) return false;
    EVP_PKEY_CTX_free(pctx);

    // 提取私钥
    BIO *bio_priv = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio_priv, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char *priv_data = nullptr;
    long priv_len = BIO_get_mem_data(bio_priv, &priv_data);
    privateKeyOut = QByteArray(priv_data, priv_len);
    BIO_free(bio_priv);

    // 提取公钥
    BIO *bio_pub = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio_pub, pkey);
    char *pub_data = nullptr;
    long pub_len = BIO_get_mem_data(bio_pub, &pub_data);
    publicKeyOut = QByteArray(pub_data, pub_len);
    BIO_free(bio_pub);

    EVP_PKEY_free(pkey);
    return true;
}

QByteArray sm2_encrypt(const QByteArray &serverPubPem, const QByteArray &plain) {
    BIO *bio = BIO_new_mem_buf(serverPubPem.data(), serverPubPem.size());
    EVP_PKEY *pubKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pubKey) return QByteArray();

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubKey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pubKey);
        return QByteArray();
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        return QByteArray();
    }

    //EVP_PKEY_CTX_set_ec_enc_padding(ctx, 1);  // SM2-specific padding

    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen,
                         reinterpret_cast<const unsigned char *>(plain.constData()), plain.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        return QByteArray();
    }

    QByteArray encrypted(outlen, 0);
    if (EVP_PKEY_encrypt(ctx,
                         reinterpret_cast<unsigned char *>(encrypted.data()), &outlen,
                         reinterpret_cast<const unsigned char *>(plain.constData()), plain.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        return QByteArray();
    }

    encrypted.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubKey);
    return encrypted;
}

