#ifndef SM2_UTILS_H
#define SM2_UTILS_H

#include <QByteArray>
QByteArray sm2_encrypt(const QByteArray &serverPubPem, const QByteArray &plain);

// 生成 SM2 密钥对，返回私钥和公钥
bool generate_sm2_keypair(QByteArray &privateKey, QByteArray &publicKey);

#endif // SM2_UTILS_H

