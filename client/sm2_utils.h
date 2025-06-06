#ifndef SM2_UTILS_H
#define SM2_UTILS_H

#include <QByteArray>

bool generate_sm2_keypair(QByteArray &privateKeyPem, QByteArray &publicKeyPem);

#endif // SM2_UTILS_H

