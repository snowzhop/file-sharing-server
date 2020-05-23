#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <QTcpSocket>

#include "eccryptopp/eccryptopp.h"

class TcpClient : public QTcpSocket {
    Q_OBJECT
public:
    TcpClient(QObject* parent = nullptr);

    const unsigned char* getPackedPublicKey();
    void calculateSecretKey(const u_char* key);
    qint64 encryptAndSend(const u_char* data, size_t length);
    QByteArray decryptData(const u_char* data, size_t length);

    // test function
    const unsigned char* getSecretKey();

private:

    EcCrypto cryptographer;
};

#endif // TCPCLIENT_H

