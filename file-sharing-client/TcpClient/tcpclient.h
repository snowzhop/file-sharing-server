#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <QTcpSocket>
#include <QTimer>

#include "eccryptopp/eccryptopp.h"

class TcpClient : public QTcpSocket {
    Q_OBJECT
public:

    static const char* TEST_MESSAGE;
    static const int TEST_MESSAGE_LENGTH = 4;
    static const int EXPECTED_TEST_MSG_LEN = 20;

    TcpClient(QObject* parent = nullptr);
    virtual ~TcpClient();

    const unsigned char* getPackedPublicKey();
    void calculateSecretKey(const u_char* key);
    void generateKeys();
    qint64 encryptAndSend(const u_char* data, size_t length);
    QByteArray decryptData(const u_char* data, size_t length);

//    void switchConnectionToEncryptedMode();
//    bool isConnectionEncrypted() const;

    // test function
    const unsigned char* getSecretKey();

private:
//    QTimer* reconnectTimer = nullptr;

//    bool encryptedConn = false;
    EcCrypto* cryptographer = nullptr;
};

#endif // TCPCLIENT_H

