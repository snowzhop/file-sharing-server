#include "tcpclient.h"

#include "util/util.h"

const char* TcpClient::TEST_MESSAGE = "Test";

TcpClient::TcpClient(QObject* parent) : QTcpSocket(parent) { /*, reconnectTimer(new QTimer(this))*/
}

TcpClient::~TcpClient() {
    delete cryptographer;
}

qint64 TcpClient::encryptAndSend(const u_char* data, size_t length) {
    std::string encryptedData = cryptographer->encryptData(data, length);

    return QTcpSocket::write(encryptedData.c_str(), encryptedData.length());
}

QByteArray TcpClient::decryptData(const u_char* data, size_t length) {
    std::string decryptedData = cryptographer->decryptData(data, length);
    return QByteArray(decryptedData.c_str(), decryptedData.length());
}

const unsigned char* TcpClient::getPackedPublicKey() {
    return cryptographer->getPublicKey();
}

void TcpClient::calculateSecretKey(const unsigned char* key) {
    cryptographer->deriveSecretKey(key);
}

const unsigned char* TcpClient::getSecretKey() {
    return cryptographer->getSecretKey();
}

void TcpClient::generateKeys() {
    delete cryptographer;
    cryptographer = new EcCrypto;
}

/*void TcpClient::switchConnectionToEncryptedMode() {
    encryptedConn = true;
}

bool TcpClient::isConnectionEncrypted() const {
    return encryptedConn;
}*/
