#include "tcpclient.h"

TcpClient::TcpClient(QObject* parent) : QTcpSocket(parent) {
}

qint64 TcpClient::encryptAndSend(const u_char* data, size_t length) {
    std::string encyptedData = cryptographer.encryptData(data, length);
    return QTcpSocket::write(encyptedData.c_str(), encyptedData.length());
}

QByteArray TcpClient::decryptData(const u_char* data, size_t length) {
    std::string decryptedData = cryptographer.decryptData(data, length);
    return QByteArray(decryptedData.c_str(), decryptedData.length());
}

const unsigned char* TcpClient::getPackedPublicKey() {
    return cryptographer.getPublicKey();
}

void TcpClient::calculateSecretKey(const unsigned char* key) {
    cryptographer.deriveSecretKey(key);
}

const unsigned char* TcpClient::getSecretKey() {
    return cryptographer.getSecretKey();
}
