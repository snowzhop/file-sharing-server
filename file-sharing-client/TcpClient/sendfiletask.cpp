#include "sendfiletask.h"

#include <QDebug>
#include <QTime>
#include <QHostAddress>
#include <QFile>
#include <QDataStream>

#include "TcpClient/tcpclient.h"

SendFileTask::SendFileTask(const QString& address, const QString& filePath, QObject* parent)
    : QObject(parent),
      m_address(address),
      m_filePath(filePath) {

}

SendFileTask::~SendFileTask() {
    qDebug() << "SendFileTask::~SendFileTask()";
}

void SendFileTask::run() {
    qDebug() << "SendFileTask::run()";
    qDebug() << "m_address:" << m_address;
    qDebug() << "m_port:" << m_port;
    qDebug() << "m_filePath:" << m_filePath;
    char buffer[SENDING_BUFFER_SIZE];
    QByteArray b_cache;
    b_cache.reserve(SENDING_BUFFER_SIZE);

    TcpClient socket;

    socket.connectToHost(m_address, m_port);
    emit information("Connected to " + socket.peerAddress().toString());

    for (int i = 0; i < 5; ++i) {
        qDebug() << "Handshake attempt:" << i+1;

        if (socket.state() != TcpClient::ConnectedState && socket.state() != TcpClient::ConnectedState) {
            socket.connectToHost("127.0.0.1", 9999);
        }

        if (!socket.waitForConnected(2000)) {
            continue;
        }

        socket.generateKeys();

        const char* ownPubKey = reinterpret_cast<const char*>(socket.getPackedPublicKey());
        socket.write(ownPubKey, 66);

        if (!socket.waitForBytesWritten(1000)) {
            qDebug() << "Bytes not written!!!(1)";
            continue;
        }
        qDebug() << "key was sent";
        if (!socket.waitForReadyRead(5000)) {
            continue;
        }

        auto bytesRead = socket.read(buffer, 128);
        if (bytesRead != 66) {
            qDebug() << "bytesRead(1) != 66";
            continue;
        }

        qDebug() << "bytesRead:" << bytesRead;

        try {
            socket.calculateSecretKey(reinterpret_cast<const u_char*>(buffer));
        } catch (const std::exception& ex) {
            qDebug() << "Secret key calculating error:" << ex.what();
            continue;
        }
        QByteArray secret(reinterpret_cast<const char*>(socket.getSecretKey()), 32);
        qDebug() << "Secret key:" << secret.toHex();

        if (!socket.waitForReadyRead(5000)) {
            qDebug() << "Reading test msg timeout";
            continue;
        }

        bytesRead = socket.read(buffer, 128);
        if (bytesRead != TcpClient::EXPECTED_TEST_MSG_LEN) {
            qDebug() << "Wrong test msg len:" << bytesRead << "!=" << TcpClient::EXPECTED_TEST_MSG_LEN;
            continue;
        }
        qDebug() << "test msg read:" << bytesRead;

        int sent;
        try {
            sent = socket.encryptAndSend(reinterpret_cast<const u_char*>(TcpClient::TEST_MESSAGE), 4);
        } catch (const std::exception& ex) {
            qDebug() << "Can't encrypt and send test message:" << ex.what();
            continue;
        }

        if (!socket.waitForBytesWritten(1000)) {
            qDebug() << "Bytes not written!!!(2)";
            continue;
        }
        qDebug() << "test msg sent:" << sent;

        QByteArray decryptedTestMsg;
        try {
            decryptedTestMsg = socket.decryptData(reinterpret_cast<const u_char*>(buffer), TcpClient::EXPECTED_TEST_MSG_LEN);
        } catch (const std::exception& ex) {
            qDebug() << "Can't decrypt test data:" << ex.what();
            continue;
        }

        if (std::strcmp(decryptedTestMsg.data(), TcpClient::TEST_MESSAGE) != 0) {
            qDebug() << "Error:" << decryptedTestMsg << "!=" << TcpClient::TEST_MESSAGE;
            continue;
        }
        emit information("Addition connection established");
        break;
    }

    QFile file(m_filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        emit error("Can't open file " + m_filePath);
        return;
    }

    QDataStream stream(&file);

    char* sendingBuffer = new char[SENDING_BUFFER_SIZE];
    uint64_t total = 0;

    while (true) {
        auto bytesRead = stream.readRawData(sendingBuffer, SENDING_BUFFER_SIZE);

        qDebug() << "\tREAD:" << bytesRead;

        qint64 written = 0;
        try {
            written = socket.encryptAndSend(reinterpret_cast<u_char*>(sendingBuffer), bytesRead);
        } catch (const std::exception& ex) {
            qDebug() << "Error: can't encrypt/send data to" << m_address << ":" << m_port;
            emit error("Can't encrypt/send data to " + m_address + ":" + QString::number(m_port));
            return;
        }

        if (!socket.waitForBytesWritten(1500)) {
            qDebug() << "Sending timeout";
            emit error("Sending timeout");
            return;
        }

        qDebug() << "\tWRITTEN:" << written;
        total += written;
        if (stream.atEnd()) {
            qDebug() << "read all info";
            break;
        }
    }

    file.close();

    qDebug() << "Information sent:" << total << "bytes";
    emit information("Information sent: " + QString::number(total) + " bytes");
}

void SendFileTask::setPort(u_short port) {
    m_port = port;
}
