#include "downloadfiletask.h"
#include "tcpclient.h"

#include "util/util.h"

#include <QDebug>

#include <QTcpSocket>
#include <QFile>
#include <QDataStream>
#include <QHostAddress>

DownloadFileTask::DownloadFileTask(const QString& fileName, const QString& address, u_short port, QObject* receiver)
    : m_fileName(fileName),
      m_address(address),
      m_port(port),
      m_receiver(receiver) {

    qDebug() << "DownloadFileTask::DownloadFileTask()";

}

void DownloadFileTask::run() {
    qDebug() << "DownloadFileTask::run() --- --- ---";
    qDebug() << "file name:" << m_fileName;
    qDebug() << "address:" << m_address;
    qDebug() << "port:" << m_port;
    char buffer[BUFFER_FILE_SIZE];
    QByteArray b_cache;
    b_cache.reserve(BUFFER_FILE_SIZE);

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

    QFile file(m_fileName);
    if (!file.open(QIODevice::WriteOnly)) {
        emit error("Can't open file");
        return;
    }
    QDataStream fileStream(&file);
    QByteArray decryptedData;

    qDebug() << "getting file...";
    while (socket.waitForReadyRead(1200)) {
        auto bytesRead = socket.read(buffer, BUFFER_FILE_SIZE);


        QByteArray tmpBuffer;
        tmpBuffer.append(b_cache, b_cache.length()).append(buffer, bytesRead);


        qDebug() << "bytesRead:" << bytesRead
                 << "\tcache.length():" << b_cache.length()
                 << "\ttmpBuffer.length():" << tmpBuffer.length();

        auto parts = tmpBuffer.length() / BUFFER_FILE_SIZE;
        qDebug() << "parts:" << parts;
        int i;
        for (i = 0; i < parts; ++i) {
            qDebug() << "i:" << i;

            try {
                qDebug() << "\ttmpBuffer.length():" << tmpBuffer.length() << "\ti*B_F_S:" << i*BUFFER_FILE_SIZE;
                decryptedData = socket.decryptData(reinterpret_cast<const u_char*>(tmpBuffer.data() + i*BUFFER_FILE_SIZE),
                                                   (i+1)*BUFFER_FILE_SIZE); // I think it's problem place
            } catch (const std::exception& ex) {
                qDebug() << "File decryption exception:" << ex.what();
                emit error("Can't decrypt file information");
                return;
            }

            auto written = fileStream.writeRawData(decryptedData.data(), decryptedData.length());
            qDebug() << "written:" << written;
        }

        b_cache.clear();
        auto tmpLen = b_cache.length();
        b_cache.append(tmpBuffer.data() + parts*BUFFER_FILE_SIZE, tmpBuffer.length() - parts*BUFFER_FILE_SIZE);
        qDebug() << "b_cache.length():[old][new]:" << tmpLen << b_cache.length();
    }

    auto lastRead = socket.read(buffer, BUFFER_FILE_SIZE);

    qDebug() << "lastRead:" << lastRead;
    if (lastRead > 0) {
        b_cache.append(buffer, lastRead);
    }

    try {
        qDebug() << "cache length before last decrypting:" << b_cache.length();
        decryptedData = socket.decryptData(reinterpret_cast<const u_char*>(b_cache.data()), b_cache.length());
    } catch (const std::exception& ex) {
        qDebug() << "File decryption exception:" << ex.what();
        emit error("Can't decrypt last part of file information");
        return;
    }
    fileStream.writeRawData(decryptedData.data(), decryptedData.length());

//    qDebug() << "written from cache:" << written;
    emit information("File " + m_fileName + " was saved");

    file.close();
}

DownloadFileTask::~DownloadFileTask() {
    qDebug() << "DownloadFileTask::~DownloadFileTask";
}
