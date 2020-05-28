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
//    char cache[1024*1024];
    QByteArray b_cache;
    b_cache.reserve(BUFFER_FILE_SIZE);

    TcpClient socket;

    socket.connectToHost(m_address, m_port);

    if (socket.waitForConnected(5000)) {
        emit information("Connected to " + socket.peerAddress().toString());

        const char* ownPubKey = reinterpret_cast<const char*>(socket.getPackedPublicKey());
        qDebug() << "client PubKey:";
        Util::printBytes(reinterpret_cast<const u_char*>(ownPubKey), 66);
        socket.write(ownPubKey, 66);

        if (socket.waitForBytesWritten(5000)) {
            qDebug() << "bytes written";
            if (socket.waitForReadyRead(5000)) {
                auto bytesRead = socket.read(buffer, BUFFER_FILE_SIZE);
                qDebug() << "bytesRead:" << bytesRead;
                qDebug() << "server PubKey:";
                Util::printBytes(reinterpret_cast<const u_char*>(buffer), 66);
                qDebug() << "Some sh..?:";
                Util::printBytes(reinterpret_cast<const u_char*>(buffer), bytesRead);
                try {
                    socket.calculateSecretKey(reinterpret_cast<u_char*>(buffer));
                } catch (const std::exception& ex) {
                    qDebug() << "Secret key calculating exception:" << ex.what();
                    return;
                }

                QByteArray secret(reinterpret_cast<const char*>(socket.getSecretKey()), 32);
                qDebug() << "Local secret key:" << secret.toHex();
            } else {
                emit error(socket.errorString());
                return;
            }
        } else {
            emit error(socket.errorString());
            return;
        }
    } else {
        emit error(socket.errorString());
        return;
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
