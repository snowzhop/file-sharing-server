#include "filesharingclient.h"
#include "util/util.h"

#include <QDebug>
#include <QTableWidgetItem>

#include <iostream>

FileSharingClient::FileSharingClient(QWidget *parent)
    : QMainWindow(parent),
      ui(new UI::Ui_Main) {

    ui->setupUi(this);
    this->show();

    mainBuffer = new char[MAIN_BUFFER_SIZE];

    ui->tableWidget->setColumnCount(3);
    ui->tableWidget->setHorizontalHeaderLabels(QStringList() << "File name" << "Size" << "Type");
    ui->tableWidget->setSortingEnabled(false);
    ui->tableWidget->setSelectionBehavior(QTableWidget::SelectRows);


    connect(ui->connectToServerButton, &QPushButton::pressed, this, &FileSharingClient::connectToServerSlot);
    connect(ui->testButton, &QPushButton::pressed, this, &FileSharingClient::testRequestSlot);

    connect(&tcpClient, &TcpClient::connected, this, &FileSharingClient::connectedSlot);
    connect(&tcpClient, &TcpClient::readyRead, this, &FileSharingClient::readyReadSlot);
}

FileSharingClient::~FileSharingClient() {
    delete[] mainBuffer;
    delete ui;
}

void FileSharingClient::connectToServerSlot() {
    qDebug() << "connection to host";
    tcpClient.connectToHost("127.0.0.1", 9999);
}

void FileSharingClient::connectedSlot() {
    qDebug() << "Connected to" << tcpClient.peerName();
    sendMessage(tcpClient.getPackedPublicKey(), 66);
}

void FileSharingClient::sendMessage(const u_char* data, size_t length) {
//    if (!gotSecretKey && (tcpClient.state() == TcpClient::ConnectedState)) {
    auto sent = tcpClient.write(reinterpret_cast<const char*>(data), length);
    qDebug() << "sent:" << sent;
//    }
}

void FileSharingClient::readyReadSlot() {
    qDebug() << "Bytes available:" << tcpClient.bytesAvailable();
    if (!gotSecretKey && (tcpClient.state() == TcpClient::ConnectedState)) {
        char buffer[128];
        int allBytes = 0;

        if (tcpClient.bytesAvailable() == 66) {
            allBytes = tcpClient.read(buffer, 128);
            tcpClient.calculateSecretKey(reinterpret_cast<unsigned char*>(buffer));
            qDebug() << "Secret key was calculated";
        }
        QByteArray secret(reinterpret_cast<const char*>(tcpClient.getSecretKey()), 32);
        qDebug() << "Secret key:" << secret.toHex();
        gotSecretKey = true;
        return;
    }

    int readBytes = 0;

    if (gotSecretKey && (tcpClient.state() == TcpClient::ConnectedState)) {
        size_t total = 0;
//        char* cache = nullptr;


        while (tcpClient.bytesAvailable()) {
            readBytes = tcpClient.read(mainBuffer, MAIN_BUFFER_SIZE);
            qDebug() << "readBytes:" << readBytes;
            total += readBytes;
        }
        qDebug() << "total:" << total;
    }

    QByteArray decryptedData = tcpClient.decryptData(reinterpret_cast<const u_char*>(mainBuffer), readBytes);
    responseProcessing(reinterpret_cast<const u_char*>(decryptedData.data()), decryptedData.length());

}

void FileSharingClient::testRequestSlot() {
    u_char* request = new u_char(2);
    request[0] = 0;
    request[1] = 0;

    try {
        tcpClient.encryptAndSend(request, 2);
    } catch (const std::exception& ex) {
        qDebug() << "Encrypt and send exception:" << ex.what();
    }
}

void FileSharingClient::responseProcessing(const u_char *data, size_t length) {
    if (length > 2) {
        if (!data[1]) {
            switch (static_cast<Command>(data[0])) {
            case Command::getFileListCommand: {
                QByteArray files;
                QDataStream stream(&files, QIODevice::WriteOnly);
                stream.writeRawData(reinterpret_cast<const char*>(data+2), length-2);
                qDebug() << files;
                showFileList(files);
                break;
            }
            case Command::changeDirCommand: {
                break;
            }
            default: {

            }
            }
        } else {
            qDebug() << "Command:" << data[0] << "Answer:" << data[1];
        }
    }
}

void FileSharingClient::showFileList(const QByteArray& rawFileList) {
    auto fileList = rawFileList.split('#');

    ui->tableWidget->setRowCount(fileList.length() + 1);

    ui->tableWidget->setItem(0, 0, new QTableWidgetItem(".."));
    ui->tableWidget->setItem(0, 2, new QTableWidgetItem("Directory"));


    for (int i = 0; i < fileList.size(); ++i ) {  // Classic for-cycle for delegate setting
        if (fileList[i].length() > 0) {
            int length = fileList[i].length();
            if (fileList[i][length-1] == 'd') {
                QTableWidgetItem* newItem = new QTableWidgetItem;
                newItem->setText(fileList[i].chopped(1));
                newItem->setToolTip(fileList[i].chopped(1));

                ui->tableWidget->setItem(i+1, 0, newItem);

                ui->tableWidget->setItem(i+1, 2, new QTableWidgetItem("Directory"));
            } else if (fileList[i][length-1] == 'f') {
                QTableWidgetItem* newItem = new QTableWidgetItem;
                newItem->setText(fileList[i].chopped(SERVICE_INFO_SIZE));
                newItem->setToolTip(fileList[i].chopped(SERVICE_INFO_SIZE));

                ui->tableWidget->setItem(i+1, 0, newItem);
                auto fileSize = fileList[i].right(SERVICE_INFO_SIZE).chopped(1);
                ui->tableWidget->setItem(i+1, 1, new QTableWidgetItem(QString::number(Util::byteRepresentationToUint(fileSize))));
                ui->tableWidget->setItem(i+1, 2, new QTableWidgetItem("File"));
            }
        } else {
            ui->tableWidget->removeRow(ui->tableWidget->rowCount() - 1);
        }
    }
}
