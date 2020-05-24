#include "filesharingclient.h"
#include "util/util.h"

#include <QDebug>
#include <QTableWidgetItem>
#include <QCommonStyle>

#include <iostream>

FileSharingClient::FileSharingClient(QWidget *parent)
    : QMainWindow(parent),
      ui(new UI::Ui_Main) {

    ui->setupUi(this);
    this->show();

    mainBuffer = new char[MAIN_BUFFER_SIZE];

    connect(ui->connectToServerButton, &QPushButton::pressed, this, &FileSharingClient::connectToServerSlot);
    connect(ui->testButton, &QPushButton::pressed, this, &FileSharingClient::testRequestSlot);

    connect(ui->tableWidget, &QTableWidget::cellDoubleClicked, this, &FileSharingClient::doubleClickSlot);

    connect(&tcpClient, &TcpClient::connected, this, &FileSharingClient::connectedSlot);
    connect(&tcpClient, &TcpClient::readyRead, this, &FileSharingClient::readyReadSlot);
}

FileSharingClient::~FileSharingClient() {
    delete[] mainBuffer;
    delete ui;
}

void FileSharingClient::connectToServerSlot() {
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

        getFileListRequestSlot();
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
    qDebug() << "Empty test request";
}

/* ---- REQUEST CREATING FUNCTIONS ---- */

void FileSharingClient::getFileListRequestSlot() {
    u_char* request = new u_char(2);
    request[0] = 0;
    request[1] = 0;

    try {
        tcpClient.encryptAndSend(request, 2);
    } catch (const std::exception& ex) {
        qDebug() << "Encrypt and send exception:" << ex.what();
    }
}

void FileSharingClient::doubleClickSlot(int row) {
    qDebug() << "Got row:" << row;

    auto data = ui->tableWidget->item(row, 0)->data(Qt::DisplayRole);
    QString dirName;
    if (data.isValid() && data.toString().length() > 0) {
        dirName = data.toString();
    } else {
        qDebug() << "doubleClickSlot: Error data.toString()";
        return;
    }

    data = ui->tableWidget->item(row, 2)->data(Qt::DisplayRole);

    if (data.isValid() && data.toString().length() > 0) {
        if (data.toString()[0] == 'D') {
            QByteArray request;
            QDataStream stream(&request, QIODevice::WriteOnly);
            stream << static_cast<u_char>(Command::changeDirCommand);
            stream.writeRawData("\0\0\0\0", 4);
            stream.writeRawData(dirName.toStdString().c_str(), dirName.length());

            try {
                tcpClient.encryptAndSend(reinterpret_cast<const u_char*>(request.data()), request.length());
            } catch (const std::exception& ex) {
                qDebug() << "changeDir exception:" << ex.what();
            }
        }
    }
}

/* ---- MAIN PROCESS FUNCTION ---- */

void FileSharingClient::responseProcessing(const u_char *data, size_t length) {
    if (length > 2) {
        if (!data[1]) {
            switch (static_cast<Command>(data[0])) {
            case Command::getFileListCommand: {
                showFileList(data+2, length-2);
                break;
            }
            case Command::changeDirCommand: {
                ui->tableWidget->setRowCount(0);
                showFileList(data+2, length-2);
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

/* ----- PROCESSING FUNCTIONS ----- */

void FileSharingClient::showFileList(const u_char* rawFileList, size_t length) {
    QByteArray allFiles;
    QDataStream stream(&allFiles, QIODevice::WriteOnly);
    stream.writeRawData(reinterpret_cast<const char*>(rawFileList), length);
    qDebug() << allFiles;

    auto fileList = allFiles.split('#');

    ui->tableWidget->setRowCount(fileList.length() + 1);

    ui->tableWidget->setItem(0, 0, new QTableWidgetItem(".."));
    ui->tableWidget->setItem(0, 2, new QTableWidgetItem("Directory"));


    for (int i = 0; i < fileList.size(); ++i ) {  // Classic for-cycle for delegate setting
        if (fileList[i].length() > 0) {
            int length = fileList[i].length();
            QTableWidgetItem* newItem = new QTableWidgetItem();
            if (fileList[i][length-1] == 'd') {

                newItem->setIcon(QCommonStyle().standardIcon(QStyle::SP_DirIcon));
                newItem->setText(fileList[i].chopped(1));
                newItem->setToolTip(fileList[i].chopped(1));

                ui->tableWidget->setItem(i+1, 0, newItem);

                ui->tableWidget->setItem(i+1, 2, new QTableWidgetItem("Directory"));
            } else if (fileList[i][length-1] == 'f') {

                newItem->setIcon(QCommonStyle().standardIcon(QStyle::SP_FileIcon));
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
