#include "filesharingclient.h"
#include "util/util.h"
#include "TcpClient/downloadfiletask.h"
#include "MinorDialogs/ServerInfoDialog/serverinfodialog.h"
#include "Widgets/RenamingLine/renamingline.h"

#include <QDebug>
#include <QThreadPool>
#include <QTableWidgetItem>
#include <QCommonStyle>
#include <QMenu>
#include <QMessageBox>
#include <QFileDialog>

#include <iostream>

FileSharingClient::FileSharingClient(QWidget *parent)
    : QMainWindow(parent),
      ui(new UI::Ui_Main) {

    ui->setupUi(this);
    this->show();

    mainBuffer = new char[MAIN_BUFFER_SIZE];

    ui->tableWidget->installEventFilter(this);

//    connect(ui->connectToServerButton, &QPushButton::pressed, this, &FileSharingClient::establishConnectionSlot);
    connect(ui->connectToServerButton, &QPushButton::clicked, this, [this] {
        ServerInfoDialog servInfo;

        connect(&servInfo, &ServerInfoDialog::connectSignal, this, &FileSharingClient::establishConnectionSlot);

        servInfo.exec();
    });
}

FileSharingClient::~FileSharingClient() {
    delete[] mainBuffer;
    delete ui;
}

void FileSharingClient::establishConnectionSlot(const QString& serverAddr, u_short serverPort) {
    if (tcpClient.state() != TcpClient::ConnectedState) {
        char buffer[128];
        tcpClient.connectToHost(serverAddr, serverPort);
        for (int i = 0; i < CONNECTION_ATTEMPTS; ++i) {
//            qDebug() << "Handshake attempt:" << i+1;

            if (tcpClient.state() != TcpClient::ConnectedState && tcpClient.state() != TcpClient::ConnectedState) {
                tcpClient.connectToHost(serverAddr, serverPort);
            }

            if (!tcpClient.waitForConnected(2000)) {
                continue;
            }

//            qDebug() << "connected";
            tcpClient.generateKeys();

            try {
                sendMessage(tcpClient.getPackedPublicKey(), 66);
            } catch (const std::exception& ex) {
                qDebug() << "Sending pub key exceprion:" << ex.what();
                continue;
            }

            if (!tcpClient.waitForBytesWritten(1000)) {
                qDebug() << "Bytes not written!!!(1)";
                continue;
            }
//            qDebug() << "key was sent";
            if (!tcpClient.waitForReadyRead(5000)) {
                continue;
            }

            auto bytesRead = tcpClient.read(buffer, 128);
            if (bytesRead != 66) {
                qDebug() << "bytesRead(1) != 66";
                continue;
            }

//            qDebug() << "bytesRead:" << bytesRead;

            try {
                tcpClient.calculateSecretKey(reinterpret_cast<const u_char*>(buffer));
            } catch (const std::exception& ex) {
                qDebug() << "Secret key calculating error:" << ex.what();
                continue;
            }
            QByteArray secret(reinterpret_cast<const char*>(tcpClient.getSecretKey()), 32);
            qDebug() << "Secret key:" << secret.toHex();

            if (!tcpClient.waitForReadyRead(5000)) {
                qDebug() << "Reading test msg timeout";
                continue;
            }

            bytesRead = tcpClient.read(buffer, 128);
            if (bytesRead != TcpClient::EXPECTED_TEST_MSG_LEN) {
                qDebug() << "Wrong test msg len:" << bytesRead << "!=" << TcpClient::EXPECTED_TEST_MSG_LEN;
                continue;
            }
//            qDebug() << "test msg read:" << bytesRead;

            int sent;
            try {
                sent = tcpClient.encryptAndSend(reinterpret_cast<const u_char*>(TcpClient::TEST_MESSAGE), 4);
            } catch (const std::exception& ex) {
                qDebug() << "Can't encrypt and send test message:" << ex.what();
                continue;
            }

            if (!tcpClient.waitForBytesWritten(1000)) {
                qDebug() << "Bytes not written!!!(2)";
                continue;
            }
//            qDebug() << "test msg sent:" << sent;

            QByteArray decryptedTestMsg;
            try {
                decryptedTestMsg = tcpClient.decryptData(reinterpret_cast<const u_char*>(buffer), TcpClient::EXPECTED_TEST_MSG_LEN);
            } catch (const std::exception& ex) {
                qDebug() << "Can't decrypt test data:" << ex.what();
                continue;
            }

            if (std::strcmp(decryptedTestMsg.data(), TcpClient::TEST_MESSAGE) != 0) {
                qDebug() << "Error:" << decryptedTestMsg << "!=" << TcpClient::TEST_MESSAGE;
                continue;
            }

            infoProcessingSlot(QString("Connected to ").append(tcpClient.peerName()));

            connect(ui->tableWidget, &QTableWidget::cellDoubleClicked, this, &FileSharingClient::changeDirOrDownloadSlot);
            connect(ui->tableWidget, &MainTableWidget::dropRowSignal, this, &FileSharingClient::moveFileRequestSlot);
            connect(ui->tableWidget, &QTableWidget::customContextMenuRequested, this, &FileSharingClient::showContextMenuSlot);

            connect(&tcpClient, &TcpClient::readyRead, this, &FileSharingClient::readyReadSlot);

            getFileListRequestSlot();
            return;
        }
    }
    // Connection already established

}

void FileSharingClient::connectToServerSlot() {
    tcpClient.connectToHost("127.0.0.1", 9999);
}

const char* FileSharingClient::getAuthToken() {
    const char* ret = "\0\0\0\0";
    return ret;
}

void FileSharingClient::connectedSlot() {
    qDebug() << "Connected to" << tcpClient.peerName();
    sendMessage(tcpClient.getPackedPublicKey(), 66);
}

void FileSharingClient::sendMessage(const u_char* data, size_t length) {
//    if (!gotSecretKey && (tcpClient.state() == TcpClient::ConnectedState)) {
    auto sent = tcpClient.write(reinterpret_cast<const char*>(data), length);
    qDebug() << "sent:" << sent;
}

void FileSharingClient::readyReadSlot() {
    qDebug() << "Bytes available:" << tcpClient.bytesAvailable();

    int readBytes = 0;

    if (tcpClient.state() == TcpClient::ConnectedState) {
        size_t total = 0;


        while (tcpClient.bytesAvailable()) {
            readBytes = tcpClient.read(mainBuffer, MAIN_BUFFER_SIZE);
            total += readBytes;
        }
    }

    QByteArray decryptedData = tcpClient.decryptData(reinterpret_cast<const u_char*>(mainBuffer), readBytes);
    responseProcessing(reinterpret_cast<const u_char*>(decryptedData.data()), decryptedData.length());

}

void FileSharingClient::testRequestSlot() {
    qDebug() << "test request slot";
    RenamingLine* renamingLine = reinterpret_cast<RenamingLine*>(sender());
    renamingLine->deleteLater();
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

void FileSharingClient::showContextMenuSlot(const QPoint& point) {
    QMenu* contextMenu = new QMenu(this);

    QAction* renameFile = new QAction("Rename", this);
    QAction* downloadFile = new QAction("Download", this);
    QAction* deleteFile = new QAction("Delete", this);

    /*
     * Here must be connections
     * */
    connect(downloadFile, &QAction::triggered, this, [this, point] {
        changeDirOrDownloadSlot(ui->tableWidget->itemAt(point)->row(), true);
    });
    connect(renameFile, &QAction::triggered, this, &FileSharingClient::showRenamingLineSlot);
    connect(deleteFile, &QAction::triggered, this, &FileSharingClient::deleteFileRequestSlot);


    contextMenu->addAction(downloadFile);
    contextMenu->addAction(renameFile);
    contextMenu->addSeparator();
    contextMenu->addAction(deleteFile);

    contextMenu->popup(ui->tableWidget->viewport()->mapToGlobal(point));
}

void FileSharingClient::showRenamingLineSlot() {
    qDebug() << "showRenamingLineSlot";
    auto items = ui->tableWidget->selectedItems();
    auto fileName = items[0]->data(Qt::DisplayRole).toString();

    RenamingLine* renamingLine = new RenamingLine(fileName, this);

    int row = ui->tableWidget->rowViewportPosition(items[0]->row())
              + renamingLine->height()
              + ui->tableWidget->rowHeight(items[0]->row()) * 2;
    int col = ui->tableWidget->columnViewportPosition(items[0]->column());

    renamingLine->resize(ui->tableWidget->columnWidth(0), renamingLine->height());
    renamingLine->move(ui->tableWidget->mapToParent(QPoint(col, row)));

    connect(renamingLine, &QLineEdit::returnPressed, this, &FileSharingClient::renameFileRequestSlot);

    renamingLine->show();
    renamingLine->setFocus();


}

void FileSharingClient::renameFileRequestSlot() {
    qDebug() << "renameFileRequestSlot";

    RenamingLine* renamingLine = reinterpret_cast<RenamingLine*>(sender());

    QString oldName = renamingLine->getOldName();
    QString newName = renamingLine->text();
    renamingLine->deleteLater();

    if (newName.length() != 0) {
        qDebug() << "oldName:" << oldName << "\tnewName:" << newName;

        QByteArray request;
        QDataStream stream(&request, QIODevice::WriteOnly);
        stream << static_cast<u_char>(Command::renameFileCommand);
        stream.writeRawData(getAuthToken(), 4);
        stream.writeRawData(oldName.toStdString().c_str(), oldName.length());
        stream.writeRawData("#", 1);
        stream.writeRawData(newName.toStdString().c_str(), newName.length());

        try {
            tcpClient.encryptAndSend(reinterpret_cast<const u_char*>(request.data()), request.length());
        } catch (const std::exception& ex) {
            qDebug() << "renameFile exception:" << ex.what();
        }
    } else {
        warningProcessingSlot("Empty name");
    }
}

void FileSharingClient::deleteFileRequestSlot() {
    auto items = ui->tableWidget->selectedItems();
    auto fileName = items[0]->data(Qt::DisplayRole).toString();

    QByteArray request;
    QDataStream stream(&request, QIODevice::WriteOnly);
    stream << static_cast<u_char>(Command::deleteFileCommand);
    stream.writeRawData(getAuthToken(), 4);
    stream.writeRawData(fileName.toStdString().c_str(), fileName.length());

    try {
        tcpClient.encryptAndSend(reinterpret_cast<const u_char*>(request.data()), request.length());
    } catch (const std::exception& ex) {
        qDebug() << "deleteFile exception:" << ex.what();
    }
}

void FileSharingClient::changeDirOrDownloadSlot(int row, bool fromContextMenu) {

    auto data = ui->tableWidget->item(row, 0)->data(Qt::DisplayRole);
    QString fileName;
    if (data.isValid() && data.toString().length() > 0) {
        fileName = data.toString();
    } else {
        qDebug() << "changeDirOrDownloadSlot: Error data.toString()";
        return;
    }

    data = ui->tableWidget->item(row, 2)->data(Qt::DisplayRole);

    QByteArray request;
    QDataStream stream(&request, QIODevice::WriteOnly);

    if (data.isValid() && data.toString().length() > 0) {
        if (data.toString()[0] == 'D') {
            if (!fromContextMenu) {
                stream << static_cast<u_char>(Command::changeDirCommand);
                stream.writeRawData(getAuthToken(), 4);  // TODO Temporary Solution
                stream.writeRawData(fileName.toStdString().c_str(), fileName.length());
            } else {
                warningProcessingSlot("Can't download directory");
                return;
            }

        } else if (data.toString()[0] == 'F') {
            stream << static_cast<u_char>(Command::downloadFileCommand);
            stream.writeRawData(getAuthToken(), 4);
            stream.writeRawData(fileName.toStdString().c_str(), fileName.length());
        }
    }

    try {
        tcpClient.encryptAndSend(reinterpret_cast<const u_char*>(request.data()), request.length());
    } catch (const std::exception& ex) {
        qDebug() << "Double Click exception:" << ex.what();
    }
}

void FileSharingClient::moveFileRequestSlot(int rowNumber) {
    auto selectedFile = ui->tableWidget->selectedItems()[0]->data(Qt::DisplayRole).toString();
    auto targetFile = ui->tableWidget->item(rowNumber, 0)->data(Qt::DisplayRole).toString();

    qDebug() << "target file:" << targetFile;
    qDebug() << "selected file:" << selectedFile;

    auto targetFileInfo = ui->tableWidget->item(rowNumber, 2)->data(Qt::DisplayRole).toString();

    if (targetFileInfo[0] != 'D') {
        warningProcessingSlot("Target isn't directory!");
        return;
    }

    QByteArray request;
    QDataStream stream(&request, QIODevice::WriteOnly);
    stream << static_cast<u_char>(Command::moveFileCommand);
    stream.writeRawData(getAuthToken(), 4);
    stream.writeRawData(selectedFile.toStdString().c_str(), selectedFile.length());
    stream.writeRawData("#", 1);
    stream.writeRawData(targetFile.toStdString().c_str(), targetFile.length());

    try {
        tcpClient.encryptAndSend(reinterpret_cast<const u_char*>(request.data()), request.length());
    } catch (const std::exception& ex) {
        qDebug() << "move file exception:" << ex.what();
    }

}

void FileSharingClient::infoProcessingSlot(const QString& info) {
    ui->statusBar->showMessage(info, STATUS_MESSAGE_TIMEOUT);
    qDebug() << "Info from other thread:" << info;
}

void FileSharingClient::errorProcessingSlot(const QString& err) {
    QMessageBox::critical(this, "Error", err);
    qDebug() << "Error:" << err;
}

void FileSharingClient::warningProcessingSlot(const QString& warn, const QString& title) {
    QMessageBox::warning(this, title, warn);
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
                case Command::renameFileCommand: {
                    ui->tableWidget->setRowCount(0);
                    showFileList(data+2, length-2);
                    break;
                }
                case Command::deleteFileCommand: {
                    ui->tableWidget->setRowCount(0);
                    showFileList(data+2, length-2);
                    break;
                }
                case Command::moveFileCommand: {
                    ui->tableWidget->setRowCount(0);
                    showFileList(data+2, length-2);
                    break;
                }
                case Command::downloadFileCommand: {
                    downloadFile(data+2, length-2);
                }
                default:
                {}
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

void FileSharingClient::downloadFile(const u_char *rawFileInfo, size_t length) {
    QByteArray fileInfo;
    QDataStream stream(&fileInfo, QIODevice::WriteOnly);
    stream.writeRawData(reinterpret_cast<const char*>(rawFileInfo), length);

    auto fileInfoList = fileInfo.split('#');

    QString fileName(fileInfoList[0]);
    u_short port = fileInfoList[1].toUShort(nullptr, 10);

    QString tmpDir = QFileDialog::getExistingDirectory(this,
                     "Choose directory : " + fileName,
                     "/home/polycarp/Test_dir",
                     QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);

    tmpDir.append("/");

    DownloadFileTask* downloadTask = new DownloadFileTask(tmpDir.append(fileName), tcpClient.peerName(), port, nullptr);
    connect(downloadTask, &DownloadFileTask::information, this, &FileSharingClient::infoProcessingSlot);
    connect(downloadTask, &DownloadFileTask::error, this, &FileSharingClient::errorProcessingSlot);

    downloadTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(downloadTask);

}
