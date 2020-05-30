#ifndef FILESHARINGCLIENT_H
#define FILESHARINGCLIENT_H

#include <QMainWindow>
#include <QEvent>

#include "ui_main.h"
#include "TcpClient/tcpclient.h"

enum struct Command : u_char {
    getFileListCommand = 0,
    changeDirCommand,                // 1
    downloadFileCommand,             // 2
    renameFileCommand,               // 3
    deleteFileCommand,               // 4
    moveFileCommand,                 // 5
    adminAuthCommand,                // 6
    addAdminCommand                  // 7
};

enum class Response : u_char {
    RespOK = 0,         // 0
    RespServerError,    // 1
    RespClientError,    // 2
    RespError,          // 3
    RespFileIsUsing,    // 4
    RespUndefinedFile,  // 5
    RespTestError       // 6
};

class FileSharingClient : public QMainWindow {
    Q_OBJECT

private:
    TcpClient tcpClient;

    bool gotSecretKey = false;

    char* mainBuffer = nullptr;
    UI::Ui_Main* ui = nullptr;

    const int CONNECTION_ATTEMPTS = 5;
    const int MAIN_BUFFER_SIZE = 1024*1024+16;
    const int SERVICE_INFO_SIZE = 5;
    const int STATUS_MESSAGE_TIMEOUT = 10000; // milliseconds

    void connectToServer(const QString address, const QString port);
    void sendMessage(const u_char* data, size_t length);
    void responseProcessing(const u_char* data, size_t length);

    void showFileList(const u_char* rawFileList, size_t length);
    void downloadFile(const u_char* rawFileInfo, size_t length);

    void renameFile(const QString& oldName, const QString& newName);


    const char* getAuthToken();

private slots:
    void establishConnectionSlot(const QString& addr, u_short port);
    void connectToServerSlot();
    void connectedSlot();
    void readyReadSlot();

    void showContextMenuSlot(const QPoint& p);
    void changeDirOrDownloadSlot(int row, bool fromContextMenu = false);
    void getFileListRequestSlot();
    void showRenamingLineSlot();
    void renameFileRequestSlot();
    void deleteFileRequestSlot();
    void moveFileRequestSlot(int rowNumber);

    void infoProcessingSlot(const QString& info);
    void errorProcessingSlot(const QString& err);
    void warningProcessingSlot(const QString& warn, const QString& title = "Warning");

    void testRequestSlot();

public:
    FileSharingClient(QWidget *parent = nullptr);
    ~FileSharingClient();
};
#endif // FILESHARINGCLIENT_H
