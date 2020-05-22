#ifndef FILESHARINGCLIENT_H
#define FILESHARINGCLIENT_H

#include <QMainWindow>

class FileSharingClient : public QMainWindow
{
    Q_OBJECT

public:
    FileSharingClient(QWidget *parent = nullptr);
    ~FileSharingClient();
};
#endif // FILESHARINGCLIENT_H
