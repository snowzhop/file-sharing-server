#ifndef FILESHARINGCLIENT_H
#define FILESHARINGCLIENT_H

#include <QMainWindow>

#include "ui_main.h"

class FileSharingClient : public QMainWindow {
    Q_OBJECT

private:
    UI::Ui_Main* ui = nullptr;

public:
    FileSharingClient(QWidget *parent = nullptr);
    ~FileSharingClient();
};
#endif // FILESHARINGCLIENT_H
