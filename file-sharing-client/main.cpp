#include "FileSharingClient/filesharingclient.h"

#include <QApplication>

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    FileSharingClient w;
    w.show();
    return a.exec();
}

