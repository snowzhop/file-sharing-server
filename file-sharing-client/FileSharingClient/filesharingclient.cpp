#include "filesharingclient.h"

FileSharingClient::FileSharingClient(QWidget *parent)
    : QMainWindow(parent),
      ui(new UI::Ui_Main) {

    ui->setupUi(this);
    this->show();
}


FileSharingClient::~FileSharingClient() {
}

