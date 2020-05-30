#include "serverinfodialog.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QRegExp>
#include <QRegExpValidator>

#include <QDebug>

const QString ServerInfoDialog::IP_ADDR_REG_EXP =
    "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

const QString ServerInfoDialog::PORT_REG_EXP =
    "([0-9]{1,4}|[1-5][0-9]"
    "{4}|6[0-4][0-9]{3}|65[0-4]"
    "[0-9]{2}|655[0-2][0-9]|6553[0-5])";

ServerInfoDialog::ServerInfoDialog(QWidget* parent)
    : QDialog(parent),
      serverAddrLine(new QLineEdit(this)),
      portLine(new QLineEdit(this)),
      connectButton(new QPushButton("Connect", this)) {

    QHBoxLayout* addressLayout  = new QHBoxLayout;
    QHBoxLayout* portLayout     = new QHBoxLayout;
    QVBoxLayout* mainLayout     = new QVBoxLayout;

    QRegExp serverAddrRegExp(IP_ADDR_REG_EXP);
    QRegExp portRegExp(PORT_REG_EXP);

    QLabel* serverAddrLabel = new QLabel("Server address:", this);
    serverAddrLine->setText("127.0.0.1");                           /* DEBUG VALUE */
    serverAddrLine->setPlaceholderText("0.0.0.0");
    serverAddrLine->setMinimumWidth(LABEL_MIN_WIDTH);
    serverAddrLine->setValidator(new QRegExpValidator(serverAddrRegExp));
    addressLayout->addWidget(serverAddrLabel, 0, Qt::AlignLeft);
    addressLayout->addWidget(serverAddrLine, 0, Qt::AlignRight);

    QLabel* portLabel = new QLabel("Server port:", this);
    portLine->setText("9999");                                      /* DEBUG VALUE */
    portLine->setPlaceholderText("00000");
    portLine->setMinimumWidth(LABEL_MIN_WIDTH);
    portLine->setValidator(new QRegExpValidator(portRegExp));
    portLayout->addWidget(portLabel, 0, Qt::AlignLeft);
    portLayout->addWidget(portLine, 0, Qt::AlignRight);

    mainLayout->addLayout(addressLayout);
    mainLayout->addLayout(portLayout);
    mainLayout->addWidget(connectButton);
    mainLayout->setSizeConstraint(QLayout::SizeConstraint::SetFixedSize);
    this->setLayout(mainLayout);
    this->setWindowTitle("Set server information");

    connect(connectButton, &QPushButton::clicked, this, [this] {
        if (this->serverAddrLine->hasAcceptableInput()) {
            emit connectSignal(this->serverAddrLine->text(), this->portLine->text().toUShort(nullptr, 10));
            this->close();
        }
    });

}

ServerInfoDialog::~ServerInfoDialog() {
}
