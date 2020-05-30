#ifndef SERVER_INFO_DIALOG_H
#define SERVER_INFO_DIALOG_H

#include <QDialog>

#include <QLineEdit>
#include <QPushButton>

class ServerInfoDialog : public QDialog {
    Q_OBJECT
public:
    ServerInfoDialog(QWidget* parent = nullptr);
    virtual ~ServerInfoDialog();

signals:
    void connectSignal(const QString& addr, u_short port);

private:
    static const int LABEL_MIN_WIDTH = 200;
    static const QString IP_ADDR_REG_EXP;
    static const QString PORT_REG_EXP;

    QLineEdit* serverAddrLine   = nullptr;
    QLineEdit* portLine         = nullptr;

    QPushButton* connectButton = nullptr;
};

#endif // SERVER_INFO_DIALOG_H
