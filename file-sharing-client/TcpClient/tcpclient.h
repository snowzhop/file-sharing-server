#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <QTcpSocket>

#include "eccryptopp/eccryptopp.h"

class TcpClient : public QTcpSocket {
    Q_OBJECT
public:
    TcpClient(QObject* parent = nullptr);

private:
    void clientHandshake();


};

#endif // TCPCLIENT_H

