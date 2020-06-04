#ifndef SENDFILETASK_H
#define SENDFILETASK_H

#include <QRunnable>
#include <QObject>
#include <QTimer>

class SendFileTask : public QObject, public QRunnable {
    Q_OBJECT
public:
    SendFileTask(const QString& address, const QString& filePath, QObject* parent = nullptr);
    virtual ~SendFileTask();
    void run() override;

    void setPort(u_short port);

signals:
    void information(const QString& info);
    void error(const QString& err);

private:
    QString m_address;
    QString m_filePath;
    u_short m_port;

    const int SENDING_BUFFER_SIZE = 1024 * 1024;
};

#endif // SENDFILETASK_H

