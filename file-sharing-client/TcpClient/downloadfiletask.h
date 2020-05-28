#ifndef DOWNLOADFILETASK_H
#define DOWNLOADFILETASK_H

#include <QRunnable>
#include <QObject>

class DownloadFileTask : public QObject, public QRunnable {
    Q_OBJECT
public:
    DownloadFileTask(const QString& fileName, const QString& address, u_short port, QObject* receiver = nullptr);
    virtual ~DownloadFileTask();
    void run() override;

signals:
    void information(const QString& info);
    void error(const QString& err);

private:
    QString m_fileName;
    QString m_address;
    u_short m_port;

    QObject* m_receiver = nullptr;

    const int BUFFER_FILE_SIZE = 1024 * 1024 + 16;
};

#endif // DOWNLOADFILETASK_H
