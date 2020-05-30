#ifndef MAINTABLE_H
#define MAINTABLE_H

#include <QTableWidget>

class MainTableWidget : public QTableWidget {
    Q_OBJECT
public:
    MainTableWidget(QWidget* parent = nullptr);
    virtual ~MainTableWidget();

signals:
    void dropRowSignal(int rowNumber);

protected:
    virtual void dropEvent(QDropEvent *event) override;
};

#endif
