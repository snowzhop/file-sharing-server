#include "maintable.h"

#include <QDropEvent>

MainTableWidget::MainTableWidget(QWidget* parent) : QTableWidget(parent) {}

MainTableWidget::~MainTableWidget() {}

void MainTableWidget::dropEvent(QDropEvent *event) {
    if (event->source() == this) {
        emit dropRowSignal(this->itemAt(event->pos())->row());
    }
}
