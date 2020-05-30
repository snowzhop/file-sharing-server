#include "renamingline.h"

#include <QFocusEvent>

#include <QDebug>

RenamingLine::RenamingLine(const QString& oldName, QWidget* parent) : QLineEdit(parent), m_oldName(oldName) {
}

RenamingLine::~RenamingLine() {
    qDebug() << "RenamingLine::~RenamingLine()";
}

void RenamingLine::focusOutEvent(QFocusEvent *event) {
    if (event->lostFocus()) {
        this->deleteLater();
    }
}

QString RenamingLine::getOldName() {
    return m_oldName;
}
