#ifndef RENAMING_LINE_H
#define RENAMING_LINE_H

#include <QLineEdit>

class RenamingLine : public QLineEdit {
    Q_OBJECT
public:
    RenamingLine(const QString& oldName, QWidget* parent = nullptr);
    virtual ~RenamingLine();

    QString getOldName();

protected:
    void focusOutEvent(QFocusEvent* event) override;
    QString m_oldName;
};

#endif // RENAMING_LINE_H
