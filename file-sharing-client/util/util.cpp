#include <QDebug>
#include <string>
#include <QString>
#include "util.h"


void Util::printBytes(const unsigned char* data, unsigned long size) {
    std::string tmp;
    tmp.append("[");

    tmp.append(std::to_string(data[0]));
    for (size_t i = 1; i < size-1; ++i) {
        tmp.append(", ");
        tmp.append(std::to_string(data[i]));
    }
    tmp.append(", ").append(std::to_string(data[size-1])).append("]");

    qDebug() << tmp.c_str();
}

u_int Util::byteRepresentationToUint(const QByteArray& str) {
    qDebug() << "str.length():" << str.length();
    return u_int(static_cast<u_char>(str[0]) << 24 |
                 static_cast<u_char>(str[1]) << 16 |
                 static_cast<u_char>(str[2]) << 8  |
                 static_cast<u_char>(str[3]));
}
