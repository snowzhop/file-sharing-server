#ifndef UTILITIES_H
#define UTILITIES_H

class QByteArray;
using u_int = unsigned int;

namespace Util {

void printBytes(const unsigned char* data, unsigned long size);
u_int byteRepresentationToUint(const QByteArray& str);

}

#endif // UTILITIES_H
