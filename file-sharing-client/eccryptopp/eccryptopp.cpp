#include "eccryptopp.h"

#include "cryptopp/filters.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"

using CryptoPP::byte;
using CryptoPP::Integer;

// Default EcCrypto ctor
EcCrypto::EcCrypto() {
    group.Initialize(CryptoPP::ASN1::secp256r1());
    
    CryptoPP::AutoSeededX917RNG<CryptoPP::AES> rng;
    privateKey.Randomize(rng, CryptoPP::Integer::One(), group.GetMaxExponent());
}

EcCrypto::~EcCrypto() {
    delete[] secretKey;
    delete[] iv;
}

CryptoPP::byte* EcCrypto::packKey(const CryptoPP::ECPPoint& elem) {
    return packKey(elem.x, elem.y);
}

CryptoPP::byte* EcCrypto::packKey(const CryptoPP::Integer &x, const CryptoPP::Integer &y) {
    if (x.ByteCount() != 32 || y.ByteCount() != 32) {
        throw std::runtime_error("Wrong arguments");
    }
    byte* packedKey = new byte[66]; /* X-coord(32) + Y-coord(32) + 2 bytes(for type of key) */
    byte* buffer = new byte[32];
    
    packedKey[0] = '0';
    packedKey[1] = '4';
    
    x.Encode(buffer, 32);
    std::strncpy(reinterpret_cast<char*>(packedKey + 2), reinterpret_cast<char*>(buffer), 32);
    
    y.Encode(buffer, 32);
    std::strncpy(reinterpret_cast<char*>(packedKey + 2 + 32), reinterpret_cast<char*>(buffer), 32);
    
    delete[] buffer;
    return packedKey;
}

CryptoPP::ECPPoint EcCrypto::unpackKey(const byte *key) {
    if (key[0] != '0' || key[1] != '4') {
        throw std::runtime_error("Wrong key form!");
    }
    
    int offset = 32; /* Byte offset for each coordinate */
    
    byte* rawX = new byte[32];
    byte* rawY = new byte[32];
    
    for (int i = 2; i < offset + 2; ++i) { /* Skips two first bytes */
        rawX[i-2] = key[i];
    }
    for (int i = offset + 2; i < 2*offset + 2; ++i) { /* Skips two first bytes and X-coordinate*/
        rawY[i-offset-2] = key[i];
    }
    
    return CryptoPP::ECPPoint(Integer(rawX, 32), Integer(rawY, 32));
}

byte* EcCrypto::getPublicKey() {
    Element publicKey = group.ExponentiateBase(privateKey);
    
    return packKey(publicKey);
}

void EcCrypto::deriveSecretKey(const CryptoPP::ECPPoint& point) {
    secretKey = new byte[32];
    
    Element shared = group.GetCurve().ScalarMultiply(point, privateKey);
    
    byte* tmpBuffer = new byte[shared.x.ByteCount()];
    shared.x.Encode(tmpBuffer, shared.x.ByteCount());
    
    CryptoPP::SHA256 sha256;
    sha256.CalculateDigest(secretKey, tmpBuffer, shared.x.ByteCount());
    
    /* TODO replace iv calculation way */
    iv = new byte[IV_SIZE];
    for (int i = 0; i < IV_SIZE; ++i) {
        iv[i] = secretKey[i];
    }
    
    encryptor.SetKeyWithIV(secretKey, 32, iv, IV_SIZE);
    decryptor.SetKeyWithIV(secretKey, 32, iv, IV_SIZE);
    
    delete[] tmpBuffer;
}

void EcCrypto::deriveSecretKey(const Integer& x, const Integer& y) {
    deriveSecretKey(CryptoPP::ECPPoint(x, y));
}

void EcCrypto::deriveSecretKey(const CryptoPP::byte* anotherKey) {
    deriveSecretKey(unpackKey(anotherKey));
}

std::string EcCrypto::encryptData(const CryptoPP::byte *data, size_t length) {
    std::string buffer;
    
    CryptoPP::StringSource(data, length, true,
            new CryptoPP::AuthenticatedEncryptionFilter(encryptor,
                    new CryptoPP::StringSink(buffer), false, TAG_SIZE));
    
    return std::move(buffer);
}

std::string EcCrypto::decryptData(CryptoPP::byte *data, size_t length) {
    std::string buffer;
    
    CryptoPP::AuthenticatedDecryptionFilter df(
            decryptor,
            new CryptoPP::StringSink(buffer),
            CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
            TAG_SIZE
            );
    
    CryptoPP::StringSource(data, length, true, new CryptoPP::Redirector(df));
    
    if (!df.GetLastResult()) {
        // TODO add exception description
        throw std::runtime_error("");
    }
    
    return std::move(buffer);
}

const CryptoPP::byte* EcCrypto::getSecretKey() {
    return secretKey;
}