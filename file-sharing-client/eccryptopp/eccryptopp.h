#ifndef ELLIPTIC_CURVES_ECCRYPTOPP_H
#define ELLIPTIC_CURVES_ECCRYPTOPP_H

#include "cryptopp/eccrypto.h"

#include "cryptopp/aes.h"
#include "cryptopp/integer.h"
#include "cryptopp/gcm.h"

class EcCrypto {
private:
    using GroupParameters = CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>;
    using Element = CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element; // equals ECPPoint

    const int TAG_SIZE = 16;
    const int IV_SIZE = 12;

    CryptoPP::GCM<CryptoPP::AES>::Encryption encryptor;
    CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor;
    GroupParameters     group;
    CryptoPP::Integer   privateKey;
    CryptoPP::byte*     secretKey = nullptr;
    CryptoPP::byte*     iv = nullptr;

public:

    /// \brief In default constructor program generates new keys
    EcCrypto();
    ~EcCrypto();

    /// \brief Packs two CryptoPP::Integer points into one complete point
    /// \param point the elliptic curve (CryptoPP::ASN1::secp256r1) point
    /// \return elliptic curve point as complete point
    static CryptoPP::byte* packKey(const CryptoPP::ECPPoint& point);
    /// \brief Packs two CryptoPP::Integer points into one complete point
    /// \param x X-coordinate of elliptic curve (CryptoPP::ASN1::secp256r1) point
    /// \param y Y-coordinate of elliptic curve (CryptoPP::ASN1::secp256r1) point
    /// \return elliptic curve point as complete point
    static CryptoPP::byte* packKey(const CryptoPP::Integer& x, const CryptoPP::Integer& y);
    /// \brief Unpacks complete point into two CryptoPP::Integer points
    /// \param key complete elliptic curve (CryptoPP::ASN1::secp256r1) point
    /// \return separate X and Y coordinates in one ECPPoint object
    static CryptoPP::ECPPoint unpackKey(const CryptoPP::byte* key);

    /// \brief Returns complete public key
    /// \return public key as complete point
    CryptoPP::byte* getPublicKey();

    /// \brief Creates secret key using others public key as ECPPoint
    /// \param point elliptic curve (CryptoPP::ASN1::secp256r1) point
    void deriveSecretKey(const CryptoPP::ECPPoint& point);
    /// \brief Creates secret key using others public key as two CryptoPP::Integers
    /// \param x X-coordinate of others public key
    /// \param y Y-coordinate of others public key
    void deriveSecretKey(const CryptoPP::Integer& x, const CryptoPP::Integer& y);
    /// \brief Creates secret key using others public key as one complete point
    /// \param anotherKey others public key as complete key
    void deriveSecretKey(const CryptoPP::byte* anotherKey);

    /// \brief Encrypts user's data using AES-256 GCM
    /// \param data user's data
    /// \return encrypted data
    std::string encryptData(const CryptoPP::byte* data, size_t length);
    /// \brief Decrypts data which was encrypted using AES-256 GCM
    /// \param data encrypted data
    /// \return decrypted data
    std::string decryptData(const CryptoPP::byte* data, size_t length);

    /* Temporary methods */
    const CryptoPP::byte* getSecretKey();
    /* Temporary methods */
};


#endif //ELLIPTIC_CURVES_ECCRYPTOPP_H
