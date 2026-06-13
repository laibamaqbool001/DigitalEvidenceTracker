/*  Evidence.cpp
 *  Contains ONLY the Evidence class implementation (AES-256-CBC encrypt/decrypt).
 *  All EvidenceTracker methods live exclusively in EvidenceTracker.cpp.
 */
#include "Evidence.h"
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>
#include <sstream>

// Demo AES-256-CBC key and IV.
// In production: generate randomly, store securely (e.g. HSM or KMS).
const unsigned char Evidence::KEY[32] = {
    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
    0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
    0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
    0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
};
const unsigned char Evidence::IV[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};

// ── AES-256-CBC encrypt ───────────────────────────────────────────
std::string Evidence::encryptAES(const std::string& plaintext) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, KEY, IV) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    int blockSize = EVP_CIPHER_CTX_get_block_size(ctx);
    std::vector<unsigned char> out(plaintext.size() + blockSize);
    int len = 0, total = 0;

    if (EVP_EncryptUpdate(ctx, out.data(), &len,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            (int)plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    total = len;

    if (EVP_EncryptFinal_ex(ctx, out.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(out.data()), total);
}

// ── AES-256-CBC decrypt ───────────────────────────────────────────
std::string Evidence::decryptAES(const std::string& ciphertext) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, KEY, IV) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    std::vector<unsigned char> out(ciphertext.size());
    int len = 0, total = 0;

    if (EVP_DecryptUpdate(ctx, out.data(), &len,
            reinterpret_cast<const unsigned char*>(ciphertext.data()),
            (int)ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    total = len;

    if (EVP_DecryptFinal_ex(ctx, out.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(out.data()), total);
}

// ── Constructor ───────────────────────────────────────────────────
Evidence::Evidence(int id, const std::string& caseId,
                   const std::string& description,
                   const std::string& location)
    : id(id), caseId(caseId),
      encryptedDescription(encryptAES(description)),
      encryptedLocation(encryptAES(location)) {}

// ── Getters ───────────────────────────────────────────────────────
int         Evidence::getId()    const { return id; }
std::string Evidence::getCaseId() const { return caseId; }

std::string Evidence::getDecryptedDescription() const {
    return decryptAES(encryptedDescription);
}
std::string Evidence::getDecryptedLocation() const {
    return decryptAES(encryptedLocation);
}

std::string Evidence::toString() const {
    std::ostringstream oss;
    oss << "[" << caseId << "] "
        << getDecryptedDescription()
        << " @ " << getDecryptedLocation();
    return oss.str();
}