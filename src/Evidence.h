#pragma once
#include <string>

class Evidence {
public:
    Evidence(int id,
             const std::string& caseId,
             const std::string& description,
             const std::string& location);

    int         getId()                   const;
    std::string getCaseId()               const;
    std::string getDecryptedDescription() const;
    std::string getDecryptedLocation()    const;
    std::string toString()                const;

private:
    int         id;
    std::string caseId;
    std::string encryptedDescription;
    std::string encryptedLocation;

    static const unsigned char KEY[32];
    static const unsigned char IV[16];

    std::string encryptAES(const std::string& plaintext)  const;
    std::string decryptAES(const std::string& ciphertext) const;
};