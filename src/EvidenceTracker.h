#pragma once
#include "Database.h"
#include "Evidence.h"
#include "User.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string>
#include <vector>

// Metadata returned after ingesting a file into evidence storage
struct FileMetadata {
    std::string sha256Hash;
    std::string mimeType;
    long long   fileSize      = 0;
    std::string storedPath;        // copy inside evidence_files/<caseId>/
    bool        fakeImageFlag = false;
    std::string fakeImageReason;
};

class EvidenceTracker {
public:
    EvidenceTracker();
    ~EvidenceTracker();

    // Public DB accessor
    Database& getDb() { return db; }

    // ── Digital signatures (RSA-2048 / OpenSSL 3.x EVP API) ──────
    std::string signEntry  (const std::string& text);
    bool        verifyEntry(const std::string& text,
                            const std::string& signature);

    // ── File / image handling ─────────────────────────────────────
    FileMetadata ingestFile         (const std::string& srcPath,
                                     const std::string& caseId,
                                     int                evidenceId);
    std::string  computeFileSHA256  (const std::string& filePath);
    bool         verifyFileIntegrity(int evidenceId);
    std::string  detectMimeType     (const std::string& filePath);
    bool         basicFakeImageCheck(const std::string& filePath,
                                     std::string& reason);
    std::string  checkIntegrity     (int evidenceId);

    // ── RBAC-controlled actions ───────────────────────────────────

    // Original interface (kept for backward compatibility)
    void addEvidence(const Evidence& ev, const User& user);

    // Extended interface used by GUI (keywords + optional file path)
    void addEvidence(const std::string& caseId,
                     const std::string& description,
                     const std::string& location,
                     const std::string& keywords,
                     const std::string& filePath,
                     const User& user);

    std::vector<EvidenceRecord> searchByCase   (const std::string& caseId,
                                                const User& user);
    EvidenceRecord              searchById     (int evidenceId,
                                                const User& user);
    std::vector<EvidenceRecord> searchByKeyword(const std::string& kw,
                                                const User& user);
    std::vector<CustodyLog>     viewCustodyLogs(const User& user);
    std::vector<AuditLog>       viewAuditLogs  (const User& user);

private:
    Database  db;
    EVP_PKEY* pkey = nullptr;

    std::string currentTimestamp();
    void        denyAccess(const User& user, const std::string& action);
    std::string toHex  (const std::string& raw);
    std::string fromHex(const std::string& hex);
};