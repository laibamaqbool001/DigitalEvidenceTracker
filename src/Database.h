#pragma once
#include <string>
#include <vector>
#include <sqlite3.h>

// ── Data structures ───────────────────────────────────────────────

struct EvidenceRecord {
    int         id            = 0;
    std::string caseId;
    std::string description;
    std::string location;
    std::string addedBy;
    std::string timestamp;
    // Extended fields
    std::string filePath;       // original filename / path label
    std::string fileHash;       // SHA-256 hex of the file bytes
    std::string mimeType;       // e.g. "image/jpeg", "application/pdf"
    long long   fileSize       = 0;   // bytes
    std::string storedPath;     // path inside evidence_files/ store
    std::string integrityStatus;// "OK" | "TAMPERED" | "MISSING" | ""
    std::string keywords;       // space-separated keyword tags
};

struct CustodyLog {
    int         id         = 0;
    int         evidenceId = 0;
    std::string user;
    std::string role;
    std::string action;
    std::string timestamp;
    std::string signature;      // hex-encoded RSA-2048 signature
    std::string sigStatus;      // "VALID" | "INVALID"
};

struct AuditLog {
    int         id        = 0;
    std::string user;
    std::string role;
    std::string action;
    std::string result;
    std::string timestamp;
};

struct UserRecord {
    int         id = 0;
    std::string username;
    std::string passwordHash;
    std::string role;
};

// ── Database class ────────────────────────────────────────────────

class Database {
public:
    explicit Database(const std::string& dbPath = "evidence.db");
    ~Database();

    // ── Evidence ──
    int  insertEvidence(const std::string& caseId,
                        const std::string& description,
                        const std::string& location,
                        const std::string& addedBy,
                        const std::string& filePath      = "",
                        const std::string& fileHash      = "",
                        const std::string& mimeType      = "",
                        long long          fileSize       = 0,
                        const std::string& storedPath    = "",
                        const std::string& keywords      = "");

    void updateIntegrityStatus(int evidenceId, const std::string& status);
    void updateFileHash(int evidenceId, const std::string& newHash);
    void updateFileMetadata(int evidenceId,
                            const std::string& filePath,
                            const std::string& fileHash,
                            const std::string& mimeType,
                            long long          fileSize,
                            const std::string& storedPath,
                            const std::string& integrityStatus);

    std::vector<EvidenceRecord> searchEvidenceByCase(const std::string& caseId);
    std::vector<EvidenceRecord> searchEvidenceByKeyword(const std::string& kw);
    EvidenceRecord              searchEvidenceById(int id);
    std::vector<std::string>    fetchAllCaseIds();
    std::vector<EvidenceRecord> fetchAllEvidence();

    // ── Custody logs ──
    void insertCustodyLog(int evidenceId,
                          const std::string& user,
                          const std::string& role,
                          const std::string& action,
                          const std::string& timestamp,
                          const std::string& signature  = "",
                          const std::string& sigStatus  = "");

    std::vector<CustodyLog> fetchCustodyLogs();
    std::vector<CustodyLog> fetchCustodyLogsByEvidence(int evidenceId);

    // ── Audit logs ──
    void insertAuditLog(const std::string& user,
                        const std::string& role,
                        const std::string& action,
                        const std::string& result);
    std::vector<AuditLog> fetchAuditLogs();

    // ── Users ──
    void       insertUser(const std::string& username,
                          const std::string& password,
                          const std::string& role);
    UserRecord fetchUser(const std::string& username,
                         const std::string& password);
    bool       userExists(const std::string& username);

    // ── Backup ──
    bool backupDatabase(const std::string& destPath);

    // ── Helpers (public for ReportGenerator) ──
    std::string currentTimestamp();

private:
    sqlite3*    conn = nullptr;
    void        createTables();
    std::string hashPassword(const std::string& password);
};