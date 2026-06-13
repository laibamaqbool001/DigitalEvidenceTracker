#include "Database.h"
#include <openssl/evp.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstring>
#include <fstream>

// ── Constructor / Destructor ──────────────────────────────────────
Database::Database(const std::string& dbPath) {
    if (sqlite3_open(dbPath.c_str(), &conn) != SQLITE_OK)
        throw std::runtime_error(
            "Cannot open database: " + std::string(sqlite3_errmsg(conn)));
    sqlite3_exec(conn, "PRAGMA journal_mode=WAL;",  nullptr, nullptr, nullptr);
    sqlite3_exec(conn, "PRAGMA foreign_keys=ON;",   nullptr, nullptr, nullptr);
    createTables();
}

Database::~Database() {
    if (conn) sqlite3_close(conn);
}

// ── Create tables ─────────────────────────────────────────────────
void Database::createTables() {
    const char* sql =
        // Users
        "CREATE TABLE IF NOT EXISTS users ("
        "  id            INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  username      TEXT UNIQUE NOT NULL,"
        "  password_hash TEXT        NOT NULL,"
        "  role          TEXT        NOT NULL"
        ");"
        // Evidence — extended with file metadata
        "CREATE TABLE IF NOT EXISTS evidence ("
        "  id               INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  case_id          TEXT    NOT NULL,"
        "  description      TEXT    NOT NULL,"
        "  location         TEXT    NOT NULL,"
        "  added_by         TEXT    NOT NULL,"
        "  timestamp        TEXT    NOT NULL,"
        "  file_path        TEXT    DEFAULT '',"
        "  file_hash        TEXT    DEFAULT '',"
        "  mime_type        TEXT    DEFAULT '',"
        "  file_size        INTEGER DEFAULT 0,"
        "  stored_path      TEXT    DEFAULT '',"
        "  integrity_status TEXT    DEFAULT '',"
        "  keywords         TEXT    DEFAULT ''"
        ");"
        // Custody logs — with RSA signature columns
        "CREATE TABLE IF NOT EXISTS custody_logs ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  evidence_id INTEGER NOT NULL,"
        "  user        TEXT    NOT NULL,"
        "  role        TEXT    NOT NULL,"
        "  action      TEXT    NOT NULL,"
        "  timestamp   TEXT    NOT NULL,"
        "  signature   TEXT    DEFAULT '',"
        "  sig_status  TEXT    DEFAULT ''"
        ");"
        // Audit logs
        "CREATE TABLE IF NOT EXISTS audit_logs ("
        "  id        INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  user      TEXT    NOT NULL,"
        "  role      TEXT    NOT NULL,"
        "  action    TEXT    NOT NULL,"
        "  result    TEXT    NOT NULL,"
        "  timestamp TEXT    NOT NULL"
        ");";

    char* err = nullptr;
    if (sqlite3_exec(conn, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err; sqlite3_free(err);
        throw std::runtime_error("createTables failed: " + msg);
    }

    // Migration: add new columns to evidence if they don't exist yet
    // (safe to run on existing databases — SQLite ignores duplicate ADD COLUMN)
    const char* migrations[] = {
        "ALTER TABLE evidence ADD COLUMN file_path        TEXT DEFAULT '';",
        "ALTER TABLE evidence ADD COLUMN file_hash        TEXT DEFAULT '';",
        "ALTER TABLE evidence ADD COLUMN mime_type        TEXT DEFAULT '';",
        "ALTER TABLE evidence ADD COLUMN file_size        INTEGER DEFAULT 0;",
        "ALTER TABLE evidence ADD COLUMN stored_path      TEXT DEFAULT '';",
        "ALTER TABLE evidence ADD COLUMN integrity_status TEXT DEFAULT '';",
        "ALTER TABLE evidence ADD COLUMN keywords         TEXT DEFAULT '';",
        "ALTER TABLE custody_logs ADD COLUMN signature  TEXT DEFAULT '';",
        "ALTER TABLE custody_logs ADD COLUMN sig_status TEXT DEFAULT '';",
    };
    for (const char* m : migrations)
        sqlite3_exec(conn, m, nullptr, nullptr, nullptr); // ignore errors (col exists)
}

// ── Helpers ───────────────────────────────────────────────────────
std::string Database::hashPassword(const std::string& pw) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int  hashLen = 0;
    if (EVP_Digest(pw.data(), pw.size(), hash, &hashLen, EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("EVP_Digest (password hash) failed");
    std::ostringstream oss;
    for (unsigned int i = 0; i < hashLen; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

std::string Database::currentTimestamp() {
    std::time_t now = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return std::string(buf);
}

// ── Evidence ──────────────────────────────────────────────────────
int Database::insertEvidence(const std::string& caseId,
                             const std::string& description,
                             const std::string& location,
                             const std::string& addedBy,
                             const std::string& filePath,
                             const std::string& fileHash,
                             const std::string& mimeType,
                             long long          fileSize,
                             const std::string& storedPath,
                             const std::string& keywords) {
    const char* sql =
        "INSERT INTO evidence "
        "(case_id, description, location, added_by, timestamp,"
        " file_path, file_hash, mime_type, file_size, stored_path,"
        " integrity_status, keywords) "
        "VALUES (?,?,?,?,?, ?,?,?,?,?, ?,?);";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr);
    std::string ts = currentTimestamp();
    sqlite3_bind_text  (stmt,  1, caseId.c_str(),      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text  (stmt,  2, description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text  (stmt,  3, location.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text  (stmt,  4, addedBy.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_bind_text  (stmt,  5, ts.c_str(),          -1, SQLITE_TRANSIENT);
    sqlite3_bind_text  (stmt,  6, filePath.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text  (stmt,  7, fileHash.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text  (stmt,  8, mimeType.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64 (stmt,  9, fileSize);
    sqlite3_bind_text  (stmt, 10, storedPath.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text  (stmt, 11, fileHash.empty() ? "" : "OK", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text  (stmt, 12, keywords.c_str(),   -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    int id = (int)sqlite3_last_insert_rowid(conn);
    sqlite3_finalize(stmt);
    return id;
}

void Database::updateIntegrityStatus(int evidenceId, const std::string& status) {
    const char* sql = "UPDATE evidence SET integrity_status=? WHERE id=?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 2, evidenceId);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void Database::updateFileHash(int evidenceId, const std::string& newHash) {
    const char* sql = "UPDATE evidence SET file_hash=? WHERE id=?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, newHash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 2, evidenceId);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void Database::updateFileMetadata(int evidenceId,
                                  const std::string& filePath,
                                  const std::string& fileHash,
                                  const std::string& mimeType,
                                  long long          fileSize,
                                  const std::string& storedPath,
                                  const std::string& integrityStatus) {
    const char* sql =
        "UPDATE evidence SET "
        "file_path=?, file_hash=?, mime_type=?, file_size=?, "
        "stored_path=?, integrity_status=? "
        "WHERE id=?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr);
    sqlite3_bind_text (stmt, 1, filePath.c_str(),        -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 2, fileHash.c_str(),        -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 3, mimeType.c_str(),        -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, fileSize);
    sqlite3_bind_text (stmt, 5, storedPath.c_str(),      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 6, integrityStatus.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int  (stmt, 7, evidenceId);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

static EvidenceRecord rowToRecord(sqlite3_stmt* stmt) {
    EvidenceRecord r;
    r.id              = sqlite3_column_int (stmt, 0);
    r.caseId          = (const char*)sqlite3_column_text(stmt, 1);
    r.description     = (const char*)sqlite3_column_text(stmt, 2);
    r.location        = (const char*)sqlite3_column_text(stmt, 3);
    r.addedBy         = (const char*)sqlite3_column_text(stmt, 4);
    r.timestamp       = (const char*)sqlite3_column_text(stmt, 5);
    if (sqlite3_column_text(stmt, 6))  r.filePath        = (const char*)sqlite3_column_text(stmt, 6);
    if (sqlite3_column_text(stmt, 7))  r.fileHash        = (const char*)sqlite3_column_text(stmt, 7);
    if (sqlite3_column_text(stmt, 8))  r.mimeType        = (const char*)sqlite3_column_text(stmt, 8);
    r.fileSize        = sqlite3_column_int64(stmt, 9);
    if (sqlite3_column_text(stmt,10))  r.storedPath      = (const char*)sqlite3_column_text(stmt,10);
    if (sqlite3_column_text(stmt,11))  r.integrityStatus = (const char*)sqlite3_column_text(stmt,11);
    if (sqlite3_column_text(stmt,12))  r.keywords        = (const char*)sqlite3_column_text(stmt,12);
    return r;
}

static const char* SELECT_EVIDENCE =
    "SELECT id,case_id,description,location,added_by,timestamp,"
    "file_path,file_hash,mime_type,file_size,stored_path,integrity_status,keywords ";

std::vector<EvidenceRecord> Database::searchEvidenceByCase(const std::string& caseId) {
    std::vector<EvidenceRecord> out;
    std::string sql = std::string(SELECT_EVIDENCE) + "FROM evidence WHERE case_id=? ORDER BY id;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, caseId.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(rowToRecord(stmt));
    sqlite3_finalize(stmt);
    return out;
}

std::vector<EvidenceRecord> Database::searchEvidenceByKeyword(const std::string& kw) {
    std::vector<EvidenceRecord> out;
    std::string pattern = "%" + kw + "%";
    std::string sql = std::string(SELECT_EVIDENCE) +
        "FROM evidence WHERE description LIKE ? OR location LIKE ? OR keywords LIKE ? ORDER BY id;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, pattern.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, pattern.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, pattern.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(rowToRecord(stmt));
    sqlite3_finalize(stmt);
    return out;
}

EvidenceRecord Database::searchEvidenceById(int id) {
    EvidenceRecord r;
    std::string sql = std::string(SELECT_EVIDENCE) + "FROM evidence WHERE id=?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, id);
    if (sqlite3_step(stmt) == SQLITE_ROW) r = rowToRecord(stmt);
    sqlite3_finalize(stmt);
    return r;
}

std::vector<std::string> Database::fetchAllCaseIds() {
    std::vector<std::string> out;
    const char* sql = "SELECT DISTINCT case_id FROM evidence ORDER BY case_id;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW)
        out.push_back((const char*)sqlite3_column_text(stmt, 0));
    sqlite3_finalize(stmt);
    return out;
}

std::vector<EvidenceRecord> Database::fetchAllEvidence() {
    std::vector<EvidenceRecord> out;
    std::string sql = std::string(SELECT_EVIDENCE) + "FROM evidence ORDER BY id DESC;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql.c_str(), -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(rowToRecord(stmt));
    sqlite3_finalize(stmt);
    return out;
}

// ── Custody logs ──────────────────────────────────────────────────
void Database::insertCustodyLog(int evidenceId,
                                const std::string& user,
                                const std::string& role,
                                const std::string& action,
                                const std::string& timestamp,
                                const std::string& signature,
                                const std::string& sigStatus) {
    const char* sql =
        "INSERT INTO custody_logs "
        "(evidence_id, user, role, action, timestamp, signature, sig_status) "
        "VALUES (?,?,?,?,?,?,?);";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr);
    sqlite3_bind_int (stmt, 1, evidenceId);
    sqlite3_bind_text(stmt, 2, user.c_str(),      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, role.c_str(),      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, action.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, timestamp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, signature.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, sigStatus.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

static CustodyLog rowToCustody(sqlite3_stmt* stmt) {
    CustodyLog l;
    l.id         = sqlite3_column_int (stmt, 0);
    l.evidenceId = sqlite3_column_int (stmt, 1);
    l.user       = (const char*)sqlite3_column_text(stmt, 2);
    l.role       = (const char*)sqlite3_column_text(stmt, 3);
    l.action     = (const char*)sqlite3_column_text(stmt, 4);
    l.timestamp  = (const char*)sqlite3_column_text(stmt, 5);
    if (sqlite3_column_text(stmt, 6)) l.signature = (const char*)sqlite3_column_text(stmt, 6);
    if (sqlite3_column_text(stmt, 7)) l.sigStatus  = (const char*)sqlite3_column_text(stmt, 7);
    return l;
}

std::vector<CustodyLog> Database::fetchCustodyLogs() {
    std::vector<CustodyLog> out;
    const char* sql =
        "SELECT id,evidence_id,user,role,action,timestamp,signature,sig_status "
        "FROM custody_logs ORDER BY id DESC;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(rowToCustody(stmt));
    sqlite3_finalize(stmt);
    return out;
}

std::vector<CustodyLog> Database::fetchCustodyLogsByEvidence(int evidenceId) {
    std::vector<CustodyLog> out;
    const char* sql =
        "SELECT id,evidence_id,user,role,action,timestamp,signature,sig_status "
        "FROM custody_logs WHERE evidence_id=? ORDER BY id;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, evidenceId);
    while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(rowToCustody(stmt));
    sqlite3_finalize(stmt);
    return out;
}

// ── Audit logs ────────────────────────────────────────────────────
void Database::insertAuditLog(const std::string& user,
                              const std::string& role,
                              const std::string& action,
                              const std::string& result) {
    const char* sql =
        "INSERT INTO audit_logs (user, role, action, result, timestamp) "
        "VALUES (?,?,?,?,?);";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr);
    std::string ts = currentTimestamp();
    sqlite3_bind_text(stmt, 1, user.c_str(),   -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, role.c_str(),   -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, result.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, ts.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<AuditLog> Database::fetchAuditLogs() {
    std::vector<AuditLog> out;
    const char* sql =
        "SELECT id,user,role,action,result,timestamp "
        "FROM audit_logs ORDER BY id DESC;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AuditLog l;
        l.id        = sqlite3_column_int (stmt, 0);
        l.user      = (const char*)sqlite3_column_text(stmt, 1);
        l.role      = (const char*)sqlite3_column_text(stmt, 2);
        l.action    = (const char*)sqlite3_column_text(stmt, 3);
        l.result    = (const char*)sqlite3_column_text(stmt, 4);
        l.timestamp = (const char*)sqlite3_column_text(stmt, 5);
        out.push_back(l);
    }
    sqlite3_finalize(stmt);
    return out;
}

// ── Users ─────────────────────────────────────────────────────────
void Database::insertUser(const std::string& username,
                          const std::string& password,
                          const std::string& role) {
    const char* sql =
        "INSERT INTO users (username, password_hash, role) VALUES (?,?,?);";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr);
    std::string hash = hashPassword(password);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hash.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, role.c_str(),     -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_DONE)
        throw std::runtime_error("Insert user failed — username may already exist.");
    sqlite3_finalize(stmt);
}

UserRecord Database::fetchUser(const std::string& username,
                               const std::string& password) {
    UserRecord r;
    std::string hash = hashPassword(password);
    const char* sql =
        "SELECT id, username, password_hash, role FROM users "
        "WHERE username=? AND password_hash=?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hash.c_str(),     -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        r.id           = sqlite3_column_int (stmt, 0);
        r.username     = (const char*)sqlite3_column_text(stmt, 1);
        r.passwordHash = (const char*)sqlite3_column_text(stmt, 2);
        r.role         = (const char*)sqlite3_column_text(stmt, 3);
    }
    sqlite3_finalize(stmt);
    return r;
}

bool Database::userExists(const std::string& username) {
    const char* sql = "SELECT 1 FROM users WHERE username=?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

// ── Backup ────────────────────────────────────────────────────────
bool Database::backupDatabase(const std::string& destPath) {
    sqlite3* dest = nullptr;
    if (sqlite3_open(destPath.c_str(), &dest) != SQLITE_OK) return false;
    sqlite3_backup* bk = sqlite3_backup_init(dest, "main", conn, "main");
    if (!bk) { sqlite3_close(dest); return false; }
    sqlite3_backup_step(bk, -1);
    sqlite3_backup_finish(bk);
    sqlite3_close(dest);
    return true;
}