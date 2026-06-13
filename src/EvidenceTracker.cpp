/*  EvidenceTracker.cpp
 *  Single implementation file — replaces both the old EvidenceTracker.cpp
 *  and any EvidenceTracker methods that previously lived in Evidence.cpp.
 *  Evidence.cpp now only contains Evidence (AES) methods — do NOT add it
 *  back to CMakeLists as a source of EvidenceTracker symbols.
 */
#include "EvidenceTracker.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <stdexcept>
#include <ctime>
#include <cstring>
#include <filesystem>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
//  CONSTRUCTOR / DESTRUCTOR
// ─────────────────────────────────────────────────────────────────────────────
EvidenceTracker::EvidenceTracker() : db("evidence.db") {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen_init failed");
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen failed");
    }
    EVP_PKEY_CTX_free(ctx);

    fs::create_directories("evidence_files");
}

EvidenceTracker::~EvidenceTracker() {
    if (pkey) EVP_PKEY_free(pkey);
}

// ─────────────────────────────────────────────────────────────────────────────
//  PRIVATE HELPERS
// ─────────────────────────────────────────────────────────────────────────────
std::string EvidenceTracker::currentTimestamp() {
    std::time_t now = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return std::string(buf);
}

void EvidenceTracker::denyAccess(const User& user, const std::string& action) {
    db.insertAuditLog(user.getName(), user.getRole(), action, "DENIED");
    std::cout << "[RBAC] Access denied: " << user.getRole()
              << " cannot perform '" << action << "'.\n";
}

std::string EvidenceTracker::toHex(const std::string& raw) {
    std::ostringstream oss;
    for (unsigned char c : raw)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    return oss.str();
}

std::string EvidenceTracker::fromHex(const std::string& hex) {
    std::string out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back((char)std::stoi(hex.substr(i, 2), nullptr, 16));
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
//  DIGITAL SIGNATURES
// ─────────────────────────────────────────────────────────────────────────────
std::string EvidenceTracker::signEntry(const std::string& text) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx); throw std::runtime_error("EVP_DigestSignInit failed");
    }
    if (EVP_DigestSignUpdate(ctx, text.data(), text.size()) <= 0) {
        EVP_MD_CTX_free(ctx); throw std::runtime_error("EVP_DigestSignUpdate failed");
    }

    size_t sigLen = 0;
    EVP_DigestSignFinal(ctx, nullptr, &sigLen);
    std::vector<unsigned char> sig(sigLen);
    EVP_DigestSignFinal(ctx, sig.data(), &sigLen);
    EVP_MD_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(sig.data()), sigLen);
}

bool EvidenceTracker::verifyEntry(const std::string& text,
                                  const std::string& signature) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) > 0 &&
        EVP_DigestVerifyUpdate(ctx, text.data(), text.size()) > 0) {
        ok = (EVP_DigestVerifyFinal(
            ctx,
            reinterpret_cast<const unsigned char*>(signature.data()),
            signature.size()) == 1);
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

// ─────────────────────────────────────────────────────────────────────────────
//  FILE SHA-256 HASH
// ─────────────────────────────────────────────────────────────────────────────
std::string EvidenceTracker::computeFileSHA256(const std::string& filePath) {
    std::ifstream f(filePath, std::ios::binary);
    if (!f) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    char buf[65536];
    while (f.read(buf, sizeof(buf)) || f.gcount() > 0)
        EVP_DigestUpdate(ctx, buf, (size_t)f.gcount());

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int  hashLen = 0;
    EVP_DigestFinal_ex(ctx, hash, &hashLen);
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < hashLen; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  MIME TYPE DETECTION (magic bytes)
// ─────────────────────────────────────────────────────────────────────────────
std::string EvidenceTracker::detectMimeType(const std::string& filePath) {
    std::ifstream f(filePath, std::ios::binary);
    if (!f) return "application/octet-stream";

    unsigned char magic[8] = {0};
    f.read(reinterpret_cast<char*>(magic), 8);

    if (magic[0]==0xFF && magic[1]==0xD8 && magic[2]==0xFF) return "image/jpeg";
    if (magic[0]==0x89 && magic[1]==0x50 && magic[2]==0x4E && magic[3]==0x47) return "image/png";
    if (magic[0]=='G'  && magic[1]=='I'  && magic[2]=='F')  return "image/gif";
    if (magic[0]=='B'  && magic[1]=='M')                     return "image/bmp";
    if (magic[0]=='%'  && magic[1]=='P'  && magic[2]=='D' && magic[3]=='F') return "application/pdf";
    if (magic[0]==0x50 && magic[1]==0x4B)                    return "application/zip";

    // Extension fallback
    std::string ext;
    auto dot = filePath.rfind('.');
    if (dot != std::string::npos) {
        ext = filePath.substr(dot + 1);
        for (auto& c : ext) c = (char)tolower(c);
    }
    if (ext == "txt") return "text/plain";
    if (ext == "mp4") return "video/mp4";
    if (ext == "avi") return "video/x-msvideo";
    if (ext == "mov") return "video/quicktime";
    return "application/octet-stream";
}

// ─────────────────────────────────────────────────────────────────────────────
//  BASIC FAKE-IMAGE DETECTION (heuristics)
// ─────────────────────────────────────────────────────────────────────────────
bool EvidenceTracker::basicFakeImageCheck(const std::string& filePath,
                                          std::string& reason) {
    std::string detected = detectMimeType(filePath);
    std::string ext;
    auto dot = filePath.rfind('.');
    if (dot != std::string::npos) {
        ext = filePath.substr(dot + 1);
        for (auto& c : ext) c = (char)tolower(c);
    }

    // 1 — extension vs magic-byte mismatch
    bool extIsImage  = (ext=="jpg"||ext=="jpeg"||ext=="png"||ext=="gif"||ext=="bmp");
    bool mimeIsImage = (detected.find("image/") == 0);
    if (extIsImage && !mimeIsImage) {
        reason = "Extension claims image but magic bytes disagree (" + detected + ")";
        return true;
    }

    // 2 — suspiciously small
    long long sz = 0;
    try { sz = (long long)fs::file_size(filePath); } catch (...) {}
    if (mimeIsImage && sz > 0 && sz < 1024) {
        reason = "Image file is unusually small (" + std::to_string(sz) + " bytes)";
        return true;
    }

    // 3 — JPEG missing EOI marker (FF D9)
    if (detected == "image/jpeg") {
        std::ifstream ff(filePath, std::ios::binary | std::ios::ate);
        if (ff) {
            std::streamsize fsize = ff.tellg();
            if (fsize >= 2) {
                ff.seekg(-2, std::ios::end);
                unsigned char tail[2] = {0,0};
                ff.read(reinterpret_cast<char*>(tail), 2);
                if (tail[0] != 0xFF || tail[1] != 0xD9) {
                    reason = "JPEG missing end-of-image marker — possible truncation or manipulation";
                    return true;
                }
            }
        }
    }

    reason = "";
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  FILE INGESTION  — copies file, computes hash, returns metadata
// ─────────────────────────────────────────────────────────────────────────────
FileMetadata EvidenceTracker::ingestFile(const std::string& srcPath,
                                         const std::string& caseId,
                                         int                evidenceId) {
    FileMetadata meta;
    if (srcPath.empty()) return meta;

    meta.sha256Hash = computeFileSHA256(srcPath);
    meta.mimeType   = detectMimeType(srcPath);
    try { meta.fileSize = (long long)fs::file_size(srcPath); } catch (...) {}

    std::string dir = "evidence_files/" + caseId;
    fs::create_directories(dir);

    std::string filename = fs::path(srcPath).filename().string();
    // Build stored path and normalize to forward slashes for consistent DB storage
    std::string rawPath = dir + "/" + std::to_string(evidenceId) + "_" + filename;
    meta.storedPath = rawPath;

    try {
        fs::copy_file(srcPath, rawPath, fs::copy_options::overwrite_existing);
        // Store the canonical absolute path so lookups always succeed
        std::error_code ec;
        auto canonical = fs::canonical(rawPath, ec);
        if (!ec) {
            meta.storedPath = canonical.string();
            // Normalize to forward slashes for cross-platform DB consistency
            for (char& c : meta.storedPath) if (c == '\\') c = '/';
        }
    } catch (...) {
        meta.storedPath = "";
    }

    meta.fakeImageFlag = basicFakeImageCheck(srcPath, meta.fakeImageReason);
    return meta;
}

// ─────────────────────────────────────────────────────────────────────────────
//  INTEGRITY VERIFICATION
// ─────────────────────────────────────────────────────────────────────────────
bool EvidenceTracker::verifyFileIntegrity(int evidenceId) {
    EvidenceRecord rec = db.searchEvidenceById(evidenceId);
    if (rec.id == 0 || rec.storedPath.empty() || rec.fileHash.empty())
        return false;

    // Try the stored path as-is first, then with backslashes (Windows),
    // then with forward slashes (as written by ingestFile on MinGW).
    auto tryHash = [&](const std::string& p) -> std::string {
        if (p.empty()) return "";
        return computeFileSHA256(p);
    };

    std::string pathFwd = rec.storedPath;   // as stored (may use / or \)
    std::string pathBk  = rec.storedPath;
    for (char& c : pathBk)  if (c == '/') c = '\\';
    std::string pathFwd2 = rec.storedPath;
    for (char& c : pathFwd2) if (c == '\\') c = '/';

    std::string currentHash = tryHash(pathFwd);
    if (currentHash.empty()) currentHash = tryHash(pathBk);
    if (currentHash.empty()) currentHash = tryHash(pathFwd2);

    // Empty hash = file could not be opened = report MISSING, not TAMPERED
    if (currentHash.empty()) {
        db.updateIntegrityStatus(evidenceId, "MISSING");
        return false;
    }

    bool ok = (currentHash == rec.fileHash);
    db.updateIntegrityStatus(evidenceId, ok ? "OK" : "TAMPERED");
    return ok;
}

std::string EvidenceTracker::checkIntegrity(int evidenceId) {
    EvidenceRecord rec = db.searchEvidenceById(evidenceId);
    if (rec.id == 0)            return "NOT_FOUND";
    if (rec.storedPath.empty()) return "NO_FILE";
    if (rec.fileHash.empty())   return "NO_HASH";

    // Check file exists (try both slash variants) before hashing
    std::string pathBk = rec.storedPath;
    for (char& c : pathBk) if (c == '/') c = '\\';
    std::string pathFwd = rec.storedPath;
    for (char& c : pathFwd) if (c == '\\') c = '/';

    bool exists = fs::exists(rec.storedPath) ||
                  fs::exists(pathBk) ||
                  fs::exists(pathFwd);
    if (!exists) return "MISSING";

    return verifyFileIntegrity(evidenceId) ? "OK" : "TAMPERED";
}

// ─────────────────────────────────────────────────────────────────────────────
//  SHARED CUSTODY LOG HELPER
// ─────────────────────────────────────────────────────────────────────────────
static void logCustody(Database& db, EvidenceTracker& tracker,
                       int id, const User& user, const std::string& ts) {
    std::string entryText = user.getName() + "|" + user.getRole() + "|" +
                            std::to_string(id) + "|" + ts;
    std::string rawSig = tracker.signEntry(entryText);
    bool valid         = tracker.verifyEntry(entryText, rawSig);
    // Convert raw binary sig to hex for DB storage
    std::ostringstream oss;
    for (unsigned char c : rawSig)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    db.insertCustodyLog(id, user.getName(), user.getRole(), "ADD", ts,
                        oss.str(), valid ? "VALID" : "INVALID");
}

// ─────────────────────────────────────────────────────────────────────────────
//  ADD EVIDENCE — original interface (Evidence object, no file)
// ─────────────────────────────────────────────────────────────────────────────
void EvidenceTracker::addEvidence(const Evidence& ev, const User& user) {
    if (user.getRole() != "Investigator" && user.getRole() != "Admin") {
        denyAccess(user, "add_evidence"); return;
    }
    std::string ts = currentTimestamp();
    int id = db.insertEvidence(ev.getCaseId(),
                               ev.getDecryptedDescription(),
                               ev.getDecryptedLocation(),
                               user.getName());
    logCustody(db, *this, id, user, ts);
    db.insertAuditLog(user.getName(), user.getRole(), "add_evidence", "SUCCESS");
    std::cout << "[TRACKER] Evidence #" << id << " added.\n";
}

// ─────────────────────────────────────────────────────────────────────────────
//  ADD EVIDENCE — extended interface (keywords + optional file path)
// ─────────────────────────────────────────────────────────────────────────────
void EvidenceTracker::addEvidence(const std::string& caseId,
                                  const std::string& description,
                                  const std::string& location,
                                  const std::string& keywords,
                                  const std::string& filePath,
                                  const User& user) {
    if (user.getRole() != "Investigator" && user.getRole() != "Admin") {
        denyAccess(user, "add_evidence"); return;
    }
    std::string ts = currentTimestamp();

    // Insert base record first (needs the row ID for the stored file path)
    int id = db.insertEvidence(caseId, description, location,
                               user.getName(), "", "", "", 0, "", keywords);

    // Ingest file and write ALL metadata back in one update
    if (!filePath.empty()) {
        FileMetadata meta = ingestFile(filePath, caseId, id);
        if (!meta.sha256Hash.empty()) {
            std::string status = meta.fakeImageFlag ? "FAKE_SUSPECT" : "OK";
            db.updateFileMetadata(id,
                filePath,           // original path label
                meta.sha256Hash,
                meta.mimeType,
                meta.fileSize,
                meta.storedPath,    // ← this is what checkIntegrity reads
                status);
        }
        if (meta.fakeImageFlag) {
            db.insertAuditLog(user.getName(), user.getRole(),
                              "fake_image_suspect:" + std::to_string(id),
                              "WARNING:" + meta.fakeImageReason);
        }
    }

    logCustody(db, *this, id, user, ts);
    db.insertAuditLog(user.getName(), user.getRole(), "add_evidence", "SUCCESS");
}

// ─────────────────────────────────────────────────────────────────────────────
//  SEARCH
// ─────────────────────────────────────────────────────────────────────────────
std::vector<EvidenceRecord> EvidenceTracker::searchByCase(
        const std::string& caseId, const User& user) {
    if (user.getRole() != "Investigator" &&
        user.getRole() != "Admin" &&
        user.getRole() != "Officer") {
        denyAccess(user, "search_by_case"); return {};
    }
    db.insertAuditLog(user.getName(), user.getRole(), "search_by_case", "SUCCESS");
    return db.searchEvidenceByCase(caseId);
}

EvidenceRecord EvidenceTracker::searchById(int evidenceId, const User& user) {
    if (user.getRole() != "Investigator" &&
        user.getRole() != "Admin" &&
        user.getRole() != "Officer") {
        denyAccess(user, "search_by_id"); return {};
    }
    db.insertAuditLog(user.getName(), user.getRole(), "search_by_id", "SUCCESS");
    return db.searchEvidenceById(evidenceId);
}

std::vector<EvidenceRecord> EvidenceTracker::searchByKeyword(
        const std::string& kw, const User& user) {
    if (user.getRole() != "Investigator" &&
        user.getRole() != "Admin" &&
        user.getRole() != "Officer") {
        denyAccess(user, "search_keyword"); return {};
    }
    db.insertAuditLog(user.getName(), user.getRole(), "search_keyword", "SUCCESS");
    return db.searchEvidenceByKeyword(kw);
}

std::vector<CustodyLog> EvidenceTracker::viewCustodyLogs(const User& user) {
    if (user.getRole() != "Investigator" &&
        user.getRole() != "Admin" &&
        user.getRole() != "Officer") {
        denyAccess(user, "view_custody_logs"); return {};
    }
    db.insertAuditLog(user.getName(), user.getRole(), "view_custody_logs", "SUCCESS");
    return db.fetchCustodyLogs();
}

std::vector<AuditLog> EvidenceTracker::viewAuditLogs(const User& user) {
    if (user.getRole() != "Admin") {
        denyAccess(user, "view_audit_logs"); return {};
    }
    return db.fetchAuditLogs();
}