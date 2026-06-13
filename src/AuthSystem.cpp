#include "AuthSystem.h"
#include <iostream>
#include <chrono>

AuthSystem::AuthSystem() : db("evidence.db") {}

void AuthSystem::registerUser(const std::string& username,
                              const std::string& password,
                              const std::string& role) {
    if (db.userExists(username)) {
        std::cout << "[AUTH] Username '" << username << "' already exists.\n";
        return;
    }
    try {
        db.insertUser(username, password, role);
        db.insertAuditLog(username, role, "REGISTER", "SUCCESS");
        std::cout << "[AUTH] User '" << username << "' registered as " << role << ".\n";
    } catch (const std::exception& e) {
        std::cout << "[AUTH] Registration failed: " << e.what() << "\n";
    }
}

std::optional<std::string> AuthSystem::login(const std::string& username,
                                             const std::string& password) {
    if (activeSession.has_value()) {
        std::cout << "[AUTH] A user is already logged in. Logout first.\n";
        return std::nullopt;
    }
    UserRecord user = db.fetchUser(username, password);
    if (!user.username.empty()) {
        auto now = std::chrono::system_clock::now();
        auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                       now.time_since_epoch()).count();
        std::string sid = username + "_" + std::to_string(ms);
        activeSession = Session{ sid, user.username, user.role };
        db.insertAuditLog(username, user.role, "LOGIN", "SUCCESS");
        std::cout << "[AUTH] Login successful. Session: " << sid << "\n";
        return sid;
    }
    db.insertAuditLog(username, "UNKNOWN", "LOGIN", "FAILED");
    std::cout << "[AUTH] Invalid credentials.\n";
    return std::nullopt;
}

std::optional<Session> AuthSystem::getUserFromSession(const std::string& sid) {
    if (activeSession.has_value() && activeSession->sessionId == sid)
        return activeSession;
    return std::nullopt;
}

void AuthSystem::logout(const std::string& sid) {
    if (activeSession.has_value() && activeSession->sessionId == sid) {
        db.insertAuditLog(activeSession->name, activeSession->role, "LOGOUT", "SUCCESS");
        std::cout << "[AUTH] Logged out: " << activeSession->name << "\n";
        activeSession.reset();
    } else {
        std::cout << "[AUTH] No matching session to logout.\n";
    }
}

bool AuthSystem::isLoggedIn() const {
    return activeSession.has_value();
}
