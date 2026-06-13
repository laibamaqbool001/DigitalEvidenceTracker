#pragma once
#include "Database.h"
#include <string>
#include <optional>

struct Session {
    std::string sessionId;
    std::string name;   // same as username
    std::string role;
};

class AuthSystem {
public:
    AuthSystem();

    void registerUser(const std::string& username,
                      const std::string& password,
                      const std::string& role);

    std::optional<std::string> login(const std::string& username,
                                     const std::string& password);

    std::optional<Session> getUserFromSession(const std::string& sessionId);

    void logout(const std::string& sessionId);

    bool isLoggedIn() const;

private:
    Database                db;
    std::optional<Session>  activeSession;
};
