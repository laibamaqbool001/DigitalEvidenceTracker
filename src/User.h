#pragma once
#include <string>

class User {
private:
    std::string name;
    std::string role;

public:
    User(const std::string& name, const std::string& role);

    std::string getName() const;
    std::string getRole() const;
    void setName(const std::string& newName);
    void setRole(const std::string& newRole);
    std::string toString() const;
};
