#include "User.h"

User::User(const std::string& name, const std::string& role)
    : name(name), role(role) {}

std::string User::getName() const { return name; }
std::string User::getRole() const { return role; }
void User::setName(const std::string& n) { name = n; }
void User::setRole(const std::string& r) { role = r; }

std::string User::toString() const {
    return "User[" + name + " | " + role + "]";
}
