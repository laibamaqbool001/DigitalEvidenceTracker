#pragma once
#include "Database.h"
#include "EvidenceTracker.h"
#include <string>

class ReportGenerator {
public:
    ReportGenerator(Database& db, EvidenceTracker& tracker);

    // Court-ready case report (plain text, no extra libs)
    std::string generateCaseReport(const std::string& caseId,
                                   const std::string& investigator,
                                   const std::string& filename = "case_report.txt");

    // Full audit trail report
    std::string generateAuditReport(const std::string& filename = "audit_report.txt");

    // Full evidence inventory (all cases)
    std::string generateFullInventory(const std::string& filename = "inventory_report.txt");

private:
    Database&        db;
    EvidenceTracker& tracker;

    std::string sep(char c = '=', int len = 72);
    std::string nowStr();
    std::string formatSize(long long bytes);
};
