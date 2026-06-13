#pragma once
#include <QMainWindow>
#include <QStackedWidget>
#include <QLineEdit>
#include <QTextEdit>
#include <QLabel>
#include <QPushButton>
#include <QFrame>
#include <QComboBox>
#include <QString>
#include "AuthSystem.h"
#include "EvidenceTracker.h"
#include "ReportGenerator.h"
#include "User.h"

class EvidenceTrackerGUI : public QMainWindow {
    Q_OBJECT

public:
    explicit EvidenceTrackerGUI(QWidget* parent = nullptr);
    ~EvidenceTrackerGUI() override = default;

private slots:
    void onLogin();
    void onGoToRegister();
    void onRegister();
    void onLogout();
    void onAddEvidence();
    void onBrowseFile();
    void onSearchByCase();
    void onSearchById();
    void onKeywordSearch();
    void onCheckIntegrity();
    void onViewCustodyLogs();
    void onViewAuditLogs();
    void onGenerateCaseReport();
    void onGenerateAuditReport();
    void onGenerateInventory();
    void onBackupDatabase();
    void toggleTheme();

private:
    // ── Systems ──────────────────────────────────────────────────
    AuthSystem      auth;
    EvidenceTracker tracker;
    ReportGenerator reporter;          // constructed in .cpp ctor
    QString         sessionId;
    std::string     currentUsername;
    std::string     currentRole;
    bool            darkMode = true;

    // ── Screens ──────────────────────────────────────────────────
    QStackedWidget* stack          = nullptr;
    QWidget*        loginScreen    = nullptr;
    QWidget*        registerScreen = nullptr;
    QWidget*        dashboard      = nullptr;

    QWidget* makeLoginScreen();
    QWidget* makeRegisterScreen();
    QWidget* makeDashboard();

    // ── Login ─────────────────────────────────────────────────────
    QLineEdit* loginUsername = nullptr;
    QLineEdit* loginPassword = nullptr;

    // ── Register ──────────────────────────────────────────────────
    QLineEdit* regUsername = nullptr;
    QLineEdit* regPassword = nullptr;
    QComboBox* regRoleBox  = nullptr;

    // ── Dashboard common ──────────────────────────────────────────
    QTextEdit* outputArea    = nullptr;
    QLabel*    statusLabel   = nullptr;
    QLabel*    userRoleLabel = nullptr;

    // ── Evidence input ────────────────────────────────────────────
    QLineEdit* caseIdField     = nullptr;
    QLineEdit* descField       = nullptr;
    QLineEdit* locField        = nullptr;
    QLineEdit* keywordsField   = nullptr;
    QLineEdit* filePathField   = nullptr;

    // ── Search / verify input ─────────────────────────────────────
    QLineEdit* searchCaseField = nullptr;
    QLineEdit* searchIdField   = nullptr;
    QLineEdit* searchKwField   = nullptr;
    QLineEdit* integrityIdField= nullptr;

    // ── Sidebar nav buttons (role-gated) ──────────────────────────
    QPushButton* btnAddEvidence  = nullptr;
    QPushButton* btnCustodyLogs  = nullptr;
    QPushButton* btnAuditLogs    = nullptr;
    QPushButton* btnCaseReport   = nullptr;
    QPushButton* btnAuditReport  = nullptr;
    QPushButton* btnInventory    = nullptr;
    QPushButton* btnRegisterUser = nullptr;
    QPushButton* btnBackup       = nullptr;

    // ── Helpers ───────────────────────────────────────────────────
    void applyRolePermissions();
    void goToDashboard();
    void setStatus(const QString& msg);
    void printToOutput(const QString& text);
    void printHeader(const QString& title);
    void printRecord(const EvidenceRecord& r);
    void showError(const QString& msg);

    QPushButton* makeNavBtn(const QString& icon, const QString& label);
    QPushButton* makeActionBtn(const QString& text, const QString& hexColor);
};
