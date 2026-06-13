/*  EvidenceTrackerGUI.cpp
 *  Digital Forensic Evidence Tracker — Qt6 GUI
 *  All features wired to real backend (AuthSystem, EvidenceTracker, ReportGenerator)
 */
#include "EvidenceTrackerGUI.h"
#include <optional>
#include <QApplication>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGridLayout>
#include <QPushButton>
#include <QGroupBox>
#include <QMessageBox>
#include <QFileDialog>
#include <QInputDialog>
#include <QSplitter>
#include <QFrame>
#include <QFont>
#include <QFile>
#include <QScrollArea>
#include <QDateTime>
#include <QGraphicsDropShadowEffect>

#include <QStandardPaths>

// ─────────────────────────────────────────────────────────────────────────────
//  COLOUR PALETTE
// ─────────────────────────────────────────────────────────────────────────────
static const char* C_BG      = "#050A0F";
static const char* C_PANEL   = "#0A1628";
static const char* C_CARD    = "#0D1F38";
static const char* C_BORDER  = "#1A3050";
static const char* C_ACCENT  = "#00D4FF";
static const char* C_GREEN   = "#00FF9F";
static const char* C_WARN    = "#FF6B35";
static const char* C_PURPLE  = "#A78BFA";
static const char* C_TEXT    = "#C8D8E8";
static const char* C_DIM     = "#4A6080";

static const QString DARK_STYLE = R"(
* { font-family:'Consolas','Courier New',monospace; color:#C8D8E8; }
QMainWindow,QDialog { background:#050A0F; }
QWidget   { background:transparent; }
QLineEdit {
    background:#071525; border:1px solid #1A3050; border-radius:4px;
    padding:8px 12px; color:#C8D8E8; font-size:13px;
}
QLineEdit:focus { border:1px solid #00D4FF; background:#0A1D30; }
QComboBox {
    background:#071525; border:1px solid #1A3050; border-radius:4px;
    padding:8px 12px; color:#C8D8E8; font-size:13px;
}
QComboBox::drop-down { border:none; }
QComboBox QAbstractItemView { background:#0A1628; border:1px solid #1A3050; color:#C8D8E8; }
QTextEdit {
    background:#030C14; border:1px solid #1A3050; border-radius:4px;
    padding:8px; color:#00D4FF; font-size:12px;
}
QScrollBar:vertical { background:#071525; width:8px; border-radius:4px; }
QScrollBar::handle:vertical { background:#1A3050; border-radius:4px; min-height:20px; }
QScrollBar::handle:vertical:hover { background:#00D4FF; }
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical { height:0; }
QGroupBox {
    border:1px solid #1A3050; border-radius:6px; margin-top:12px;
    padding-top:8px; font-size:10px; color:#4A6080; letter-spacing:1px;
}
QGroupBox::title { subcontrol-origin:margin; left:12px; padding:0 6px; color:#00D4FF; font-size:10px; }
QLabel { background:transparent; }
QMessageBox { background:#0A1628; }
QMessageBox QLabel { color:#C8D8E8; }
QMessageBox QPushButton {
    background:#0D1F38; border:1px solid #00D4FF; border-radius:4px;
    padding:6px 20px; color:#00D4FF; min-width:80px;
}
QMessageBox QPushButton:hover { background:#00D4FF22; }
)";

// ─────────────────────────────────────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────────────────────────────────────
static QGraphicsDropShadowEffect* glow(QColor c, int r = 20) {
    auto* e = new QGraphicsDropShadowEffect;
    e->setBlurRadius(r); e->setColor(c); e->setOffset(0,0);
    return e;
}

QPushButton* EvidenceTrackerGUI::makeNavBtn(const QString& icon, const QString& label) {
    auto* b = new QPushButton(icon + "  " + label);
    b->setFixedHeight(44);
    b->setStyleSheet(R"(
        QPushButton {
            background:transparent; border:none;
            border-left:3px solid transparent; border-radius:0;
            text-align:left; padding:0 16px;
            color:#4A6080; font-size:13px;
        }
        QPushButton:hover { background:#0D1F3888; border-left:3px solid #00D4FF88; color:#C8D8E8; }
        QPushButton:pressed { background:#00D4FF15; border-left:3px solid #00D4FF; color:#00D4FF; }
        QPushButton:disabled { color:#1A2A3A; }
    )");
    return b;
}

QPushButton* EvidenceTrackerGUI::makeActionBtn(const QString& text, const QString& col) {
    auto* b = new QPushButton(text);
    b->setFixedHeight(36);
    b->setStyleSheet(QString(R"(
        QPushButton {
            background:%1 18; border:1px solid %1; border-radius:4px;
            color:%1; font-size:11px; letter-spacing:1px; padding:0 12px;
        }
        QPushButton:hover { background:%1 35; color:white; }
        QPushButton:pressed { background:%1 55; }
        QPushButton:disabled { border-color:#1A3050; color:#2A4060; background:transparent; }
    )").replace("%1", col));
    return b;
}

void EvidenceTrackerGUI::setStatus(const QString& msg) {
    if (statusLabel) statusLabel->setText(msg);
}

void EvidenceTrackerGUI::printToOutput(const QString& text) {
    if (outputArea) outputArea->append(text);
}

void EvidenceTrackerGUI::printHeader(const QString& title) {
    printToOutput("\n<span style='color:#00D4FF;font-weight:bold;'>"
                  "══════════════════════════════════════<br>"
                  "  " + title + "<br>"
                  "══════════════════════════════════════</span>");
}

void EvidenceTrackerGUI::printRecord(const EvidenceRecord& r) {
    QString integrity = QString::fromStdString(r.integrityStatus);
    QString iColor    = (integrity == "OK") ? C_GREEN :
                        (integrity == "TAMPERED") ? C_WARN : C_DIM;

    printToOutput(QString(
        "<span style='color:%9;'>  ─────────────────────────────────────</span><br>"
        "  <b>Evidence ID :</b> EV-%1<br>"
        "  <b>Case ID     :</b> %2<br>"
        "  <b>Description :</b> %3<br>"
        "  <b>Location    :</b> %4<br>"
        "  <b>Keywords    :</b> %5<br>"
        "  <b>Added By    :</b> %6  @  %7<br>"
        "  <b>File        :</b> %8<br>"
        "  <b>SHA-256     :</b> <span style='color:%9;font-size:10px;'>%10</span><br>"
        "  <b>Integrity   :</b> <span style='color:%11;'>%12</span><br>")
        .arg(r.id)
        .arg(QString::fromStdString(r.caseId))
        .arg(QString::fromStdString(r.description))
        .arg(QString::fromStdString(r.location))
        .arg(r.keywords.empty() ? "—" : QString::fromStdString(r.keywords))
        .arg(QString::fromStdString(r.addedBy))
        .arg(QString::fromStdString(r.timestamp))
        .arg(r.filePath.empty() ? "—" : QString::fromStdString(r.filePath)
             + "  (" + QString::fromStdString(r.mimeType) + "  "
             + QString::number(r.fileSize/1024) + " KB)")
        .arg(C_DIM)
        .arg(r.fileHash.empty() ? "—" : QString::fromStdString(r.fileHash))
        .arg(iColor)
        .arg(integrity.isEmpty() ? "—" : integrity)
    );
}

void EvidenceTrackerGUI::showError(const QString& msg) {
    printToOutput("<span style='color:" + QString(C_WARN) + ";'>  ✖  " + msg + "</span>");
    setStatus("● ERROR");
}

void EvidenceTrackerGUI::goToDashboard() {
    if (stack && dashboard) stack->setCurrentWidget(dashboard);
}

// ─────────────────────────────────────────────────────────────────────────────
//  CONSTRUCTOR
// ─────────────────────────────────────────────────────────────────────────────
EvidenceTrackerGUI::EvidenceTrackerGUI(QWidget* parent)
    : QMainWindow(parent),
      reporter(tracker.getDb(), tracker)   // initialise reporter after tracker
{
    setWindowTitle("DET — Digital Evidence Tracker  v3.0");
    setMinimumSize(1140, 760);
    resize(1300, 840);
    qApp->setStyleSheet(DARK_STYLE);

    stack          = new QStackedWidget(this);
    loginScreen    = makeLoginScreen();
    registerScreen = makeRegisterScreen();
    dashboard      = makeDashboard();
    stack->addWidget(loginScreen);
    stack->addWidget(registerScreen);
    stack->addWidget(dashboard);
    stack->setCurrentWidget(loginScreen);
    setCentralWidget(stack);
}

// ─────────────────────────────────────────────────────────────────────────────
//  LOGIN SCREEN
// ─────────────────────────────────────────────────────────────────────────────
QWidget* EvidenceTrackerGUI::makeLoginScreen() {
    QWidget* w = new QWidget;
    w->setStyleSheet(QString("QWidget { background:%1; "
        "background-image: repeating-linear-gradient(0deg,transparent,transparent 39px,#0A1628 39px,#0A1628 40px),"
        "repeating-linear-gradient(90deg,transparent,transparent 39px,#0A1628 39px,#0A1628 40px); }").arg(C_BG));

    auto* outer = new QVBoxLayout(w);
    outer->setAlignment(Qt::AlignCenter);

    QFrame* card = new QFrame;
    card->setFixedSize(430, 560);
    card->setStyleSheet(QString("QFrame{background:%1;border:1px solid %2;border-radius:8px;}").arg(C_PANEL).arg(C_BORDER));
    card->setGraphicsEffect(glow(QColor(0,212,255,80), 40));

    auto* cl = new QVBoxLayout(card);
    cl->setContentsMargins(44, 38, 44, 38);
    cl->setSpacing(0);

    auto* badge = new QLabel("◈  D.E.T.");
    badge->setAlignment(Qt::AlignCenter);
    badge->setStyleSheet(QString("color:%1;font-size:28px;font-weight:bold;letter-spacing:8px;").arg(C_ACCENT));
    badge->setGraphicsEffect(glow(QColor(0,212,255), 24));
    cl->addWidget(badge);

    auto* sub = new QLabel("DIGITAL EVIDENCE TRACKER");
    sub->setAlignment(Qt::AlignCenter);
    sub->setStyleSheet(QString("color:%1;font-size:9px;letter-spacing:4px;margin-bottom:4px;").arg(C_DIM));
    cl->addWidget(sub);

    auto* div = new QFrame; div->setFixedHeight(1);
    div->setStyleSheet(QString("background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "stop:0 transparent,stop:0.5 %1,stop:1 transparent);margin:20px 0;").arg(C_ACCENT));
    cl->addWidget(div);
    cl->addSpacing(12);

    auto addField = [&](const QString& lbl, QLineEdit*& field, bool pw = false) {
        auto* l = new QLabel(lbl);
        l->setStyleSheet(QString("color:%1;font-size:9px;letter-spacing:2px;margin-bottom:3px;").arg(C_DIM));
        cl->addWidget(l);
        field = new QLineEdit; field->setFixedHeight(42);
        if (pw) field->setEchoMode(QLineEdit::Password);
        cl->addWidget(field);
        cl->addSpacing(14);
    };
    addField("OPERATOR ID",  loginUsername);
    addField("ACCESS CODE",  loginPassword, true);
    cl->addSpacing(10);

    auto* loginBtn = new QPushButton("AUTHENTICATE");
    loginBtn->setFixedHeight(48);
    loginBtn->setStyleSheet(QString(R"(
        QPushButton{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #003A55,stop:1 #001A2E);
            border:1px solid %1;border-radius:5px;color:%1;font-size:14px;letter-spacing:3px;font-weight:bold;}
        QPushButton:hover{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #005577,stop:1 #002A44);color:white;}
    )").arg(C_ACCENT));
    loginBtn->setGraphicsEffect(glow(QColor(0,212,255,100), 14));
    connect(loginBtn, &QPushButton::clicked, this, &EvidenceTrackerGUI::onLogin);
    cl->addWidget(loginBtn);
    cl->addSpacing(14);

    auto* regLink = new QPushButton("▸  New operator? Request access");
    regLink->setStyleSheet(QString("QPushButton{background:transparent;border:none;color:%1;"
        "font-size:11px;}QPushButton:hover{color:white;}").arg(C_DIM));
    connect(regLink, &QPushButton::clicked, this, &EvidenceTrackerGUI::onGoToRegister);
    cl->addWidget(regLink, 0, Qt::AlignCenter);
    cl->addStretch();

    auto* ts = new QLabel("SYSTEM  " + QDateTime::currentDateTimeUtc().toString("yyyy-MM-dd  HH:mm") + "  UTC");
    ts->setAlignment(Qt::AlignCenter);
    ts->setStyleSheet(QString("color:%1;font-size:9px;letter-spacing:1px;").arg(C_DIM));
    cl->addWidget(ts);

    outer->addWidget(card);
    return w;
}

// ─────────────────────────────────────────────────────────────────────────────
//  REGISTER SCREEN
// ─────────────────────────────────────────────────────────────────────────────
QWidget* EvidenceTrackerGUI::makeRegisterScreen() {
    QWidget* w = new QWidget;
    w->setStyleSheet(QString("QWidget{background:%1;}").arg(C_BG));

    auto* outer = new QVBoxLayout(w);
    outer->setAlignment(Qt::AlignCenter);

    QFrame* card = new QFrame;
    card->setFixedSize(450, 520);
    card->setStyleSheet(QString("QFrame{background:%1;border:1px solid #FF6B3555;border-radius:8px;}").arg(C_PANEL));
    card->setGraphicsEffect(glow(QColor(255,107,53,80), 35));

    auto* cl = new QVBoxLayout(card);
    cl->setContentsMargins(44, 36, 44, 36);
    cl->setSpacing(0);

    auto* badge = new QLabel("◈  ACCESS REQUEST");
    badge->setAlignment(Qt::AlignCenter);
    badge->setStyleSheet(QString("color:%1;font-size:18px;font-weight:bold;letter-spacing:4px;").arg(C_WARN));
    badge->setGraphicsEffect(glow(QColor(255,107,53), 18));
    cl->addWidget(badge);

    auto* sub = new QLabel("NEW OPERATOR REGISTRATION");
    sub->setAlignment(Qt::AlignCenter);
    sub->setStyleSheet(QString("color:%1;font-size:9px;letter-spacing:3px;margin-bottom:4px;").arg(C_DIM));
    cl->addWidget(sub);

    auto* div = new QFrame; div->setFixedHeight(1);
    div->setStyleSheet(QString("background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "stop:0 transparent,stop:0.5 %1,stop:1 transparent);margin:18px 0;").arg(C_WARN));
    cl->addWidget(div);
    cl->addSpacing(8);

    auto addField = [&](const QString& lbl, QLineEdit*& field, bool pw = false) {
        auto* l = new QLabel(lbl);
        l->setStyleSheet(QString("color:%1;font-size:9px;letter-spacing:2px;margin-bottom:3px;").arg(C_DIM));
        cl->addWidget(l);
        field = new QLineEdit; field->setFixedHeight(40);
        if (pw) field->setEchoMode(QLineEdit::Password);
        cl->addWidget(field);
        cl->addSpacing(12);
    };
    addField("OPERATOR ID",  regUsername);
    addField("ACCESS CODE",  regPassword, true);

    auto* roleLbl = new QLabel("ASSIGNED ROLE");
    roleLbl->setStyleSheet(QString("color:%1;font-size:9px;letter-spacing:2px;margin-bottom:3px;").arg(C_DIM));
    cl->addWidget(roleLbl);
    regRoleBox = new QComboBox; regRoleBox->setFixedHeight(40);
    regRoleBox->addItems({"Investigator", "Officer", "Admin"});
    cl->addWidget(regRoleBox);
    cl->addSpacing(20);

    auto* regBtn = new QPushButton("SUBMIT REGISTRATION");
    regBtn->setFixedHeight(46);
    regBtn->setStyleSheet(QString(R"(
        QPushButton{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #3A1500,stop:1 #1E0800);
            border:1px solid %1;border-radius:5px;color:%1;font-size:13px;letter-spacing:3px;font-weight:bold;}
        QPushButton:hover{color:white;background:#552200;}
    )").arg(C_WARN));
    regBtn->setGraphicsEffect(glow(QColor(255,107,53,100), 14));
    connect(regBtn, &QPushButton::clicked, this, &EvidenceTrackerGUI::onRegister);
    cl->addWidget(regBtn);
    cl->addSpacing(12);

    auto* backBtn = new QPushButton("◂  Back to Authentication");
    backBtn->setStyleSheet(QString("QPushButton{background:transparent;border:none;color:%1;"
        "font-size:11px;}QPushButton:hover{color:white;}").arg(C_DIM));
    connect(backBtn, &QPushButton::clicked, this, &EvidenceTrackerGUI::onLogout);
    cl->addWidget(backBtn, 0, Qt::AlignCenter);
    cl->addStretch();

    outer->addWidget(card);
    return w;
}

// ─────────────────────────────────────────────────────────────────────────────
//  DASHBOARD
// ─────────────────────────────────────────────────────────────────────────────
QWidget* EvidenceTrackerGUI::makeDashboard() {
    QWidget* w = new QWidget;
    w->setStyleSheet(QString("QWidget{background:%1;}").arg(C_BG));

    auto* root = new QHBoxLayout(w);
    root->setContentsMargins(0,0,0,0);
    root->setSpacing(0);

    // ── SIDEBAR ──────────────────────────────────────────────────
    auto* side = new QFrame;
    side->setFixedWidth(230);
    side->setStyleSheet(QString("QFrame{background:%1;border-right:1px solid %2;}").arg(C_PANEL).arg(C_BORDER));

    auto* sideL = new QVBoxLayout(side);
    sideL->setContentsMargins(0,0,0,0);
    sideL->setSpacing(0);

    // Sidebar header
    auto* sideHdr = new QFrame; sideHdr->setFixedHeight(78);
    sideHdr->setStyleSheet(QString("QFrame{background:%1;border-bottom:1px solid %2;}").arg(C_CARD).arg(C_BORDER));
    auto* shL = new QVBoxLayout(sideHdr); shL->setAlignment(Qt::AlignCenter);

    auto* sTitle = new QLabel("◈  D.E.T.");
    sTitle->setAlignment(Qt::AlignCenter);
    sTitle->setStyleSheet(QString("color:%1;font-size:18px;font-weight:bold;letter-spacing:6px;background:transparent;").arg(C_ACCENT));
    sTitle->setGraphicsEffect(glow(QColor(0,212,255), 14));
    shL->addWidget(sTitle);

    userRoleLabel = new QLabel("ROLE: —");
    userRoleLabel->setAlignment(Qt::AlignCenter);
    userRoleLabel->setStyleSheet(QString("color:%1;font-size:9px;letter-spacing:2px;background:transparent;").arg(C_DIM));
    shL->addWidget(userRoleLabel);
    sideL->addWidget(sideHdr);
    sideL->addSpacing(12);

    auto addSection = [&](const QString& txt) {
        auto* l = new QLabel(txt);
        l->setStyleSheet(QString("color:%1;font-size:8px;letter-spacing:3px;padding:6px 16px 2px;background:transparent;").arg(C_DIM));
        sideL->addWidget(l);
    };

    addSection("EVIDENCE");
    btnAddEvidence = makeNavBtn("⊕","Add Evidence");
    connect(btnAddEvidence, &QPushButton::clicked, this, &EvidenceTrackerGUI::onAddEvidence);
    sideL->addWidget(btnAddEvidence);

    auto* btnSrchCase = makeNavBtn("⌕","Search by Case ID");
    connect(btnSrchCase, &QPushButton::clicked, this, &EvidenceTrackerGUI::onSearchByCase);
    sideL->addWidget(btnSrchCase);

    auto* btnSrchId = makeNavBtn("⌕","Search by Evidence ID");
    connect(btnSrchId, &QPushButton::clicked, this, &EvidenceTrackerGUI::onSearchById);
    sideL->addWidget(btnSrchId);

    auto* btnKw = makeNavBtn("⌖","Keyword Search");
    connect(btnKw, &QPushButton::clicked, this, &EvidenceTrackerGUI::onKeywordSearch);
    sideL->addWidget(btnKw);

    auto* btnIntegrity = makeNavBtn("⛨","Verify Integrity");
    connect(btnIntegrity, &QPushButton::clicked, this, &EvidenceTrackerGUI::onCheckIntegrity);
    sideL->addWidget(btnIntegrity);

    sideL->addSpacing(6);
    addSection("AUDIT & CUSTODY");
    btnCustodyLogs = makeNavBtn("⛓","Custody Logs");
    connect(btnCustodyLogs, &QPushButton::clicked, this, &EvidenceTrackerGUI::onViewCustodyLogs);
    sideL->addWidget(btnCustodyLogs);

    btnAuditLogs = makeNavBtn("◎","Audit Trail");
    connect(btnAuditLogs, &QPushButton::clicked, this, &EvidenceTrackerGUI::onViewAuditLogs);
    sideL->addWidget(btnAuditLogs);

    sideL->addSpacing(6);
    addSection("REPORTS");
    btnCaseReport = makeNavBtn("▤","Case Report");
    connect(btnCaseReport, &QPushButton::clicked, this, &EvidenceTrackerGUI::onGenerateCaseReport);
    sideL->addWidget(btnCaseReport);

    btnAuditReport = makeNavBtn("▦","Audit Report");
    connect(btnAuditReport, &QPushButton::clicked, this, &EvidenceTrackerGUI::onGenerateAuditReport);
    sideL->addWidget(btnAuditReport);

    btnInventory = makeNavBtn("≡","Full Inventory");
    connect(btnInventory, &QPushButton::clicked, this, &EvidenceTrackerGUI::onGenerateInventory);
    sideL->addWidget(btnInventory);

    sideL->addSpacing(6);
    addSection("ADMIN");
    btnRegisterUser = makeNavBtn("⊞","Register Operator");
    connect(btnRegisterUser, &QPushButton::clicked, this, &EvidenceTrackerGUI::onGoToRegister);
    sideL->addWidget(btnRegisterUser);

    btnBackup = makeNavBtn("⊡","Backup Database");
    connect(btnBackup, &QPushButton::clicked, this, &EvidenceTrackerGUI::onBackupDatabase);
    sideL->addWidget(btnBackup);

    sideL->addStretch();

    // Footer
    auto* sideFooter = new QFrame; sideFooter->setFixedHeight(52);
    sideFooter->setStyleSheet(QString("QFrame{background:transparent;border-top:1px solid %1;}").arg(C_BORDER));
    auto* sfL = new QHBoxLayout(sideFooter); sfL->setContentsMargins(8,0,8,0); sfL->setSpacing(6);

    auto* themeBtn = new QPushButton("◑ Theme");
    themeBtn->setFixedHeight(30);
    themeBtn->setStyleSheet(QString("QPushButton{background:transparent;border:1px solid #1A3050;"
        "border-radius:4px;color:#4A6080;font-size:10px;padding:0 8px;}"
        "QPushButton:hover{border-color:%1;color:%1;}").arg(C_ACCENT));
    connect(themeBtn, &QPushButton::clicked, this, &EvidenceTrackerGUI::toggleTheme);
    sfL->addWidget(themeBtn);

    auto* logoutBtn = new QPushButton("⏏ Logout");
    logoutBtn->setFixedHeight(30);
    logoutBtn->setStyleSheet(QString("QPushButton{background:transparent;border:1px solid #FF6B3566;"
        "border-radius:4px;color:%1;font-size:10px;padding:0 8px;}"
        "QPushButton:hover{border-color:%1;color:white;background:#FF6B3522;}").arg(C_WARN));
    connect(logoutBtn, &QPushButton::clicked, this, &EvidenceTrackerGUI::onLogout);
    sfL->addWidget(logoutBtn);
    sideL->addWidget(sideFooter);

    root->addWidget(side);

    // ── CONTENT AREA ─────────────────────────────────────────────
    auto* content = new QFrame;
    content->setStyleSheet("QFrame{background:transparent;}");
    auto* contentL = new QVBoxLayout(content);
    contentL->setContentsMargins(0,0,0,0);
    contentL->setSpacing(0);

    // Top bar
    auto* topBar = new QFrame; topBar->setFixedHeight(54);
    topBar->setStyleSheet(QString("QFrame{background:%1;border-bottom:1px solid %2;}").arg(C_PANEL).arg(C_BORDER));
    auto* topL = new QHBoxLayout(topBar); topL->setContentsMargins(20,0,20,0);

    auto* pageTitle = new QLabel("FORENSIC COMMAND CENTRE");
    pageTitle->setStyleSheet("color:white;font-size:13px;font-weight:bold;letter-spacing:3px;background:transparent;");
    topL->addWidget(pageTitle);
    topL->addStretch();

    statusLabel = new QLabel("● SYSTEM READY");
    statusLabel->setStyleSheet(QString("color:%1;font-size:11px;letter-spacing:1px;background:transparent;").arg(C_GREEN));
    topL->addWidget(statusLabel);
    contentL->addWidget(topBar);

    // Scrollable inner
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setStyleSheet("QScrollArea{background:transparent;border:none;}");

    auto* inner = new QWidget;
    inner->setStyleSheet("QWidget{background:transparent;}");
    auto* innerL = new QVBoxLayout(inner);
    innerL->setContentsMargins(20,20,20,20);
    innerL->setSpacing(16);

    // ── Card: Add Evidence ─────────────────────────────────────
    auto* addCard = new QGroupBox("ADD EVIDENCE");
    auto* addGrid = new QGridLayout(addCard);
    addGrid->setSpacing(10);

    auto addLabel = [](const QString& t) -> QLabel* {
        auto* l = new QLabel(t);
        l->setStyleSheet("color:#4A6080;font-size:9px;letter-spacing:2px;background:transparent;");
        return l;
    };

    addGrid->addWidget(addLabel("CASE ID"),       0, 0);
    caseIdField = new QLineEdit; caseIdField->setFixedHeight(36); caseIdField->setPlaceholderText("e.g. CASE-2025-001");
    addGrid->addWidget(caseIdField,               1, 0);

    addGrid->addWidget(addLabel("DESCRIPTION"),   0, 1);
    descField = new QLineEdit; descField->setFixedHeight(36); descField->setPlaceholderText("Brief description...");
    addGrid->addWidget(descField,                 1, 1);

    addGrid->addWidget(addLabel("LOCATION / SOURCE"), 0, 2);
    locField = new QLineEdit; locField->setFixedHeight(36); locField->setPlaceholderText("e.g. Crime scene desk, Seized phone");
    addGrid->addWidget(locField,                  1, 2);

    addGrid->addWidget(addLabel("KEYWORDS"),      2, 0);
    keywordsField = new QLineEdit; keywordsField->setFixedHeight(36); keywordsField->setPlaceholderText("e.g. malware usb encrypted");
    addGrid->addWidget(keywordsField,             3, 0);

    addGrid->addWidget(addLabel("FILE / IMAGE (optional)"), 2, 1, 1, 2);
    auto* fileRow = new QHBoxLayout;
    filePathField = new QLineEdit; filePathField->setFixedHeight(36); filePathField->setPlaceholderText("Browse or drag a file...");
    auto* browseBtn = makeActionBtn("BROWSE", C_ACCENT);
    connect(browseBtn, &QPushButton::clicked, this, &EvidenceTrackerGUI::onBrowseFile);
    fileRow->addWidget(filePathField);
    fileRow->addWidget(browseBtn);
    auto* fileW = new QWidget; fileW->setLayout(fileRow);
    addGrid->addWidget(fileW,                     3, 1, 1, 2);

    auto* addEvidenceBtn = makeActionBtn("⊕  SUBMIT EVIDENCE", C_GREEN);
    addEvidenceBtn->setFixedHeight(40);
    connect(addEvidenceBtn, &QPushButton::clicked, this, &EvidenceTrackerGUI::onAddEvidence);
    addGrid->addWidget(addEvidenceBtn,            4, 0, 1, 3);

    innerL->addWidget(addCard);

    // ── Card: Search & Integrity ────────────────────────────────
    auto* srchCard = new QGroupBox("SEARCH  &  INTEGRITY CHECK");
    auto* srchGrid = new QGridLayout(srchCard);
    srchGrid->setSpacing(10);

    srchGrid->addWidget(addLabel("SEARCH BY CASE ID"), 0, 0);
    searchCaseField = new QLineEdit; searchCaseField->setFixedHeight(34); searchCaseField->setPlaceholderText("Case ID...");
    srchGrid->addWidget(searchCaseField, 1, 0);
    auto* btnSC = makeActionBtn("SEARCH", C_ACCENT);
    connect(btnSC, &QPushButton::clicked, this, &EvidenceTrackerGUI::onSearchByCase);
    srchGrid->addWidget(btnSC, 1, 1);

    srchGrid->addWidget(addLabel("SEARCH BY EVIDENCE ID"), 0, 2);
    searchIdField = new QLineEdit; searchIdField->setFixedHeight(34); searchIdField->setPlaceholderText("Evidence ID number...");
    srchGrid->addWidget(searchIdField, 1, 2);
    auto* btnSI = makeActionBtn("SEARCH", C_ACCENT);
    connect(btnSI, &QPushButton::clicked, this, &EvidenceTrackerGUI::onSearchById);
    srchGrid->addWidget(btnSI, 1, 3);

    srchGrid->addWidget(addLabel("KEYWORD SEARCH"), 2, 0);
    searchKwField = new QLineEdit; searchKwField->setFixedHeight(34); searchKwField->setPlaceholderText("Keyword...");
    srchGrid->addWidget(searchKwField, 3, 0);
    auto* btnKwS = makeActionBtn("SEARCH", C_PURPLE);
    connect(btnKwS, &QPushButton::clicked, this, &EvidenceTrackerGUI::onKeywordSearch);
    srchGrid->addWidget(btnKwS, 3, 1);

    srchGrid->addWidget(addLabel("VERIFY FILE INTEGRITY  (Evidence ID)"), 2, 2);
    integrityIdField = new QLineEdit; integrityIdField->setFixedHeight(34); integrityIdField->setPlaceholderText("Evidence ID...");
    srchGrid->addWidget(integrityIdField, 3, 2);
    auto* btnVI = makeActionBtn("VERIFY", C_WARN);
    connect(btnVI, &QPushButton::clicked, this, &EvidenceTrackerGUI::onCheckIntegrity);
    srchGrid->addWidget(btnVI, 3, 3);

    innerL->addWidget(srchCard);

    // ── Terminal output ────────────────────────────────────────
    auto* outCard = new QFrame;
    outCard->setStyleSheet(QString("QFrame{background:#030C14;border:1px solid %1;border-radius:6px;}").arg(C_BORDER));
    auto* outL = new QVBoxLayout(outCard); outL->setContentsMargins(0,0,0,0);

    auto* termHdr = new QFrame; termHdr->setFixedHeight(34);
    termHdr->setStyleSheet(QString("QFrame{background:%1;border-radius:6px 6px 0 0;border-bottom:1px solid %2;}").arg(C_CARD).arg(C_BORDER));
    auto* thL = new QHBoxLayout(termHdr); thL->setContentsMargins(14,0,14,0);
    auto* dots = new QLabel("●  ●  ●"); dots->setStyleSheet("color:#1A3050;font-size:10px;background:transparent;");
    thL->addWidget(dots); thL->addStretch();
    auto* tLbl = new QLabel("FORENSIC OUTPUT TERMINAL");
    tLbl->setStyleSheet(QString("color:%1;font-size:9px;letter-spacing:3px;background:transparent;").arg(C_DIM));
    thL->addWidget(tLbl);
    outL->addWidget(termHdr);

    outputArea = new QTextEdit;
    outputArea->setReadOnly(true);
    outputArea->setAcceptRichText(true);
    outputArea->setMinimumHeight(280);
    outputArea->setStyleSheet("QTextEdit{background:#030C14;border:none;border-radius:0 0 6px 6px;"
                              "color:#00D4FF;font-size:12px;padding:12px;}");
    outL->addWidget(outputArea);
    innerL->addWidget(outCard);

    scroll->setWidget(inner);
    contentL->addWidget(scroll);
    root->addWidget(content);
    return w;
}

// ─────────────────────────────────────────────────────────────────────────────
//  ROLE PERMISSIONS
// ─────────────────────────────────────────────────────────────────────────────
void EvidenceTrackerGUI::applyRolePermissions() {
    bool isAdmin = (currentRole == "Admin");
    bool isInv   = (currentRole == "Investigator");
    // bool isOff   = (currentRole == "Officer"); // all remaining: enabled for all

    btnAddEvidence ->setEnabled(isAdmin || isInv);
    btnCustodyLogs ->setEnabled(true);
    btnAuditLogs   ->setEnabled(isAdmin);
    btnCaseReport  ->setEnabled(isAdmin || isInv);
    btnAuditReport ->setEnabled(isAdmin);
    btnInventory   ->setEnabled(isAdmin || isInv);
    btnRegisterUser->setEnabled(isAdmin);
    btnBackup      ->setEnabled(isAdmin);

    QString roleColor = isAdmin ? C_WARN : (isInv ? C_GREEN : C_ACCENT);
    userRoleLabel->setStyleSheet(QString("color:%1;font-size:10px;font-weight:bold;"
                                         "letter-spacing:2px;background:transparent;").arg(roleColor));
    userRoleLabel->setText(QString("◈  %1").arg(QString::fromStdString(currentRole).toUpper()));
}

// ─────────────────────────────────────────────────────────────────────────────
//  AUTH SLOTS
// ─────────────────────────────────────────────────────────────────────────────
void EvidenceTrackerGUI::onLogin() {
    QString user = loginUsername->text().trimmed();
    QString pass = loginPassword->text();
    if (user.isEmpty() || pass.isEmpty()) {
        QMessageBox::warning(this, "Missing Fields", "Operator ID and Access Code are required.");
        return;
    }
    try {
        std::optional<std::string> result = auth.login(user.toStdString(), pass.toStdString());
        if (result.has_value()) {
            sessionId       = QString::fromStdString(result.value());
            auto session    = auth.getUserFromSession(result.value());
            if (session.has_value()) {
                currentUsername = session->name;
                currentRole     = session->role;
            } else {
                currentUsername = user.toStdString();
                currentRole     = "Officer";
            }
            applyRolePermissions();
            setStatus(QString("● %1  |  %2")
                .arg(QString::fromStdString(currentRole).toUpper())
                .arg(QString::fromStdString(currentUsername).toUpper()));
            printHeader("SESSION STARTED");
            printToOutput(QString("  Operator  : %1<br>  Role      : %2<br>  Session   : %3<br>  Time      : %4")
                .arg(QString::fromStdString(currentUsername))
                .arg(QString::fromStdString(currentRole))
                .arg(sessionId)
                .arg(QDateTime::currentDateTimeUtc().toString("yyyy-MM-dd HH:mm:ss UTC")));
            goToDashboard();
            loginUsername->clear();
            loginPassword->clear();
        } else {
            QMessageBox::critical(this, "Access Denied", "Invalid credentials.");
        }
    } catch (const std::exception& ex) {
        QMessageBox::critical(this, "System Error", QString::fromStdString(ex.what()));
    }
}

void EvidenceTrackerGUI::onGoToRegister() {
    stack->setCurrentWidget(registerScreen);
}

void EvidenceTrackerGUI::onRegister() {
    QString user = regUsername->text().trimmed();
    QString pass = regPassword->text();
    QString role = regRoleBox->currentText();
    if (user.isEmpty() || pass.isEmpty()) {
        QMessageBox::warning(this, "Missing Fields", "All fields are required.");
        return;
    }
    try {
        auth.registerUser(user.toStdString(), pass.toStdString(), role.toStdString());
        QMessageBox::information(this, "Registered",
            QString("Operator '%1' registered as '%2'.").arg(user).arg(role));
        regUsername->clear(); regPassword->clear();
        stack->setCurrentWidget(loginScreen);
    } catch (const std::exception& ex) {
        QMessageBox::critical(this, "Registration Failed", QString::fromStdString(ex.what()));
    }
}

void EvidenceTrackerGUI::onLogout() {
    if (!sessionId.isEmpty()) {
        try { auth.logout(sessionId.toStdString()); } catch (...) {}
    }
    sessionId.clear();
    currentUsername.clear();
    currentRole.clear();
    if (outputArea) outputArea->clear();
    setStatus("● SYSTEM READY");
    stack->setCurrentWidget(loginScreen);
}

// ─────────────────────────────────────────────────────────────────────────────
//  EVIDENCE SLOTS
// ─────────────────────────────────────────────────────────────────────────────
void EvidenceTrackerGUI::onBrowseFile() {
    QString path = QFileDialog::getOpenFileName(this, "Select Evidence File", "",
        "All Files (*);;Images (*.jpg *.jpeg *.png *.bmp *.gif);;PDF (*.pdf);;Video (*.mp4 *.avi *.mov)");
    if (!path.isEmpty()) filePathField->setText(path);
}

void EvidenceTrackerGUI::onAddEvidence() {
    if (currentRole != "Admin" && currentRole != "Investigator") {
        showError("Access denied — Investigator or Admin role required.");
        return;
    }
    QString caseId  = caseIdField->text().trimmed();
    QString desc    = descField->text().trimmed();
    QString loc     = locField->text().trimmed();
    QString kw      = keywordsField->text().trimmed();
    QString filePath= filePathField->text().trimmed();

    if (caseId.isEmpty() || desc.isEmpty()) {
        showError("Case ID and Description are required.");
        return;
    }
    try {
        User u(currentUsername, currentRole);
        tracker.addEvidence(caseId.toStdString(), desc.toStdString(),
                            loc.toStdString(), kw.toStdString(),
                            filePath.toStdString(), u);

        // Get last inserted record
        auto recs = tracker.getDb().searchEvidenceByCase(caseId.toStdString());

        printHeader("EVIDENCE ADDED");
        if (!recs.empty()) printRecord(recs.back());

        if (!filePath.isEmpty()) {
            std::string fakeReason;
            bool isFake = tracker.basicFakeImageCheck(filePath.toStdString(), fakeReason);
            if (isFake) {
                printToOutput(QString("<span style='color:%1;'>"
                    "  ⚠  FAKE IMAGE ALERT: %2</span>").arg(C_WARN)
                    .arg(QString::fromStdString(fakeReason)));
            } else if (filePath.toLower().endsWith(".jpg") || filePath.toLower().endsWith(".jpeg")
                    || filePath.toLower().endsWith(".png") || filePath.toLower().endsWith(".bmp")) {
                printToOutput(QString("<span style='color:%1;'>  ✔  Image integrity check passed — no anomalies detected.</span>").arg(C_GREEN));
            }
        }

        setStatus("● Evidence added successfully");
        caseIdField->clear(); descField->clear(); locField->clear();
        keywordsField->clear(); filePathField->clear();
    } catch (const std::exception& ex) {
        showError(QString::fromStdString(ex.what()));
    }
}

void EvidenceTrackerGUI::onSearchByCase() {
    QString caseId = searchCaseField->text().trimmed();
    if (caseId.isEmpty()) caseId = caseIdField->text().trimmed();
    if (caseId.isEmpty()) { showError("Enter a Case ID."); return; }
    try {
        User u(currentUsername, currentRole);
        auto results = tracker.searchByCase(caseId.toStdString(), u);
        printHeader(QString("SEARCH RESULTS — Case: %1  (%2 records)").arg(caseId).arg(results.size()));
        if (results.empty()) {
            printToOutput("  No records found for this Case ID.");
        } else {
            for (auto& r : results) printRecord(r);
        }
        setStatus(QString("● Found %1 records").arg(results.size()));
    } catch (const std::exception& ex) { showError(QString::fromStdString(ex.what())); }
}

void EvidenceTrackerGUI::onSearchById() {
    QString idStr = searchIdField->text().trimmed();
    if (idStr.isEmpty()) { showError("Enter an Evidence ID."); return; }
    bool ok; int id = idStr.toInt(&ok);
    if (!ok) { showError("Evidence ID must be a number."); return; }
    try {
        User u(currentUsername, currentRole);
        auto r = tracker.searchById(id, u);
        printHeader(QString("EVIDENCE RECORD — EV-%1").arg(id));
        if (r.id == 0) { printToOutput("  No record found with that ID."); }
        else           { printRecord(r); }
        setStatus(r.id ? "● Record found" : "● Not found");
    } catch (const std::exception& ex) { showError(QString::fromStdString(ex.what())); }
}

void EvidenceTrackerGUI::onKeywordSearch() {
    QString kw = searchKwField->text().trimmed();
    if (kw.isEmpty()) { showError("Enter a keyword."); return; }
    try {
        User u(currentUsername, currentRole);
        auto results = tracker.searchByKeyword(kw.toStdString(), u);
        printHeader(QString("KEYWORD SEARCH — \"%1\"  (%2 results)").arg(kw).arg(results.size()));
        if (results.empty()) { printToOutput("  No matching records."); }
        else { for (auto& r : results) printRecord(r); }
        setStatus(QString("● %1 results for \"%2\"").arg(results.size()).arg(kw));
    } catch (const std::exception& ex) { showError(QString::fromStdString(ex.what())); }
}

void EvidenceTrackerGUI::onCheckIntegrity() {
    QString idStr = integrityIdField->text().trimmed();
    if (idStr.isEmpty()) { showError("Enter an Evidence ID to verify."); return; }
    bool ok; int id = idStr.toInt(&ok);
    if (!ok) { showError("Evidence ID must be a number."); return; }
    try {
        std::string status = tracker.checkIntegrity(id);
        printHeader(QString("INTEGRITY CHECK — EV-%1").arg(id));
        if (status == "OK") {
            printToOutput(QString("<span style='color:%1;'>"
                "  ✔  File hash verified — evidence is INTACT.</span>").arg(C_GREEN));
        } else if (status == "TAMPERED") {
            printToOutput(QString("<span style='color:%1;'>"
                "  ✖  TAMPER DETECTED — SHA-256 mismatch! Do NOT admit without review.</span>").arg(C_WARN));
        } else if (status == "NO_FILE") {
            printToOutput("  No file attached to this evidence record.");
        } else if (status == "NO_HASH") {
            printToOutput("  No original hash stored — cannot verify integrity.");
        } else {
            printToOutput("  Evidence ID not found.");
        }
        setStatus(QString("● Integrity: %1").arg(QString::fromStdString(status)));
    } catch (const std::exception& ex) { showError(QString::fromStdString(ex.what())); }
}

// ─────────────────────────────────────────────────────────────────────────────
//  LOG SLOTS
// ─────────────────────────────────────────────────────────────────────────────
void EvidenceTrackerGUI::onViewCustodyLogs() {
    try {
        User u(currentUsername, currentRole);
        auto logs = tracker.viewCustodyLogs(u);
        printHeader(QString("CHAIN OF CUSTODY  (%1 entries)").arg(logs.size()));
        if (logs.empty()) { printToOutput("  No custody log entries."); return; }
        for (auto& l : logs) {
            QString sigCol = (l.sigStatus == "VALID") ? C_GREEN : C_WARN;
            printToOutput(QString(
                "  <span style='color:%6;'>CL-%1</span>  |  EV-%2  |  %3 (%4)  →  <b>%5</b>  "
                "|  %7  |  Sig: <span style='color:%6;'>%8</span>")
                .arg(l.id).arg(l.evidenceId)
                .arg(QString::fromStdString(l.user))
                .arg(QString::fromStdString(l.role))
                .arg(QString::fromStdString(l.action))
                .arg(C_DIM)
                .arg(QString::fromStdString(l.timestamp))
                .arg(QString::fromStdString(l.sigStatus.empty() ? "—" : l.sigStatus)));
        }
        setStatus(QString("● %1 custody entries").arg(logs.size()));
    } catch (const std::exception& ex) { showError(QString::fromStdString(ex.what())); }
}

void EvidenceTrackerGUI::onViewAuditLogs() {
    if (currentRole != "Admin") { showError("Audit trail — Admin access only."); return; }
    try {
        User u(currentUsername, currentRole);
        auto logs = tracker.viewAuditLogs(u);
        printHeader(QString("AUDIT TRAIL  (%1 events)").arg(logs.size()));
        if (logs.empty()) { printToOutput("  No audit events recorded."); return; }
        for (auto& l : logs) {
            QString col = (l.result == "SUCCESS") ? C_GREEN :
                          (l.result == "DENIED")  ? C_WARN  : C_ACCENT;
            printToOutput(QString(
                "  <span style='color:%1;'>[%2]</span>  %3 (%4)  →  %5  "
                "<span style='color:%6;'>[%7]</span>")
                .arg(C_DIM)
                .arg(QString::fromStdString(l.timestamp))
                .arg(QString::fromStdString(l.user))
                .arg(QString::fromStdString(l.role))
                .arg(QString::fromStdString(l.action))
                .arg(col)
                .arg(QString::fromStdString(l.result)));
        }
        setStatus(QString("● %1 audit events").arg(logs.size()));
    } catch (const std::exception& ex) { showError(QString::fromStdString(ex.what())); }
}

// ─────────────────────────────────────────────────────────────────────────────
//  REPORT SLOTS
// ─────────────────────────────────────────────────────────────────────────────
void EvidenceTrackerGUI::onGenerateCaseReport() {
    if (currentRole != "Admin" && currentRole != "Investigator") {
        showError("Case Report — Investigator or Admin access required."); return;
    }
    QString caseId = searchCaseField->text().trimmed();
    if (caseId.isEmpty()) caseId = caseIdField->text().trimmed();
    if (caseId.isEmpty()) {
        bool _ok; caseId = QInputDialog::getText(this, "Case Report", "Enter Case ID:", QLineEdit::Normal, "", &_ok); if (!_ok) return;
        if (caseId.isEmpty()) return;
    }
    QString savePath = QFileDialog::getSaveFileName(this, "Save Case Report",
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation)
        + "/" + caseId + "_case_report.txt", "Text Files (*.txt)");
    if (savePath.isEmpty()) return;
    try {
        std::string content = reporter.generateCaseReport(
            caseId.toStdString(), currentUsername, savePath.toStdString());
        printHeader("CASE REPORT GENERATED");
        printToOutput(QString::fromStdString(content.substr(0, 2000)));
        printToOutput(QString("<br><span style='color:%1;'>  ✔  Full report saved to: %2</span>")
            .arg(C_GREEN).arg(savePath));
        setStatus("● Case report saved");
    } catch (const std::exception& ex) { showError(QString::fromStdString(ex.what())); }
}

void EvidenceTrackerGUI::onGenerateAuditReport() {
    if (currentRole != "Admin") { showError("Audit Report — Admin only."); return; }
    QString savePath = QFileDialog::getSaveFileName(this, "Save Audit Report",
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation)
        + "/audit_report.txt", "Text Files (*.txt)");
    if (savePath.isEmpty()) return;
    try {
        std::string content = reporter.generateAuditReport(savePath.toStdString());
        printHeader("AUDIT REPORT GENERATED");
        printToOutput(QString::fromStdString(content.substr(0, 2000)));
        printToOutput(QString("<br><span style='color:%1;'>  ✔  Saved to: %2</span>").arg(C_GREEN).arg(savePath));
        setStatus("● Audit report saved");
    } catch (const std::exception& ex) { showError(QString::fromStdString(ex.what())); }
}

void EvidenceTrackerGUI::onGenerateInventory() {
    if (currentRole != "Admin" && currentRole != "Investigator") {
        showError("Inventory — Investigator or Admin required."); return;
    }
    QString savePath = QFileDialog::getSaveFileName(this, "Save Inventory Report",
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation)
        + "/inventory_report.txt", "Text Files (*.txt)");
    if (savePath.isEmpty()) return;
    try {
        std::string content = reporter.generateFullInventory(savePath.toStdString());
        printHeader("INVENTORY REPORT GENERATED");
        printToOutput(QString::fromStdString(content.substr(0, 2000)));
        printToOutput(QString("<br><span style='color:%1;'>  ✔  Saved to: %2</span>").arg(C_GREEN).arg(savePath));
        setStatus("● Inventory saved");
    } catch (const std::exception& ex) { showError(QString::fromStdString(ex.what())); }
}

void EvidenceTrackerGUI::onBackupDatabase() {
    if (currentRole != "Admin") { showError("Backup — Admin only."); return; }
    QString savePath = QFileDialog::getSaveFileName(this, "Save Database Backup",
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation)
        + "/evidence_backup.db", "SQLite Database (*.db)");
    if (savePath.isEmpty()) return;
    try {
        bool ok = tracker.getDb().backupDatabase(savePath.toStdString());
        if (ok) {
            printHeader("DATABASE BACKUP");
            printToOutput(QString("<span style='color:%1;'>  ✔  Backup saved to: %2</span>")
                .arg(C_GREEN).arg(savePath));
            setStatus("● Backup complete");
        } else {
            showError("Backup failed — check path permissions.");
        }
    } catch (const std::exception& ex) { showError(QString::fromStdString(ex.what())); }
}

// ─────────────────────────────────────────────────────────────────────────────
//  THEME TOGGLE
// ─────────────────────────────────────────────────────────────────────────────
void EvidenceTrackerGUI::toggleTheme() {
    darkMode = !darkMode;
    if (darkMode) {
        qApp->setStyleSheet(DARK_STYLE);
    } else {
        qApp->setStyleSheet(R"(
            * { font-family:'Consolas','Courier New',monospace; color:#1E3A5F; }
            QMainWindow,QWidget { background:#F0F4F8; }
            QLineEdit,QComboBox,QTextEdit { background:white; border:1px solid #93C5FD;
                border-radius:4px; padding:8px; color:#1E3A5F; }
            QFrame { background:#E8EFF8; }
            QPushButton { background:#1E3A5F; color:white; border-radius:4px; padding:6px 14px; border:none; }
            QPushButton:hover { background:#2A5080; }
            QGroupBox { border:1px solid #93C5FD; border-radius:6px; margin-top:12px; padding-top:8px; }
            QGroupBox::title { color:#1E3A5F; subcontrol-origin:margin; left:12px; padding:0 6px; }
            QScrollBar:vertical { background:#E8EFF8; width:8px; }
            QScrollBar::handle:vertical { background:#93C5FD; border-radius:4px; }
        )");
    }
    setStatus(darkMode ? "● DARK MODE" : "● LIGHT MODE");
}
