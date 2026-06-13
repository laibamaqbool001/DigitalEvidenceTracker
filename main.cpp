#include <QApplication>
#include <QFile>
#include <QIcon>
#include "EvidenceTrackerGUI.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // Load default dark theme
    QFile styleFile(":/resources/darkstyle.qss");
    if (styleFile.open(QFile::ReadOnly)) {
        QString style = styleFile.readAll();
        app.setStyleSheet(style);
    }

    app.setWindowIcon(QIcon(":/resources/appicon.png"));

    EvidenceTrackerGUI gui;
    gui.show();

    return app.exec();
}
