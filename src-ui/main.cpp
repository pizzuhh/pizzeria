#include <QApplication>
#include "MainWindow.hpp"


int main(int argc, char **argv) {
    QApplication app(argc, argv);
    MainWindow window;
    window.setWindowFlags(window.windowFlags() & ~Qt::WindowMaximizeButtonHint);
    window.setFixedSize(window.size());
    window.show();
    return app.exec();
}
