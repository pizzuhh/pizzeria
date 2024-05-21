#include "MainWindow.hpp"
#include "dialogConnectLogic.hpp"
#include "DialogAboutLogic.hpp"
#include <QAction>


MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->actionQuit, &QAction::triggered, this, [=]() {
        exit(0);
    });
    connect(ui->actionConnect, &QAction::triggered, this, [=]() {
        DialogConnect d(this);
        d.exec();
    });
    connect(ui->actionAbout, &QAction::triggered, this, [=]() {
        DialogAbout d(this);
        d.exec();
    });
    
}
