#include "MainWindow.hpp"
#include <QAction>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->actionQuit, &QAction::triggered, this, [=]{
        exit(0);
    });
}
