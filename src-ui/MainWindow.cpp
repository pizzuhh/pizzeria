#include "MainWindow.hpp"
#include "dialogConnectLogic.hpp"
#include <QAction>


MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->actionQuit, &QAction::triggered, this, [=]{
        exit(0);
    });
    connect(ui->actionConnect, &QAction::triggered, this, [=]{
        DialogConnect d(this);
        connect(&d, &QDialog::finished, [&](int r){
            QString c = d.getIp();
            printf("%s\n", c.toStdString().c_str());
        });
        d.exec();
        // do something after it closes like access global variable set by the dialog
    });
    
}
