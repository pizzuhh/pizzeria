#include "dialogConnectLogic.hpp"
#include "./utils.hpp"
#include <QAction>
#include <QMessageBox>
#include <errno.h>

DialogConnect::DialogConnect(QWidget *parrent) : QDialog(parrent), ui(new Ui::Connect) {
    ui->setupUi(this);
    connect(ui->PingServer, &QPushButton::clicked, this, &DialogConnect::btnPing);
    
}

void DialogConnect::btnPing() {
    if (Ping(ui->ServerIpInput->text().toStdString().c_str(), ui->ServerPortInput->text().toInt())) {
        QMessageBox::information(this, "Ping", "Server responded");
    } else {
        std::string err = "Server did not responded\nError: " + std::string(strerror(errno));
        QMessageBox::warning(this, "Ping", err.c_str());
    }
    this->close();
}
