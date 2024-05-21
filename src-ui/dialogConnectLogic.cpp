#include "dialogConnectLogic.hpp"
#include "./utils.hpp"
#include <QAction>
#include <QMessageBox>

DialogConnect::DialogConnect(QWidget *parrent) : QDialog(parrent), ui(new Ui::Dialog) {
    ui->setupUi(this);
    connect(ui->PingServer, &QPushButton::clicked, this, &DialogConnect::btnPing);
    
}

void DialogConnect::btnPing() {
    if (Ping(ui->ServerIpInput->text().toStdString().c_str(), ui->ServerPortInput->text().toInt())) {
        QMessageBox::information(this, "Ping", "Server responded");
    }
    this->close();
}
