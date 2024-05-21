#include "DialogAboutLogic.hpp"


DialogAbout::DialogAbout(QWidget * parrent) : QDialog(parrent), ui(new Ui::About) {
    ui->setupUi(this);
    connect(ui->pushButton, &QPushButton::clicked, this, [=](){
        this->close();
    });
}
