#include "dialogConnect.hpp"
#include <QDialog>
#include <QPushButton>
#include <QLineEdit>
#include <QString>

class DialogConnect : public QDialog {
    Q_OBJECT
    public:
        Ui::Dialog *ui;
        void btnPing();
        DialogConnect(QWidget *parrent = nullptr);
        ~DialogConnect(){}
        QString getIp() {return this->ip;}
    private:
        QString ip;
        
};
