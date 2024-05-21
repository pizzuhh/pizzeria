#include "dialogConnect.hpp"
#include <QDialog>
#include <QPushButton>
#include <QLineEdit>
#include <QString>

class DialogConnect : public QDialog {
    Q_OBJECT
    public:
        
        DialogConnect(QWidget *parrent = nullptr);
        ~DialogConnect(){}
        QString getIp() {return this->ip;}
    private:
        QString ip;
        Ui::Connect *ui;
        void btnPing();
        
};
