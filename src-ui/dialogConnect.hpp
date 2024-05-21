/********************************************************************************
** Form generated from reading UI file 'DialogConnect.ui'
**
** Created by: Qt User Interface Compiler version 5.15.13
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef DIALOGCONNECT_H
#define DIALOGCONNECT_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>

QT_BEGIN_NAMESPACE

class Ui_Dialog
{
public:
    QLineEdit *ServerIpInput;
    QLineEdit *ServerPortInput;
    QPushButton *PingServer;
    QPushButton *ConnectServer;

    void setupUi(QDialog *Dialog)
    {
        if (Dialog->objectName().isEmpty())
            Dialog->setObjectName(QString::fromUtf8("Dialog"));
        Dialog->resize(370, 203);
        ServerIpInput = new QLineEdit(Dialog);
        ServerIpInput->setObjectName(QString::fromUtf8("ServerIpInput"));
        ServerIpInput->setGeometry(QRect(30, 40, 191, 36));
        ServerPortInput = new QLineEdit(Dialog);
        ServerPortInput->setObjectName(QString::fromUtf8("ServerPortInput"));
        ServerPortInput->setGeometry(QRect(30, 90, 191, 36));
        PingServer = new QPushButton(Dialog);
        PingServer->setObjectName(QString::fromUtf8("PingServer"));
        PingServer->setGeometry(QRect(140, 140, 91, 41));
        ConnectServer = new QPushButton(Dialog);
        ConnectServer->setObjectName(QString::fromUtf8("ConnectServer"));
        ConnectServer->setGeometry(QRect(250, 140, 91, 41));

        retranslateUi(Dialog);

        QMetaObject::connectSlotsByName(Dialog);
    } // setupUi

    void retranslateUi(QDialog *Dialog)
    {
        Dialog->setWindowTitle(QCoreApplication::translate("Dialog", "Dialog", nullptr));
        ServerIpInput->setPlaceholderText(QCoreApplication::translate("Dialog", "Server IP", nullptr));
        ServerPortInput->setPlaceholderText(QCoreApplication::translate("Dialog", "Server Port", nullptr));
        PingServer->setText(QCoreApplication::translate("Dialog", "Ping", nullptr));
        ConnectServer->setText(QCoreApplication::translate("Dialog", "Connect", nullptr));
    } // retranslateUi

};

namespace Ui {
    class Dialog: public Ui_Dialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // DIALOGCONNECT_H
