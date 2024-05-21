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

class Ui_Connect
{
public:
    QLineEdit *ServerIpInput;
    QLineEdit *ServerPortInput;
    QPushButton *PingServer;
    QPushButton *ConnectServer;

    void setupUi(QDialog *Connect)
    {
        if (Connect->objectName().isEmpty())
            Connect->setObjectName(QString::fromUtf8("Connect"));
        Connect->resize(370, 203);
        ServerIpInput = new QLineEdit(Connect);
        ServerIpInput->setObjectName(QString::fromUtf8("ServerIpInput"));
        ServerIpInput->setGeometry(QRect(30, 40, 191, 36));
        ServerPortInput = new QLineEdit(Connect);
        ServerPortInput->setObjectName(QString::fromUtf8("ServerPortInput"));
        ServerPortInput->setGeometry(QRect(30, 90, 191, 36));
        PingServer = new QPushButton(Connect);
        PingServer->setObjectName(QString::fromUtf8("PingServer"));
        PingServer->setGeometry(QRect(140, 140, 91, 41));
        ConnectServer = new QPushButton(Connect);
        ConnectServer->setObjectName(QString::fromUtf8("ConnectServer"));
        ConnectServer->setGeometry(QRect(250, 140, 91, 41));

        retranslateUi(Connect);

        QMetaObject::connectSlotsByName(Connect);
    } // setupUi

    void retranslateUi(QDialog *Connect)
    {
        Connect->setWindowTitle(QCoreApplication::translate("Connect", "Connect", nullptr));
        ServerIpInput->setPlaceholderText(QCoreApplication::translate("Connect", "Server IP", nullptr));
        ServerPortInput->setPlaceholderText(QCoreApplication::translate("Connect", "Server Port", nullptr));
        PingServer->setText(QCoreApplication::translate("Connect", "Ping", nullptr));
        ConnectServer->setText(QCoreApplication::translate("Connect", "Connect", nullptr));
    } // retranslateUi

};

namespace Ui {
    class Connect: public Ui_Connect {};
} // namespace Ui

QT_END_NAMESPACE

#endif // DIALOGCONNECT_H
