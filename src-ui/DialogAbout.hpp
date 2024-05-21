/********************************************************************************
** Form generated from reading UI file 'DialogAbout.ui'
**
** Created by: Qt User Interface Compiler version 5.15.13
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef DIALOGABOUT_H
#define DIALOGABOUT_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>

QT_BEGIN_NAMESPACE

class Ui_About
{
public:
    QLabel *label;
    QLabel *label_2;
    QPushButton *pushButton;

    void setupUi(QDialog *About)
    {
        if (About->objectName().isEmpty())
            About->setObjectName(QString::fromUtf8("About"));
        About->resize(387, 340);
        label = new QLabel(About);
        label->setObjectName(QString::fromUtf8("label"));
        label->setGeometry(QRect(100, 0, 171, 61));
        QFont font;
        font.setPointSize(36);
        label->setFont(font);
        label->setTextFormat(Qt::PlainText);
        label_2 = new QLabel(About);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        label_2->setGeometry(QRect(20, 60, 351, 221));
        QFont font1;
        font1.setPointSize(14);
        label_2->setFont(font1);
        label_2->setTextFormat(Qt::MarkdownText);
        pushButton = new QPushButton(About);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));
        pushButton->setGeometry(QRect(280, 295, 101, 41));
        QFont font2;
        font2.setPointSize(16);
        pushButton->setFont(font2);

        retranslateUi(About);

        QMetaObject::connectSlotsByName(About);
    } // setupUi

    void retranslateUi(QDialog *About)
    {
        About->setWindowTitle(QCoreApplication::translate("About", "About", nullptr));
        label->setText(QCoreApplication::translate("About", "Pizzeria", nullptr));
        label_2->setText(QCoreApplication::translate("About", "<html><head/><body><p><span style=\" font-size:10pt;\">Pizzeria is a chat app written in C++.</span></p><p><span style=\" font-size:10pt;\">Written by: pizzuhh</span></p><p><span style=\" font-size:10pt;\">Source code on: </span><a href=\"https://github.com/pizzuhh/pizzeria\"><span style=\" font-size:10; text-decoration: underline; color:#0986d3;\">github</span></a></p></body></html>", nullptr));
        pushButton->setText(QCoreApplication::translate("About", "Ok", nullptr));
    } // retranslateUi

};

namespace Ui {
    class About: public Ui_About {};
} // namespace Ui

QT_END_NAMESPACE

#endif // DIALOGABOUT_H
