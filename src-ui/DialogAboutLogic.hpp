#pragma once
#include "DialogAbout.hpp"
#include <QDialog>


class DialogAbout : public QDialog {
    Q_OBJECT
    public: 
    DialogAbout(QWidget *parrent = nullptr);
    ~DialogAbout(){}
    private:
        Ui::About *ui;
};
