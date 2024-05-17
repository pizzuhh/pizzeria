#ifndef MAINWINDOW_HPP
#define MAINWINDOW_HPP

#include <QMainWindow>
#include "window.hpp"

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow() {};

private slots:

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_HPP
