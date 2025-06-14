#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPainter>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    virtual void paintEvent(QPaintEvent *event);

private slots:
    void on_startButton_clicked();
    void on_stopButton_clicked();
    void on_editButton_clicked();
    void on_quitButton_clicked();
    void on_cmdEdit_editingFinished();

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
