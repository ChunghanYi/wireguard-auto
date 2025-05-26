#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "editconfigdialog.h"
#include <QMessageBox>
#include <QTextEdit>
#include <QProcess>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ui->textBrowser->append("WireGuard Auto Connect...");
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::paintEvent(QPaintEvent *event)
{
    QImage image;
    image.load("../../wireguard_logo2.png");
    QPainter painter;
    painter.begin(this);
    painter.drawImage(QPoint(0, 0), image);

    painter.end();
}

void MainWindow::on_startButton_clicked()
{
    QMessageBox::information(this, "Start WGAC Server", ui->cmdEdit->text());

    //system("/usr/local/sbin/wg_autod --daemon --config /etc/wgauto/server.conf");

    QProcess proc;
    QString cmd;
    QStringList args;

    cmd = "/usr/local/sbin/wg_autod";
    args << "--daemon" << "--config" << "/etc/wgauto/server.conf";

    proc.start(cmd, args, QIODevice::ReadOnly);
    proc.waitForFinished();

    ui->textBrowser->append("# /usr/local/sbin/wg_autod --daemon --config /etc/wgauto/server.conf");
}

void MainWindow::on_stopButton_clicked()
{
    QMessageBox::information(this, "Stop WGAC Server", "Stop WireGuard Auto Connect Server...");

    //system("killall -9 wg_autod");

    QProcess proc;
    QString cmd;
    QStringList args;

    cmd = "killall";
    args << "-9" << "wg_autod";

    proc.start(cmd, args, QIODevice::ReadOnly);
    proc.waitForFinished();

    ui->textBrowser->append("# killall -9 wg_autod");
}

void MainWindow::on_editButton_clicked()
{
    qDebug() << "Config Edit Push button clicked";

    EditConfigDialog edit;
    edit.exec();
}

void MainWindow::on_quitButton_clicked()
{
    qDebug() << "Quit Push button clicked";
    ui->textBrowser->append("Quitting...");
    this->close();
}

void MainWindow::on_cmdEdit_editingFinished()
{
    qDebug() << "Cmd Edit modification is finished.";
}
