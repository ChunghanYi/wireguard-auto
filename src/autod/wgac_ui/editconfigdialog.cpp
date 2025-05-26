#include "editconfigdialog.h"
#include "ui_editconfigdialog.h"
#include <QFile>
#include <QMessageBox>


EditConfigDialog::EditConfigDialog(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::EditConfigDialog)
{
    ui->setupUi(this);

    QFile file("/etc/wgauto/server.conf");
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return;

    QTextStream in(&file);
#if 0
    while (!in.atEnd()) {
        QString line = in.readLine();
        ui->plainTextEdit->insertPlainText(line);
        ui->plainTextEdit->insertPlainText(QString("\n"));
    }
#else
    ui->plainTextEdit->setPlainText(in.readAll());
#endif
    file.close();
}

EditConfigDialog::~EditConfigDialog()
{
    delete ui;
}

void EditConfigDialog::on_buttonBox_accepted()
{
    qDebug() << "### Ok Button has been clicked!";

    QFile file("/etc/wgauto/server.conf");
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qDebug() << "Error: Could not save file";
        return;
    }

    QTextStream out(&file);
    out << ui->plainTextEdit->toPlainText();
    file.close();
}

