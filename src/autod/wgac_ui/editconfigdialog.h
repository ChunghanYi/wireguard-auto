#ifndef EDITCONFIGDIALOG_H
#define EDITCONFIGDIALOG_H

#include <QDialog>

namespace Ui {
class EditConfigDialog;
}

class EditConfigDialog : public QDialog
{
    Q_OBJECT

public:
    explicit EditConfigDialog(QWidget *parent = nullptr);
    ~EditConfigDialog();

private slots:
    void on_buttonBox_accepted();

private:
    Ui::EditConfigDialog *ui;
};

#endif // EDITCONFIGDIALOG_H
