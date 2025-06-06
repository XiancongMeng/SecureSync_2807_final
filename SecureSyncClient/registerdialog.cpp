#include "registerdialog.h"
#include "ui_registerdialog.h"
#include <QMessageBox>
#include <QProcess>

RegisterDialog::RegisterDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::RegisterDialog)
{
    ui->setupUi(this);
}

RegisterDialog::~RegisterDialog()
{
    delete ui;
}

void RegisterDialog::on_buttonRegister_clicked()
{
    QString username = ui->lineEditUsername->text();
    QString password = ui->lineEditPassword->text();

    if (username.isEmpty() || password.isEmpty()) {
        QMessageBox::warning(this, "输入错误", "请输入用户名和密码");
        return;
    }

    // 拼接 system 命令，注意加上 ./server 路径
    QString cmd = QString("./server/register_user %1 %2").arg(username, password);

    // 转为 C 风格字符串并执行
    int result = system(cmd.toUtf8().constData());

    if (result == 0) {
        QMessageBox::information(this, "注册成功", "用户注册成功！");
        this->accept();
    } else {
        QMessageBox::critical(this, "注册失败", "注册过程失败，请检查用户名是否重复");
    }
}


