#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "registerdialog.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onLoginButtonClicked();
    void onSelectFileClicked();
    void onUploadFileClicked();
    void onRegisterButtonClicked();
private:
    Ui::MainWindow *ui;
    QString selectedFile;
    bool loginSuccess = false;
    QString verifiedUsername;  // ✅ 记录认证通过的用户名

    void uploadFile(const QString &filePath);
    QByteArray calculateSM3Hash(const QString &saltHex, const QString &password);
    QByteArray calculateFileSM3Hash(const QString &filePath); // 添加文件SM3哈希计算函数声明
};

#endif // MAINWINDOW_H
