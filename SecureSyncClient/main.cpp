#include "mainwindow.h"
#include <QApplication>
#include <QDir>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QDir::setCurrent(QCoreApplication::applicationDirPath() + "/.."); // 设置工作目录为 SecureSync 根目录

    MainWindow w;
    w.show();
    return a.exec();
}
