/********************************************************************************
** Form generated from reading UI file 'registerdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.3
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_REGISTERDIALOG_H
#define UI_REGISTERDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>

QT_BEGIN_NAMESPACE

class Ui_RegisterDialog
{
public:
    QLabel *labelUsername;
    QLineEdit *lineEditUsername;
    QLineEdit *lineEditPassword;
    QLabel *labelPassword;
    QPushButton *buttonRegister;
    QLabel *labelStatus;

    void setupUi(QDialog *RegisterDialog)
    {
        if (RegisterDialog->objectName().isEmpty())
            RegisterDialog->setObjectName(QString::fromUtf8("RegisterDialog"));
        RegisterDialog->resize(750, 514);
        labelUsername = new QLabel(RegisterDialog);
        labelUsername->setObjectName(QString::fromUtf8("labelUsername"));
        labelUsername->setGeometry(QRect(90, 160, 81, 41));
        lineEditUsername = new QLineEdit(RegisterDialog);
        lineEditUsername->setObjectName(QString::fromUtf8("lineEditUsername"));
        lineEditUsername->setGeometry(QRect(160, 170, 113, 25));
        lineEditPassword = new QLineEdit(RegisterDialog);
        lineEditPassword->setObjectName(QString::fromUtf8("lineEditPassword"));
        lineEditPassword->setGeometry(QRect(160, 270, 113, 25));
        lineEditPassword->setEchoMode(QLineEdit::Password);
        labelPassword = new QLabel(RegisterDialog);
        labelPassword->setObjectName(QString::fromUtf8("labelPassword"));
        labelPassword->setGeometry(QRect(80, 270, 67, 17));
        buttonRegister = new QPushButton(RegisterDialog);
        buttonRegister->setObjectName(QString::fromUtf8("buttonRegister"));
        buttonRegister->setGeometry(QRect(390, 270, 89, 25));
        labelStatus = new QLabel(RegisterDialog);
        labelStatus->setObjectName(QString::fromUtf8("labelStatus"));
        labelStatus->setGeometry(QRect(380, 170, 67, 17));

        retranslateUi(RegisterDialog);

        QMetaObject::connectSlotsByName(RegisterDialog);
    } // setupUi

    void retranslateUi(QDialog *RegisterDialog)
    {
        RegisterDialog->setWindowTitle(QCoreApplication::translate("RegisterDialog", "Dialog", nullptr));
        labelUsername->setText(QCoreApplication::translate("RegisterDialog", "\347\224\250\346\210\267\345\220\215", nullptr));
        labelPassword->setText(QCoreApplication::translate("RegisterDialog", "\350\276\223\345\205\245\345\257\206\347\240\201", nullptr));
        buttonRegister->setText(QCoreApplication::translate("RegisterDialog", "\346\263\250\345\206\214", nullptr));
        labelStatus->setText(QString());
    } // retranslateUi

};

namespace Ui {
    class RegisterDialog: public Ui_RegisterDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_REGISTERDIALOG_H
