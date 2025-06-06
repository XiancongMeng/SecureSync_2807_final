#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "registerdialog.h"
#include "sm2_utils.h"  // ✅ 新增头文件
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/sm3.h>
#include <openssl/rand.h>       // ✅ 用于 RAND_bytes
#include "sm2_utils.h"          // ✅ 包含 sm2_encrypt 声明
#include <openssl/err.h>
#include <QFileDialog>
#include <QMessageBox>
#include <QTcpSocket>
#include <QFileInfo>
#include <QDebug>  // ✅ 打印调试信息

QByteArray serverPublicKey =
"-----BEGIN PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEPwsj9HhwTxks/VfdObi7vEVRY3es\n"
"xTdWZzU+BQHZYiiVPAtT5GOBKfu0FbgGrBY2bvPqdv9ZXiJ628EgEtCQ8Q==\n"
"-----END PUBLIC KEY-----\n";

QByteArray clientPrivateKey;  // ✅ 客户端 SM2 私钥
QByteArray clientPublicKey;   // ✅ 客户端 SM2 公钥

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->statusLabel->setText("Status: Ready");
    ui->progressBar->setValue(0);

    // ✅ 生成客户端 SM2 密钥对
    if (generate_sm2_keypair(clientPrivateKey, clientPublicKey)) {
        qDebug() << "[SM2] 客户端临时 SM2 公钥：\n" << clientPublicKey;
    } else {
        qDebug() << "[SM2] ❌ 密钥对生成失败！";
    }

    connect(ui->loginButton, &QPushButton::clicked, this, &MainWindow::onLoginButtonClicked);
    connect(ui->selectFileButton, &QPushButton::clicked, this, &MainWindow::onSelectFileClicked);
    connect(ui->uploadButton, &QPushButton::clicked, this, &MainWindow::onUploadFileClicked);
    connect(ui->registerButton, &QPushButton::clicked, this, &MainWindow::onRegisterButtonClicked);
}

MainWindow::~MainWindow()
{
    delete ui;
}

QByteArray MainWindow::calculateSM3Hash(const QString &saltHex, const QString &password)
{
    qDebug() << "\n===== 客户端SM3哈希计算 =====";
    qDebug() << "[客户端] 接收到的salt(十六进制): " << saltHex;
    qDebug() << "[客户端] 用户密码: " << password;

    QByteArray salt = QByteArray::fromHex(saltHex.toUtf8());
    QByteArray data = salt + password.toUtf8();

    qDebug() << "[客户端] salt解码后(二进制): " << salt.toHex();
    qDebug() << "[客户端] 组合后的数据(salt+密码): " << data.toHex();

    unsigned char hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sm3(), nullptr);
    EVP_DigestUpdate(ctx, data.constData(), data.size());
    EVP_DigestFinal_ex(ctx, hash, nullptr);
    EVP_MD_CTX_free(ctx);

    QByteArray hashResult = QByteArray(reinterpret_cast<char*>(hash), 32).toHex();
    qDebug() << "[客户端] 计算的SM3哈希结果: " << hashResult;
    qDebug() << "===== SM3哈希计算完成 =====\n";

    return hashResult;
}

// 新增：计算文件SM3哈希
QByteArray MainWindow::calculateFileSM3Hash(const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << "无法打开文件进行哈希计算：" << filePath;
        return QByteArray();
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sm3(), nullptr);

    char buffer[8192];
    qint64 bytesRead;
    int processedChunks = 0;

    while ((bytesRead = file.read(buffer, sizeof(buffer))) > 0) {
        EVP_DigestUpdate(ctx, buffer, bytesRead);
        processedChunks++;

        // 每处理10个数据块，更新状态
        if (processedChunks % 10 == 0) {
            ui->statusLabel->setText(QString("正在计算文件哈希: %1 MB 已处理")
                                    .arg((processedChunks * sizeof(buffer)) / (1024.0 * 1024.0), 0, 'f', 2));
            QApplication::processEvents();
        }
    }

    unsigned char hash[32];
    unsigned int md_len;
    EVP_DigestFinal_ex(ctx, hash, &md_len);
    EVP_MD_CTX_free(ctx);
    file.close();

    return QByteArray(reinterpret_cast<char*>(hash), md_len);
}

void MainWindow::onLoginButtonClicked()
{
    loginSuccess = false;
    verifiedUsername.clear();
    QString username = ui->usernameEdit->text();
    QString password = ui->passwordEdit->text();

    if (username.isEmpty() || password.isEmpty()) {
        QMessageBox::warning(this, "输入错误", "请输入用户名和密码");
        return;
    }

    qDebug() << "\n===== 登录流程开始 =====";
    qDebug() << "[客户端] 用户名: " << username;
    qDebug() << "[客户端] 尝试连接服务器...";

    QTcpSocket socket;
    socket.connectToHost("127.0.0.1", 8080);
    if (!socket.waitForConnected(3000)) {
        QMessageBox::warning(this, "连接失败", "无法连接认证服务器");
        qDebug() << "[客户端] 连接服务器失败";
        return;
    }

    qDebug() << "[客户端] 连接服务器成功";
    qDebug() << "[客户端] 发送登录请求: LOGIN|" << username;

    QString trimmedUsername = username.trimmed();  // 去除前后空格和换行
    socket.write("LOGIN|" + trimmedUsername.toUtf8() + "\n");

    socket.waitForBytesWritten();

    if (!socket.waitForReadyRead(3000)) {
        QMessageBox::warning(this, "超时", "未能接收 salt");
        qDebug() << "[客户端] 接收salt超时";
        return;
    }

    QByteArray saltLine = socket.readLine().trimmed();
    qDebug() << "[客户端] 收到 saltLine: " << saltLine;

    if (!saltLine.startsWith("SALT|")) {
        QMessageBox::warning(this, "格式错误", "返回内容不合法");
        qDebug() << "[客户端] 收到的salt格式错误";
        return;
    }

    QString salt = QString::fromUtf8(saltLine.mid(5));
    qDebug() << "[客户端] 提取的salt: " << salt;

    QByteArray hashHex = calculateSM3Hash(salt, password);
    qDebug() << "[客户端] 发送哈希: HASH|" << hashHex;

    socket.write("HASH|" + hashHex + "\n");
    socket.waitForBytesWritten();

    if (!socket.waitForReadyRead(3000)) {
        QMessageBox::warning(this, "超时", "未收到认证结果");
        qDebug() << "[客户端] 接收认证结果超时";
        return;
    }

    QByteArray reply = socket.readLine().trimmed();
    qDebug() << "[客户端] 收到认证结果: " << reply;

    if (reply == "OK") {
        loginSuccess = true;
        verifiedUsername = username;
        ui->statusLabel->setText("✅ 登录成功！");
        qDebug() << "[客户端] 登录成功!";
    } else {
        loginSuccess = false;
        verifiedUsername.clear();
        QMessageBox::warning(this, "认证失败", "用户名或密码错误");
        qDebug() << "[客户端] 登录失败";
    }

    qDebug() << "===== 登录流程结束 =====\n";

    socket.close();
}

void MainWindow::onSelectFileClicked()
{
    selectedFile = QFileDialog::getOpenFileName(this, "选择文件", "", "所有文件 (*.*)");
    if (!selectedFile.isEmpty()) {
        QFileInfo fileInfo(selectedFile);
        ui->statusLabel->setText(QString("已选择文件：%1 (大小: %2 字节)").arg(
            fileInfo.fileName()).arg(fileInfo.size()));
    }
}

void MainWindow::onUploadFileClicked()
{
    if (!loginSuccess || verifiedUsername.isEmpty()) {
        QMessageBox::warning(this, "未登录", "请先成功登录再上传文件");
        return;
    }

    if (selectedFile.isEmpty()) {
        QMessageBox::warning(this, "未选择文件", "请先选择文件再上传");
        return;
    }

    ui->statusLabel->setText("开始加密上传文件...");
    uploadFile(selectedFile);
}

void MainWindow::uploadFile(const QString &filePath)
{
    // 首先计算文件的SM3哈希
    ui->statusLabel->setText("正在计算文件哈希...");
    QApplication::processEvents();
    QByteArray fileHash = calculateFileSM3Hash(filePath);

    if (fileHash.isEmpty()) {
        QMessageBox::warning(this, "哈希计算失败", "无法计算文件完整性哈希");
        return;
    }

    qDebug() << "[完整性] 文件SM3哈希: " << fileHash.toHex();

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, "文件打开失败", "无法打开文件进行上传");
        return;
    }

    QTcpSocket *socket = new QTcpSocket(this);
    socket->connectToHost("127.0.0.1", 8081);
    if (!socket->waitForConnected(3000)) {
        QMessageBox::warning(this, "连接失败", "无法连接到文件服务器");
        return;
    }

    // 打印客户端SM2公钥信息
    qDebug() << "\n======= 密钥信息 =======";
    qDebug() << "[客户端] SM2公钥：\n" << clientPublicKey;

    QFileInfo fileInfo(filePath);
    qint64 fileSize = fileInfo.size();

    // 发送客户端的 SM2 公钥
    QByteArray pubKeyMsg = "PUBKEY|" + clientPublicKey.toBase64() + "\n";
    socket->write(pubKeyMsg);
    socket->waitForBytesWritten();
    ui->statusLabel->setText("发送公钥...");

    // 等待服务器回应 SM2 公钥
    if (!socket->waitForReadyRead(3000)) {
        QMessageBox::warning(this, "错误", "未收到服务端公钥");
        return;
    }
    QByteArray response = socket->readLine().trimmed();
    if (!response.startsWith("SERVERPUB|")) {
        QMessageBox::warning(this, "错误", "服务端公钥格式错误");
        return;
    }
    QByteArray b64Data = response.mid(QString("SERVERPUB|").length()).trimmed();
    QByteArray serverPubPem = QByteArray::fromBase64(b64Data);
    qDebug() << "[服务端] SM2公钥：\n" << serverPubPem;
    ui->statusLabel->setText("收到服务端公钥，准备加密...");

    // 生成会话密钥（SM4）
    unsigned char sm4_key[16];
    if (RAND_bytes(sm4_key, sizeof(sm4_key)) != 1) {
        QMessageBox::critical(this, "错误", "生成会话密钥失败");
        return;
    }

    // 打印SM4会话密钥
    qDebug() << "[会话密钥] SM4密钥: ";
    QString sm4KeyHex;
    for (int i = 0; i < 16; i++) {
        sm4KeyHex += QString("%1").arg(sm4_key[i], 2, 16, QChar('0'));
    }
    qDebug() << sm4KeyHex;

    // 使用服务端公钥加密 SM4 会话密钥
    BIO *bio = BIO_new_mem_buf(serverPubPem.constData(), serverPubPem.size());
    EVP_PKEY *server_pubkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!server_pubkey) {
        QMessageBox::critical(this, "错误", "解析服务端公钥失败");
        ERR_print_errors_fp(stderr);
        return;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(server_pubkey, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
        QMessageBox::critical(this, "错误", "初始化加密上下文失败");
        EVP_PKEY_free(server_pubkey);
        return;
    }

    size_t encrypted_len = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_len, sm4_key, sizeof(sm4_key)) <= 0) {
        QMessageBox::critical(this, "错误", "计算加密长度失败");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(server_pubkey);
        return;
    }

    unsigned char *encrypted_key = (unsigned char *)OPENSSL_malloc(encrypted_len);
    if (EVP_PKEY_encrypt(ctx, encrypted_key, &encrypted_len, sm4_key, sizeof(sm4_key)) <= 0) {
        QMessageBox::critical(this, "错误", "SM2 加密失败");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(server_pubkey);
        OPENSSL_free(encrypted_key);
        return;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(server_pubkey);

    // 打印加密后的SM4密钥
    qDebug() << "[加密后会话密钥] 长度: " << encrypted_len << " 字节";
    QString encKeyHex;
    for (size_t i = 0; i < encrypted_len && i < 32; i++) { // 只打印前32字节
        encKeyHex += QString("%1").arg(encrypted_key[i], 2, 16, QChar('0'));
    }
    if (encrypted_len > 32) encKeyHex += "...";
    qDebug() << encKeyHex;

    QByteArray keyHeader = "KEY|" + QByteArray((char*)encrypted_key, encrypted_len).toBase64() + "\n";
    socket->write(keyHeader);
    socket->waitForBytesWritten();
    qDebug() << "[客户端] 已发送加密会话密钥";
    ui->statusLabel->setText("已发送加密会话密钥，开始传输文件...");
    OPENSSL_free(encrypted_key);

    QString fileName = QFileInfo(filePath).fileName();

    // 新的文件头格式，包含SM3哈希值: username|filename|filesize|hash
    QByteArray fileHashBase64 = fileHash.toBase64();
    QByteArray header = verifiedUsername.toUtf8() + "|" + fileName.toUtf8() + "|" +
                      QByteArray::number(fileSize) + "|" + fileHashBase64 + "\n";

    qDebug() << "[上传调试] Header:" << header;
    socket->write(header);
    socket->waitForBytesWritten();

    unsigned char sm4_iv[16] = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff
    };

    // 打印SM4 IV
    qDebug() << "[加密参数] SM4 IV: ";
    QString sm4IvHex;
    for (int i = 0; i < 16; i++) {
        sm4IvHex += QString("%1").arg(sm4_iv[i], 2, 16, QChar('0'));
    }
    qDebug() << sm4IvHex;
    qDebug() << "======= 密钥信息结束 =======\n";

    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(cipher_ctx, EVP_sm4_ctr(), nullptr, sm4_key, sm4_iv);

    char buffer[4096];
    unsigned char encrypted[4096 + 32];
    qint64 bytesRead;
    qint64 totalBytesSent = 0;
    int lastProgress = 0;

    ui->statusLabel->setText("正在加密并上传文件...");
    while ((bytesRead = file.read(buffer, sizeof(buffer))) > 0) {
        int outlen = 0;
        EVP_EncryptUpdate(cipher_ctx, encrypted, &outlen, reinterpret_cast<unsigned char *>(buffer), bytesRead);

        // 不再打印文件内容，只显示重要的进度信息
        socket->write(reinterpret_cast<char *>(encrypted), outlen);
        socket->waitForBytesWritten();

        totalBytesSent += bytesRead;
        int currentProgress = (totalBytesSent * 100) / fileSize;

        // 只在进度有明显变化时更新UI，减少更新频率
        if (currentProgress >= lastProgress + 5 || currentProgress == 100) {
            lastProgress = currentProgress;
            ui->progressBar->setValue(currentProgress);
            ui->statusLabel->setText(QString("正在上传: %1% (%2/%3 字节)")
                                    .arg(currentProgress)
                                    .arg(totalBytesSent)
                                    .arg(fileSize));
            QApplication::processEvents(); // 确保UI及时更新
        }
    }

    int tmplen = 0;
    EVP_EncryptFinal_ex(cipher_ctx, encrypted, &tmplen);
    if (tmplen > 0) {
        socket->write(reinterpret_cast<char *>(encrypted), tmplen);
        socket->waitForBytesWritten();
    }

    EVP_CIPHER_CTX_free(cipher_ctx);
    file.close();

    ui->progressBar->setValue(100);
    ui->statusLabel->setText("文件上传完成，等待服务器完整性验证...");
    QApplication::processEvents();

    // 等待服务器返回完整性校验结果
    if (socket->waitForReadyRead(10000)) { // 等待最多10秒
        QByteArray verifyResponse = socket->readLine().trimmed();
        qDebug() << "[完整性] 服务器返回:" << verifyResponse;

        if (verifyResponse.startsWith("VERIFY|")) {
            QString verifyResult = QString(verifyResponse).mid(7);
            if (verifyResult == "OK") {
                ui->statusLabel->setText(QString("\U0001f510 文件 %1 上传成功，完整性已验证！").arg(fileName));
            } else {
                ui->statusLabel->setText(QString("⚠️ 文件 %1 上传完成，但完整性校验失败！").arg(fileName));
                QMessageBox::warning(this, "完整性警告", "文件上传完成，但服务器端完整性校验失败！");
            }
        } else {
            ui->statusLabel->setText(QString("\U0001f510 文件 %1 (大小: %2 字节) 上传完成！").arg(fileName).arg(fileSize));
        }
    } else {
        ui->statusLabel->setText(QString("\U0001f510 文件 %1 (大小: %2 字节) 上传完成！").arg(fileName).arg(fileSize));
    }

    socket->flush();
    socket->close();
    delete socket;
}

void MainWindow::onRegisterButtonClicked()
{
    RegisterDialog dialog(this);
    dialog.exec();
}
