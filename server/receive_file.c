#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <time.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <ctype.h>  // 用于isprint函数
#include <openssl/err.h> // 用于错误处理
#include <signal.h>
#include <sys/wait.h>
#include <sys/epoll.h>  // 添加epoll头文件
#include <openssl/sm3.h>  // 添加SM3哈希头文件

#define PORT 8081
#define BUFFER_SIZE 4096
#define MAX_EVENTS 10  // epoll事件数组大小
#define HASH_SIZE 32   // SM3哈希长度为32字节
#define DEFAULT_KEY_PATH "../keys/server_private_key.pem"  // 默认密钥路径

// 从文件加载私钥的函数
EVP_PKEY* load_private_key_from_file(const char* filename) {
    FILE* key_file = fopen(filename, "r");
    if (!key_file) {
        fprintf(stderr, "❌ 无法打开密钥文件: %s\n", filename);
        perror("fopen error");
        return NULL;
    }
    
    EVP_PKEY* privkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    
    if (!privkey) {
        fprintf(stderr, "❌ 无法加载私钥: %s\n", filename);
        ERR_print_errors_fp(stderr);
    }
    
    return privkey;
}

unsigned char sm4_iv[16] = {
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff
};

// 辅助函数：将二进制数据转换为十六进制字符串
void bin2hex(const unsigned char *bin, size_t bin_len, char *hex) {
    static const char hexchars[] = "0123456789abcdef";
    size_t i;
    
    for (i = 0; i < bin_len; i++) {
        hex[i*2] = hexchars[bin[i] >> 4];
        hex[i*2+1] = hexchars[bin[i] & 0x0F];
    }
    hex[bin_len*2] = '\0';
}

void write_log(const char *userid, const char *operation) {
    sqlite3 *db;
    sqlite3_open("data/users.db", &db);
    char sql[512];
    time_t now = time(NULL);
    snprintf(sql, sizeof(sql),
             "INSERT INTO logs (timestamp, userid, operation) VALUES (%ld, '%s', '%s');",
             now, userid, operation);
    char *err = NULL;
    sqlite3_exec(db, sql, 0, 0, &err);
    sqlite3_close(db);
}

int base64_decode(const char *input, unsigned char *output, int output_len) {
    int len = strlen(input);
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf((void *)input, len);
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
    int decoded = BIO_read(bmem, output, output_len);
    BIO_free_all(bmem);
    return decoded;
}

// Base64编码函数
char *base64_encode(const unsigned char *input, int length) {
    BIO *bmem = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bptr = NULL;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);

    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;

    BIO_free_all(b64);

    return buff;
}

// 客户端处理函数
void process_client(int client_fd) {
    // Step 1: receive client public key
    char pubkey_line[2048] = {0};
    recv(client_fd, pubkey_line, sizeof(pubkey_line), 0);
    if (strncmp(pubkey_line, "PUBKEY|", 7) != 0) {
        fprintf(stderr, "格式错误，未收到 PUBKEY|\n");
        return;
    }

    // Step 2: send server public key (从文件加载密钥)
    const char* key_paths[] = {
        DEFAULT_KEY_PATH,             // 相对于运行目录的路径
        "keys/server_private_key.pem", // 项目根目录的相对路径
        "../keys/server_private_key.pem", // 向上一级的相对路径
        "/var/lib/securesync/keys/server_private_key.pem" // 可能的绝对路径
    };
    
    EVP_PKEY *server_privkey = NULL;
    for (int i = 0; i < sizeof(key_paths) / sizeof(key_paths[0]); i++) {
        server_privkey = load_private_key_from_file(key_paths[i]);
        if (server_privkey) {
            printf("✅ 成功从 %s 加载服务端私钥\n", key_paths[i]);
            break;
        }
    }
    
    if (!server_privkey) {
        fprintf(stderr, "❌ 无法加载服务端私钥，尝试了多个路径但均失败\n");
        return;
    }

    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(server_privkey);
    if (!ec_key) {
        fprintf(stderr, "❌ 提取 EC_KEY 失败\n");
        EVP_PKEY_free(server_privkey);
        return;
    }

    EVP_PKEY *server_pubkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(server_pubkey, ec_key)) {
        fprintf(stderr, "❌ 分配 EC_KEY 给公钥失败\n");
        EVP_PKEY_free(server_privkey);
        EVP_PKEY_free(server_pubkey);
        return;
    }

    BIO *pubbio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pubbio, server_pubkey);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(pubbio, &bptr);
    BIO_set_close(pubbio, BIO_NOCLOSE);

    char base64_pub[2048] = {0};
    EVP_EncodeBlock((unsigned char*)base64_pub, (unsigned char*)bptr->data, bptr->length);

    char message[2100];
    snprintf(message, sizeof(message), "SERVERPUB|%s\n", base64_pub);
    send(client_fd, message, strlen(message), 0);
    printf("\U0001f4e1 已发送 SERVERPUB 公钥给客户端\n");

    BIO_free(pubbio);
    EVP_PKEY_free(server_pubkey);

    // Step 3: receive session key
    char key_line[1024] = {0};
    recv(client_fd, key_line, sizeof(key_line), 0);
    if (strncmp(key_line, "KEY|", 4) != 0) {
        fprintf(stderr, "未收到加密密钥\n");
        EVP_PKEY_free(server_privkey);
        return;
    }

    unsigned char enc_key[256];
    int enc_len = base64_decode(key_line + 4, enc_key, sizeof(enc_key));

    // 显示接收到的加密密钥
    fprintf(stderr, "接收到的加密密钥 (%d 字节):\n", enc_len);
    for(int i=0; i<enc_len; i++) {
        fprintf(stderr, "%02x ", enc_key[i]);
        if((i+1)%16 == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(server_privkey, NULL);
    EVP_PKEY_decrypt_init(ctx);
    unsigned char sm4_key[16];
    size_t sm4_key_len = sizeof(sm4_key);
    if (EVP_PKEY_decrypt(ctx, sm4_key, &sm4_key_len, enc_key, enc_len) <= 0) {
        fprintf(stderr, "SM2 解密失败\n");
        // 添加错误详细信息
        unsigned long err = ERR_get_error();
        char err_msg[256];
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        fprintf(stderr, "SM2 解密错误: %s\n", err_msg);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(server_privkey);
        return;
    }

    // 调试: 显示解密后的SM4密钥
    fprintf(stderr, "解密后的SM4密钥 (%zu 字节):\n", sm4_key_len);
    for(int i=0; i<sm4_key_len; i++) {
        fprintf(stderr, "%02x ", sm4_key[i]);
    }
    fprintf(stderr, "\n");

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(server_privkey);

    // Step 4: receive file header
    char header[512] = {0};
    ssize_t header_len = recv(client_fd, header, sizeof(header), 0);
    char username[64], filename[128], hash_str[128] = {0};
    long filesize;
    int header_parsed_len = 0;

    // 打印原始头部数据以便调试
    fprintf(stderr, "[接收调试] 原始头部数据: ");
    for (int i = 0; i < 30 && i < header_len; i++) {
        fprintf(stderr, "%02x ", (unsigned char)header[i]);
    }
    fprintf(stderr, "\n");

    // 解析文件头，现在包括SM3哈希值，格式为: username|filename|size|hash
    sscanf(header, "%63[^|]|%127[^|]|%ld|%127[^|\n]%n", username, filename, &filesize, hash_str, &header_parsed_len);

    fprintf(stderr, "[接收调试] 文件头部内容: %s|%s|%ld|%s\n", username, filename, filesize, hash_str);
    fprintf(stderr, "[接收调试] 解析头部使用字符数: %d\n", header_parsed_len);

    // 检查解析后的位置是否为换行符，如果是则跳过它
    if (header[header_parsed_len] == '\n') {
        header_parsed_len++;
        fprintf(stderr, "[接收调试] 检测到头部换行符，调整解析位置: %d\n", header_parsed_len);
    }

    printf("\U0001f4e9 Receiving '%s' from '%s' (%ld bytes)...\n", filename, username, filesize);
    if (filesize <= 0) {
        fprintf(stderr, "❌ 文件大小无效: %ld\n", filesize);
        return;
    }

    // 将Base64编码的哈希值解码为原始二进制形式
    unsigned char expected_hash[HASH_SIZE];
    int hash_len = 0;
    if (strlen(hash_str) > 0) {
        printf("\n===== SM3 完整性校验 - 开始 =====\n");
        printf("🔍 接收到的Base64编码哈希值: %s\n", hash_str);
        
        hash_len = base64_decode(hash_str, expected_hash, HASH_SIZE);
        if (hash_len != HASH_SIZE) {
            fprintf(stderr, "❌ 哈希值解码错误，长度不匹配: %d (应为32字节)\n", hash_len);
            char hash_hex[HASH_SIZE*2+1];
            bin2hex(expected_hash, hash_len, hash_hex);
            fprintf(stderr, "接收到的哈希值: %s (长度: %d)\n", hash_hex, hash_len);
        } else {
            printf("✅ 哈希值解码成功，长度正确: %d 字节\n", hash_len);
            printf("📊 客户端计算的文件哈希 (十六进制): ");
            for (int i = 0; i < HASH_SIZE; i++) {
                printf("%02x", expected_hash[i]);
            }
            printf("\n");
        }
    } else {
        fprintf(stderr, "⚠️ 警告: 未接收到文件哈希值，将跳过完整性检查\n");
    }

    char user_dir[256];
    snprintf(user_dir, sizeof(user_dir), "/var/sync/%s", username);
    mkdir("/var/sync", 0755);
    mkdir(user_dir, 0755);

    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/%s", user_dir, filename);
    
    // 路径遍历攻击检测
    if (strstr(filename, "../") != NULL || strstr(filename, "..\\") != NULL || 
        strstr(filename, "/..") != NULL || strstr(filename, "\\..") != NULL ||
        strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0) {
        fprintf(stderr, "❌ 检测到路径遍历攻击尝试: %s\n", filename);
        char log_message[256];
        snprintf(log_message, sizeof(log_message), "SECURITY:path_traversal_attempt:%s", filename);
        write_log(username, log_message);
        return;
    }
    
    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("文件打开失败");
        return;
    }

    // 初始化解密上下文
    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(cipher_ctx, EVP_sm4_ctr(), NULL, sm4_key, sm4_iv);
    
    // 初始化SM3哈希上下文
    unsigned char calculated_hash[HASH_SIZE];
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(hash_ctx, EVP_sm3(), NULL);

    if (hash_len == HASH_SIZE) {
        printf("🔐 已初始化SM3哈希计算上下文，将在解密过程中累计计算\n");
    }

    // 调试输出SM4密钥和IV
    printf("[密钥调试] SM4 密钥: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", sm4_key[i]);
    }
    printf("\n");
    printf("[密钥调试] SM4 IV: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", sm4_iv[i]);
    }
    printf("\n");

    // 检查文件头后是否有额外数据
    long total_received = 0;
    long total_decrypted = 0;
    int decrypt_error = 0;
    
    if (header_parsed_len > 0 && header_len > header_parsed_len) {
        int extra_data_len = header_len - header_parsed_len;
        printf("[接收调试] 文件头部后发现额外数据: %d字节\n", extra_data_len);
        
        // 处理额外数据作为第一块加密数据
        unsigned char decrypted_header[512];
        int outlen = 0;
        if (EVP_DecryptUpdate(cipher_ctx, decrypted_header, &outlen, (unsigned char *)(header + header_parsed_len), extra_data_len) == 1) {
            printf("[解密调试] 解密头部后的额外数据: %d字节\n", outlen);
            if (outlen > 0) {
                printf("[解密调试] 额外数据解密内容: ");
                for (int i = 0; i < (outlen > 16 ? 16 : outlen); i++) {
                    printf("%c", isprint(decrypted_header[i]) ? decrypted_header[i] : '.');
                }
                printf("...\n");
                
                if (write(fd, decrypted_header, outlen) == outlen) {
                    total_decrypted = outlen;
                    printf("[写入调试] 写入文件头中的额外数据: %d字节\n", outlen);
                    
                    // 更新SM3哈希
                    EVP_DigestUpdate(hash_ctx, decrypted_header, outlen);
                } else {
                    perror("[错误] 写入文件头中的额外数据失败");
                }
            }
        } else {
            printf("[警告] 解密文件头中的额外数据失败\n");
        }
        
        // 更新接收总数据量
        total_received = extra_data_len;
    }

    // 读取并解密文件内容
    char enc_buffer[BUFFER_SIZE];
    unsigned char dec_buffer[BUFFER_SIZE];
    
    printf("📦 开始接收加密数据并解密...\n");
    
    // 使用缓冲式读取，接收加密数据并解密
    while (1) {
        ssize_t bytes_read = recv(client_fd, enc_buffer, BUFFER_SIZE, 0);
        if (bytes_read <= 0) {
            if (bytes_read == 0) 
                printf("[接收] 连接已关闭，接收数据: %ld/%ld 字节\n", total_received, filesize);
            else 
                perror("[接收] 接收数据错误");
            break;
        }
        
        total_received += bytes_read;
        printf("[接收] 读取数据块: %zd 字节，累计: %ld/%ld (%.1f%%)\n", 
              bytes_read, total_received, filesize, 
              (float)total_received/filesize*100);
        
        int outlen = 0;
        if (EVP_DecryptUpdate(cipher_ctx, dec_buffer, &outlen, (unsigned char*)enc_buffer, bytes_read) != 1) {
            fprintf(stderr, "❌ 解密失败\n");
            decrypt_error = 1;
            break;
        }
        
        // 更新SM3哈希计算
        if (hash_len == HASH_SIZE) {
            EVP_DigestUpdate(hash_ctx, dec_buffer, outlen);
        }
        
        if (write(fd, dec_buffer, outlen) != outlen) {
            perror("❌ 写入文件错误");
            decrypt_error = 1;
            break;
        }
        
        total_decrypted += outlen;
        
        // 接收完毕检查
        if (total_received >= filesize) {
            printf("[接收] 文件接收完成: %ld 字节\n", total_received);
            break;
        }
    }
    
    // 添加处理解密最后块的代码
    int final_len = 0;
    unsigned char final_block[BUFFER_SIZE];
    if (!decrypt_error && EVP_DecryptFinal_ex(cipher_ctx, final_block, &final_len) != 1) {
        fprintf(stderr, "❌ 解密最终块失败\n");
        decrypt_error = 1;
    }
    
    if (final_len > 0) {
        printf("[解密] 处理最终块: %d 字节\n", final_len);
        if (hash_len == HASH_SIZE) {
            EVP_DigestUpdate(hash_ctx, final_block, final_len);
        }
        if (write(fd, final_block, final_len) != final_len) {
            perror("❌ 写入最终块错误");
            decrypt_error = 1;
        }
        total_decrypted += final_len;
    }
    
    printf("[摘要] 总接收: %ld 字节, 总解密写入: %ld 字节\n", total_received, total_decrypted);

    // 完成SM3哈希计算
    unsigned int md_len;
    EVP_DigestFinal_ex(hash_ctx, calculated_hash, &md_len);
    EVP_MD_CTX_free(hash_ctx);
    
    // 详细显示哈希验证过程
    if (hash_len == HASH_SIZE) {
        printf("\n===== SM3 完整性校验 - 验证阶段 =====\n");
        
        // 打印计算出的哈希值
        printf("📊 服务端计算的文件哈希: ");
        for (int i = 0; i < HASH_SIZE; i++) {
            printf("%02x", calculated_hash[i]);
        }
        printf("\n");
        
        printf("📊 客户端发送的文件哈希: ");
        for (int i = 0; i < HASH_SIZE; i++) {
            printf("%02x", expected_hash[i]);
        }
        printf("\n");
        
        // 验证哈希值
        int integrity_verified = 0;
        if (memcmp(expected_hash, calculated_hash, HASH_SIZE) == 0) {
            printf("✅ SM3哈希匹配成功！文件完整性校验通过\n");
            integrity_verified = 1;
        } else {
            printf("❌ SM3哈希不匹配！文件完整性校验失败，文件可能已被篡改或传输错误\n");
            
            // 计算有多少字节不匹配
            int mismatch_bytes = 0;
            for (int i = 0; i < HASH_SIZE; i++) {
                if (expected_hash[i] != calculated_hash[i]) {
                    mismatch_bytes++;
                }
            }
            printf("   不匹配字节数: %d / %d\n", mismatch_bytes, HASH_SIZE);
        }
        
        printf("===== SM3 完整性校验 - 完成 =====\n\n");
        
        // 完整性校验结果发送给客户端
        char verify_result[128];
        snprintf(verify_result, sizeof(verify_result), "VERIFY|%s\n", 
                 integrity_verified ? "OK" : "FAIL");
        send(client_fd, verify_result, strlen(verify_result), 0);
        printf("📤 发送验证结果到客户端: %s", verify_result);
    } else {
        printf("⚠️ 跳过完整性校验：未收到有效哈希值\n");
    }

    EVP_CIPHER_CTX_free(cipher_ctx);
    close(fd);

    printf("✅ 文件已解密保存至 %s\n", filepath);
    char operation[256];
    int integrity_verified = (hash_len == HASH_SIZE && memcmp(expected_hash, calculated_hash, HASH_SIZE) == 0) ? 1 : 0;
    if (integrity_verified) {
        snprintf(operation, sizeof(operation), "upload:%.100s:integrity-verified", filename);
    } else {
        snprintf(operation, sizeof(operation), "upload:%.100s:integrity-unknown", filename);
    }

    write_log(username, operation);

    // 文件传输完成，关闭套接字
    close(client_fd);
    fprintf(stderr, "✅ 传输成功完成\n\n");
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY
    };

    // 设置socket为非阻塞模式
    int flags = fcntl(server_fd, F_GETFL, 0);
    fcntl(server_fd, F_SETFL, flags | O_NONBLOCK);
    
    // 设置SO_REUSEADDR选项，允许端口重用
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, SOMAXCONN);
    
    // 创建epoll实例
    printf("\n===== EPOLL 创建 =====\n");
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1 失败");
        exit(EXIT_FAILURE);
    }
    printf("[EPOLL] 创建成功，epoll_fd = %d\n", epoll_fd);
    
    // 添加服务器socket到epoll
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;  // 监听读事件
    ev.data.fd = server_fd;
    printf("[EPOLL] 添加服务器socket(fd=%d)到epoll监听列表，监听EPOLLIN(读)事件\n", server_fd);
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) == -1) {
        perror("epoll_ctl: server_fd");
        close(epoll_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("[EPOLL] 添加成功\n");
    printf("===== EPOLL 创建结束 =====\n\n");
    
    // 设置SIGCHLD信号处理，避免僵尸进程
    printf("[系统] 设置SIGCHLD信号处理为SIG_IGN，自动回收子进程，避免僵尸进程\n");
    signal(SIGCHLD, SIG_IGN);
    
    printf("\U0001f510 File receive server (with SM2/SM4) running on port %d (epoll mode)...\n", PORT);

    // 事件循环
    printf("\n===== EPOLL 事件循环开始 =====\n");
    printf("[EPOLL] 等待事件发生...\n");
    int loop_count = 0;
    
    while (1) {
        loop_count++;
        // 打印当前时间
        time_t now = time(NULL);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        printf("[EPOLL %s] 循环 #%d: 调用epoll_wait()等待事件...\n", time_str, loop_count);
        fflush(stdout);
        
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 30000); // 30秒超时，方便看日志
        
        if (nfds == -1) {
            if (errno == EINTR) {
                printf("[EPOLL] 被信号中断，重新等待\n");
                fflush(stdout);
                continue;
            }
            perror("epoll_wait");
            break;
        } else if (nfds == 0) {
            printf("[EPOLL] 等待超时，无事件发生\n");
            fflush(stdout);
            continue;
        }
        
        printf("[EPOLL] 检测到 %d 个事件！\n", nfds);
        fflush(stdout);
        
        for (int n = 0; n < nfds; ++n) {
            printf("[EPOLL] 处理第 %d 个事件，fd = %d\n", n+1, events[n].data.fd);
            fflush(stdout);
            
            if (events[n].data.fd == server_fd) {
                printf("[EPOLL] 服务器socket上有事件，表示有新连接请求\n");
                fflush(stdout);
                
                // 处理新连接
                int client_fd;
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int accept_count = 0;
                
                printf("[EPOLL] 开始接受所有等待的连接...\n");
                fflush(stdout);
                
                while ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len)) > 0) {
                    accept_count++;
                    char client_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                    
                    printf("[EPOLL] 接受第 %d 个新连接: fd=%d, 来自 %s:%d\n", 
                           accept_count, client_fd, client_ip, ntohs(client_addr.sin_port));
                    fflush(stdout);
                    
                    // 创建子进程处理连接
                    printf("\n===== FORK 调试 =====\n");
                    printf("[父进程 PID: %d] 准备创建子进程处理连接 %d (来自 %s:%d)\n", 
                           getpid(), client_fd, client_ip, ntohs(client_addr.sin_port));
                    fflush(stdout);
                    
                    // 获取当前进程数量（注意：system调用可能较慢）
                    printf("[系统状态] 检查当前活跃进程...\n");
                    system("ps -ef | grep receive_file | grep -v grep");
                    fflush(stdout);
                    
                    pid_t pid = fork();
                    
                    if (pid < 0) {
                        perror("fork 失败");
                        close(client_fd);
                    }
                    else if (pid == 0) {
                        // 子进程
                        printf("[子进程 PID: %d] 已创建，准备处理客户端连接 %d\n", getpid(), client_fd);
                        printf("[子进程 PID: %d] 关闭监听socket(%d)和epoll_fd(%d)\n", getpid(), server_fd, epoll_fd);
                        fflush(stdout);
                        
                        close(server_fd);    // 子进程关闭监听socket
                        close(epoll_fd);     // 子进程关闭epoll fd
                        
                        // 处理客户端请求
                        printf("[子进程 PID: %d] 开始处理客户端请求...\n", getpid());
                        fflush(stdout);
                        process_client(client_fd);
                        
                        printf("[子进程 PID: %d] 处理完成，关闭连接，退出\n", getpid());
                        fflush(stdout);
                        close(client_fd);
                        exit(0);  // 子进程退出
                    }
                    else {
                        // 父进程
                        printf("[父进程 PID: %d] 创建了子进程(PID: %d)，关闭客户端socket(%d)\n", getpid(), pid, client_fd);
                        close(client_fd);  // 父进程不需要客户端socket
                        printf("[父进程 PID: %d] 继续监听新连接...\n", getpid());
                        printf("===== FORK 调试结束 =====\n\n");
                        fflush(stdout);
                    }
                }
                
                if (client_fd == -1) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("[EPOLL] accept失败");
                    } else {
                        printf("[EPOLL] 没有更多连接等待接受\n");
                    }
                    fflush(stdout);
                }
                
                printf("[EPOLL] 共接受了 %d 个新连接\n", accept_count);
                fflush(stdout);
            } else {
                printf("[EPOLL] 未知的文件描述符上有事件: fd=%d\n", events[n].data.fd);
                fflush(stdout);
            }
        }
        
        printf("[EPOLL] 所有事件处理完毕，继续等待...\n\n");
        fflush(stdout);
    }
    
    close(epoll_fd);
    close(server_fd);
    return 0;
}

