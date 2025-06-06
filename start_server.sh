#!/bin/bash

# 设置颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}====== 启动 SecureSync 服务组件 ======${NC}"

# 确保工作目录正确
cd "$(dirname "$0")"

# 检查服务器可执行文件是否存在
if [ ! -f "server/receive_file" ] || [ ! -f "server/server_login" ]; then
    echo -e "${RED}服务器组件未编译，正在编译...${NC}"
    
    # 进入server目录
    cd server
    
    # 编译所有服务器组件
    echo -e "${YELLOW}编译 receive_file...${NC}"
    gcc -o receive_file receive_file.c -lcrypto -lsqlite3
    
    echo -e "${YELLOW}编译 server_login...${NC}"
    gcc -o server_login server_login.c -lcrypto -lsqlite3
    
    echo -e "${YELLOW}编译 register_user...${NC}"
    gcc -o register_user register_user.c -lcrypto -lsqlite3
    
    echo -e "${YELLOW}编译 verify_user...${NC}"
    gcc -o verify_user verify_user.c -lcrypto -lsqlite3
    
    cd ..
fi

# 检查数据目录是否存在
if [ ! -d "data" ]; then
    echo -e "${YELLOW}创建数据目录...${NC}"
    mkdir -p data
fi

# 检查日志目录是否存在
if [ ! -d "logs" ]; then
    echo -e "${YELLOW}创建日志目录...${NC}"
    mkdir -p logs
fi

# 检查数据库是否存在
if [ ! -f "data/users.db" ]; then
    echo -e "${YELLOW}初始化数据库...${NC}"
    if [ -f "server/init_db" ]; then
        ./server/init_db
    else
        echo -e "${RED}未找到init_db，正在编译...${NC}"
        cd server
        gcc -o init_db init_db.c -lsqlite3
        cd ..
        ./server/init_db
    fi
fi

# 定义日志文件
LOG_DIR="logs"
RECEIVE_LOG="$LOG_DIR/receive_file.log"
LOGIN_LOG="$LOG_DIR/server_login.log"

# 停止已经运行的进程
echo -e "${YELLOW}检查并停止已运行的服务...${NC}"
pkill -f "receive_file" 2>/dev/null
pkill -f "server_login" 2>/dev/null
sleep 1

# 启动文件接收服务器
echo -e "${YELLOW}启动文件接收服务器...${NC}"
./server/receive_file > "$RECEIVE_LOG" 2>&1 &
RECEIVE_PID=$!

# 启动登录验证服务器
echo -e "${YELLOW}启动登录验证服务器...${NC}"
./server/server_login > "$LOGIN_LOG" 2>&1 &
LOGIN_PID=$!

# 等待服务器启动
sleep 2

# 检查服务器是否成功启动
if ps -p $RECEIVE_PID > /dev/null; then
    echo -e "${GREEN}文件接收服务器已启动 (PID: $RECEIVE_PID)${NC}"
else
    echo -e "${RED}文件接收服务器启动失败，请检查日志: $RECEIVE_LOG${NC}"
    tail -n 10 "$RECEIVE_LOG"
fi

if ps -p $LOGIN_PID > /dev/null; then
    echo -e "${GREEN}登录验证服务器已启动 (PID: $LOGIN_PID)${NC}"
else
    echo -e "${RED}登录验证服务器启动失败，请检查日志: $LOGIN_LOG${NC}"
    tail -n 10 "$LOGIN_LOG"
fi

echo -e "${GREEN}所有服务已启动，现在可以运行客户端了${NC}"
echo -e "${YELLOW}日志文件位置:${NC}"
echo -e "  文件接收服务器: $RECEIVE_LOG"
echo -e "  登录验证服务器: $LOGIN_LOG"
echo -e "${YELLOW}=============================${NC}"
