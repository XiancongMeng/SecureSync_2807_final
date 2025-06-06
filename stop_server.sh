#!/bin/bash

# 设置颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}====== 停止 SecureSync 服务组件 ======${NC}"

# 停止文件接收服务器
echo -e "${YELLOW}停止文件接收服务器...${NC}"
RECEIVE_PIDS=$(pgrep -f "receive_file" 2>/dev/null)
if [ -n "$RECEIVE_PIDS" ]; then
    echo -e "${GREEN}找到进程: $RECEIVE_PIDS${NC}"
    pkill -f "receive_file"
    sleep 1
    if pgrep -f "receive_file" > /dev/null; then
        echo -e "${RED}无法正常停止，尝试强制终止...${NC}"
        pkill -9 -f "receive_file"
    fi
    echo -e "${GREEN}文件接收服务器已停止${NC}"
else
    echo -e "${YELLOW}文件接收服务器未运行${NC}"
fi

# 停止登录验证服务器
echo -e "${YELLOW}停止登录验证服务器...${NC}"
LOGIN_PIDS=$(pgrep -f "server_login" 2>/dev/null)
if [ -n "$LOGIN_PIDS" ]; then
    echo -e "${GREEN}找到进程: $LOGIN_PIDS${NC}"
    pkill -f "server_login"
    sleep 1
    if pgrep -f "server_login" > /dev/null; then
        echo -e "${RED}无法正常停止，尝试强制终止...${NC}"
        pkill -9 -f "server_login"
    fi
    echo -e "${GREEN}登录验证服务器已停止${NC}"
else
    echo -e "${YELLOW}登录验证服务器未运行${NC}"
fi

echo -e "${GREEN}所有服务已停止${NC}"
echo -e "${YELLOW}=============================${NC}"
