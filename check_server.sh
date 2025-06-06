#!/bin/bash

# 设置颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}====== SecureSync 服务状态检查 ======${NC}"

# 检查文件接收服务器
echo -e "${YELLOW}检查文件接收服务器...${NC}"
RECEIVE_PIDS=$(pgrep -f "receive_file" 2>/dev/null)
if [ -n "$RECEIVE_PIDS" ]; then
    echo -e "${GREEN}文件接收服务器正在运行:${NC}"
    ps -p $RECEIVE_PIDS -o pid,ppid,user,stat,start,time,command
else
    echo -e "${RED}文件接收服务器未运行${NC}"
fi

echo ""

# 检查登录验证服务器
echo -e "${YELLOW}检查登录验证服务器...${NC}"
LOGIN_PIDS=$(pgrep -f "server_login" 2>/dev/null)
if [ -n "$LOGIN_PIDS" ]; then
    echo -e "${GREEN}登录验证服务器正在运行:${NC}"
    ps -p $LOGIN_PIDS -o pid,ppid,user,stat,start,time,command
else
    echo -e "${RED}登录验证服务器未运行${NC}"
fi

echo ""

# 检查网络端口
echo -e "${YELLOW}检查网络端口...${NC}"
echo -e "${YELLOW}文件服务端口 (8081):${NC}"
netstat -tuln | grep 8081 || echo -e "${RED}端口未开放${NC}"

echo -e "${YELLOW}登录服务端口 (8080):${NC}"
netstat -tuln | grep 8080 || echo -e "${RED}端口未开放${NC}"

echo ""

# 检查日志文件
echo -e "${YELLOW}检查日志文件...${NC}"
LOG_DIR="logs"
RECEIVE_LOG="$LOG_DIR/receive_file.log"
LOGIN_LOG="$LOG_DIR/server_login.log"

if [ -f "$RECEIVE_LOG" ]; then
    echo -e "${GREEN}文件接收服务器日志 (最后5行):${NC}"
    tail -n 5 "$RECEIVE_LOG"
else
    echo -e "${RED}文件接收服务器日志不存在${NC}"
fi

echo ""

if [ -f "$LOGIN_LOG" ]; then
    echo -e "${GREEN}登录验证服务器日志 (最后5行):${NC}"
    tail -n 5 "$LOGIN_LOG"
else
    echo -e "${RED}登录验证服务器日志不存在${NC}"
fi

echo -e "${YELLOW}=============================${NC}"
