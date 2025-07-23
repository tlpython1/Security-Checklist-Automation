#!/bin/bash

# Security Checklist Automation - Server Startup Script
# This script activates the virtual environment and starts the FastAPI server

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${BLUE}🚀 Security Checklist Automation Server Startup${NC}"
echo -e "${BLUE}================================================${NC}"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}⚠️  Virtual environment not found. Creating one...${NC}"
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Failed to create virtual environment${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Virtual environment created successfully${NC}"
fi

# Activate virtual environment
echo -e "${BLUE}📦 Activating virtual environment...${NC}"
source venv/bin/activate

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to activate virtual environment${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Virtual environment activated${NC}"

# Check if requirements are installed
echo -e "${BLUE}📋 Checking dependencies...${NC}"
python -c "import fastapi, uvicorn" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}⚠️  Dependencies not found. Installing from requirements.txt...${NC}"
    
    if [ ! -f "requirements.txt" ]; then
        echo -e "${RED}❌ requirements.txt not found${NC}"
        exit 1
    fi
    
    pip install --upgrade pip
    pip install -r requirements.txt
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Failed to install dependencies${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Dependencies installed successfully${NC}"
else
    echo -e "${GREEN}✅ Dependencies are already installed${NC}"
fi

# Change to app directory
cd app

# Check if main.py exists
if [ ! -f "main.py" ]; then
    echo -e "${RED}❌ main.py not found in app directory${NC}"
    exit 1
fi

# Display server information
echo -e "${BLUE}🌐 Server Configuration:${NC}"
echo -e "   Host: ${GREEN}0.0.0.0${NC}"
echo -e "   Port: ${GREEN}8081${NC}"
echo -e "   URL:  ${GREEN}http://localhost:8081${NC}"
echo -e "   Docs: ${GREEN}http://localhost:8081/docs${NC}"
echo ""

# Start the FastAPI server
echo -e "${BLUE}🚀 Starting FastAPI server...${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop the server${NC}"
echo ""

uvicorn main:app --reload --host 0.0.0.0 --port 8081

# Deactivate virtual environment when server stops
echo -e "${BLUE}🛑 Server stopped. Deactivating virtual environment...${NC}"
deactivate
echo -e "${GREEN}✅ Cleanup completed${NC}"
