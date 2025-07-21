# logger.py
from loguru import logger
import sys
import os

# Create logs directory if not exists
os.makedirs("logs", exist_ok=True)

logger.remove()  # Remove default
logger.add(sys.stdout, level="INFO", colorize=True, format="<green>{time}</green> <level>{message}</level>")
logger.add("logs/server_scan_{time}.log", rotation="500 KB", retention="10 days", level="DEBUG")
