import logging
import sys

def get_logger(name: str) -> logging.Logger:
    """
    Configure and return a logger.
    This logger will output INFO level and above logs to console,
    and write DEBUG level and above logs to 'workflow.log' file.
    """
    # Create a logger
    logger = logging.getLogger(name)
    
    # Prevent duplicate handler addition
    if logger.hasHandlers():
        return logger
        
    logger.setLevel(logging.DEBUG)  # Set minimum level for logger to process

    # --- Console Handler ---
    # This handler is responsible for printing logs to screen
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)  # Console only shows INFO, WARNING, ERROR, CRITICAL
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # --- File Handler ---
    # This handler is responsible for writing logs to file
    file_handler = logging.FileHandler('workflow.log', mode='a', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)  # File records all level logs (DEBUG, INFO, etc.)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger