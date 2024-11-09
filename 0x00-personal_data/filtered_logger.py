#!/usr/bin/env python3
"""
This module contains functions for obfuscating sensitive data in log messages.
"""

import re
import logging
import os
import mysql.connector
from typing import List



PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def replace_with_redaction(redaction: str):
    """
    Returns a function that replaces the matched group with the redacted string.

    Args:
        redaction (str): The replacement text.

    Returns:
        function: A function to be used in re.sub.
    """
    def replacer(match):
        return match.group(1) + redaction if match.group(1) else ''
    return replacer


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """
    Obfuscates specified fields in a log message.

    Args:
        fields (List[str]): Fields to obfuscate.
        redaction (str): Replacement string for obfuscated fields.
        message (str): Log message to process.
        separator (str): Field separator in the log message.

    Returns:
        str: The obfuscated log message.
    """
    pattern = '|'.join([f"({field}=)([^{separator}]*)" for field in fields])
    return re.sub(pattern, replace_with_redaction(redaction), message)
  
class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """
    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initialize the formatter with fields to be redacted.
        
        Args:
            fields (List[str]): Fields that should be redacted in log messages.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Formats the log record, redacting sensitive information in specified fields.
        
        Args:
            record (logging.LogRecord): The log record to be formatted.
        
        Returns:
            str: The formatted log message with sensitive information redacted.
        """
        record.msg = filter_datum(self.fields, self.REDACTION, record.msg, self.SEPARATOR)
        return super().format(record)

def get_logger() -> logging.Logger:
    """
    Creates and configures a logger for user data with sensitive fields redacted.

    Returns:
        logging.Logger: Configured logger instance for user data.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(fields=PII_FIELDS))
    logger.addHandler(handler)

    return logger
  
def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Connects to a MySQL database using credentials from environment variables.
    
    Returns:
        mysql.connector.connection.MySQLConnection: Database connection object.
    """
    username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    database = os.getenv("PERSONAL_DATA_DB_NAME")

    connection = mysql.connector.connect(
        user=username,
        password=password,
        host=host,
        database=database
    )
    return connection
  
def main() -> None:
    """
    Main function that fetches all rows from the users table and logs each row with sensitive
    fields redacted.
    """
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM users;")
    columns = [desc[0] for desc in cursor.description]
    logger = get_logger()

    for row in cursor:
        message = "; ".join(f"{col}={val}" for col, val in zip(columns, row))
        logger.info(message)

    cursor.close()
    db.close()

if __name__ == "__main__":
    main()
    