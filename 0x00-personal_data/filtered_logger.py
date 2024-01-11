#!/usr/bin/env python3
"""
Filter
"""
from typing import List
import re
import logging
import os
import mysql.connector


PERSONALLY_IDENTIFIABLE_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


def redact_data(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """
    Redact sensitive data in the message.
    """
    for field in fields:
        message = re.sub(field + '=.*?' + separator, field +
                         '=' + redaction + separator, message)
    return message


class RedactingFormatter(logging.Formatter):
    """ Custom log formatter to redact sensitive information. """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, sensitive_fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.sensitive_fields = sensitive_fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log message with redacted sensitive data.
        """
        message = super(RedactingFormatter, self).format(record)
        redacted_message = redact_data(
            self.sensitive_fields, self.REDACTION, message, self.SEPARATOR)
        return redacted_message


def get_logger() -> logging.Logger:
    """
    Get a configured logger with redacting formatter.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()

    formatter = RedactingFormatter(PERSONALLY_IDENTIFIABLE_FIELDS)

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def get_database_connection() -> mysql.connector.connection.MySQLConnection:
    """
    Get a connection to the database.
    """
    user = os.getenv('PERSONAL_DATA_DB_USERNAME') or "root"
    password = os.getenv('PERSONAL_DATA_DB_PASSWORD') or ""
    host = os.getenv('PERSONAL_DATA_DB_HOST') or "localhost"
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')
    connection = mysql.connector.connect(
        user=user, password=password, host=host, database=db_name)
    return connection


def main():
    """
    Main entry point.
    """
    db_connection = get_database_connection()
    logger = get_logger()
    cursor = db_connection.cursor()
    cursor.execute("SELECT * FROM users;")
    column_names = cursor.column_names
    for row in cursor:
        message = "".join("{}={}; ".format(key, value)
                          for key, value in zip(column_names, row))
        logger.info(message.strip())
    cursor.close()
    db_connection.close()


if __name__ == "__main__":
    main()
