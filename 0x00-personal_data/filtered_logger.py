#!/usr/bin/env python3
"""
This module contains functions for obfuscating sensitive data in log messages.
"""

import re
from typing import List

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
