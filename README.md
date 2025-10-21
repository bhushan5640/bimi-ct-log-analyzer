# BIMI CT Certificate Analyzer

A security analytics tool for analyzing BIMI (Brand Indicators for Message Identification) certificates from Certificate Transparency logs. This tool detects suspicious patterns, lookalike brands, obfuscation techniques, and other security issues in BIMI certificates.

## Features

- **Suspicious SVG Pattern Detection**: Identifies JavaScript injection, hidden content, and foreign objects
- **Unicode Homograph Detection**: Detects lookalike characters and script mixing attacks
- **Lookalike Brand Detection**: Identifies potential brand impersonation attempts
- **Hidden Content Analysis**: Finds invisible or zero-sized elements in SVG logos
- **Obfuscation Detection**: Detects zero-width characters and bidirectional text overrides
- **URL Analysis**: Extracts and reports suspicious URLs in SVG content
- **Oversized Logo Detection**: Identifies unusually large logos that may contain hidden payloads
- **Brand Name Validation**: Checks if brand names appear in SVG title elements

## Requirements

- Java 21 or higher
- Maven 3.6+
- Database with BIMI certificate data (PostgreSQL, MySQL, etc.)
