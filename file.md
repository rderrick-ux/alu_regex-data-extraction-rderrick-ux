## 📋 Overview

This project extracts and validates structured data from unstructured text, with built-in security measures to handle hostile or malformed input.

## 🎯 Extracted Data Types

1. **Phone Numbers** - Various formats: (123) 456-7890, 123-456-7890, +1-555-123-4567
2. **Credit Card Numbers** - 16-digit cards with validation via Luhn algorithm
3. **Hashtags** - Social media style tags: #Example, #ThisIsAHashtag
4. **Currency Amounts** - USD format: $19.99, $1,234.56

## 🔒 Security Features

### Input Sanitization
- **XSS Prevention**: Strips `<script>` tags and `javascript:` protocols
- **Injection Protection**: Removes SQL injection patterns

### Data Protection
- **Credit Card Masking**: Displays only last 4 digits (e.g., ************6467)
- **No PII Logging**: Sensitive data never logged in plaintext

### Pattern Filtering
- Rejects obvious false positives (e.g., all-zero phone numbers)
- Validates data format before inclusion in results
