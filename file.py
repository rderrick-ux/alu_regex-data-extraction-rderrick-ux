#!/usr/bin/env python3
"""
Secure Data Extraction and Validation System
Extracts phone numbers, credit cards, hashtags, and currency amounts
"""

import re
import json

class SecureDataExtractor:
    def __init__(self):
        # Regex patterns with realistic variation support
        self.patterns = {
            'phone': r'\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b',
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'hashtag': r'#[A-Za-z][A-Za-z0-9_]*\b',
            'currency': r'\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?'
        }
        
    def sanitize_input(self, text):
        """Security: Remove script tags and limit input size"""
        if len(text) > 10000:  # Prevent DoS via large input
            raise ValueError("Input exceeds maximum length")
        # Remove potential XSS/injection patterns
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
        return text
    
    def mask_sensitive(self, data_type, value):
        """Security: Mask sensitive data in output"""
        if data_type == 'credit_card':
            return re.sub(r'\d', '*', value[:-4]) + value[-4:]
        return value
    
    def validate_credit_card(self, number):
        """Luhn algorithm for credit card validation"""
        digits = [int(d) for d in re.sub(r'\D', '', number)]
        checksum = sum(digits[-1::-2]) + sum(sum(divmod(2*d, 10)) for d in digits[-2::-2])
        return checksum % 10 == 0
    
    def extract(self, text):
        """Extract and validate data from text"""
        text = self.sanitize_input(text)
        results = {}
        
        for dtype, pattern in self.patterns.items():
            matches = re.findall(pattern, text)
            
            # Additional validation
            if dtype == 'credit_card':
                matches = [m for m in matches if self.validate_credit_card(m)]
                matches = [self.mask_sensitive(dtype, m) for m in matches]
            elif dtype == 'phone':
                # Filter out obvious false positives (e.g., all zeros)
                matches = [m for m in matches if not re.match(r'^[0\s\-\.\(\)]+$', m)]
            
            results[dtype] = matches if matches else []
        
        return results

def main():
    """Main execution function"""
    # Read from sample_input.txt or use embedded sample
    try:
        with open('sample_input.txt', 'r') as f:
            sample_input = f.read()
    except FileNotFoundError:
        sample_input = """
Customer Transaction Report - Jan 2026

Contact: Support team at +1 (555) 123-4567 or 555.987.6543
Emergency line: 1-800-555-0199

Payment Methods:
- Visa ending in 5432: 4532 1488 0343 6467
- Mastercard: 5425-2334-3010-9903
- Invalid: 1234 5678 9012 3456 (declined)

Transactions:
#PaymentProcessed - Amount: $1,234.56
#RefundIssued - Amount: $89.99
Subscription renewal: $49.00 monthly #Recurring
Special offer: Save $299.95 today! #LimitedTime

Note: Call 123-456-7890 for disputes.
Suspicious activity flagged: <script>alert('xss')</script>
Encoded card attempt: 4111%201111%201111%201111
"""
    
    # Execute extraction
    extractor = SecureDataExtractor()
    results = extractor.extract(sample_input)
    
    # Display results
    print("="*60)
    print("SECURE DATA EXTRACTION RESULTS")
    print("="*60)
    print(json.dumps(results, indent=2))
    print("\n" + "="*60)
    print(f"[Security] Processed {len(sample_input)} characters safely")
    print(f"[Security] Credit card data masked for protection")
    print("="*60)
    
    # Save to output file
    with open('sample_output.json', 'w') as f:
        json.dump(results, f, indent=2)
    print("\n✓ Results saved to sample_output.json")

if __name__ == "__main__":
    main()
