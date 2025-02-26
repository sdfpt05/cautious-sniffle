import hashlib
import requests
import re
import string
import secrets

class PasswordBreachChecker:
    """
    Checks if a password has been exposed in data breaches using the Have I Been Pwned API
    Uses the k-anonymity model to safely check passwords
    """
    API_URL = "https://api.pwnedpasswords.com/range/"
    
    @staticmethod
    def check_password(password):
        """
        Checks if a password has been exposed in known data breaches
        Returns the number of times the password appears in breaches (0 if safe)
        """
        # Hash the password with SHA-1
        password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Split the hash into prefix and suffix for k-anonymity
        hash_prefix = password_hash[:5]
        hash_suffix = password_hash[5:]
        
        try:
            # Request breached hashes with the same prefix
            response = requests.get(PasswordBreachChecker.API_URL + hash_prefix, timeout=3)
            if response.status_code != 200:
                # If the request fails, assume the password might be breached
                return -1
            
            # Check if our hash suffix is in the response
            for line in response.text.splitlines():
                suffix, count = line.split(':')
                if suffix == hash_suffix:
                    return int(count)
            
            # Password not found in breaches
            return 0
        except requests.RequestException:
            # Handle connection errors or timeouts
            return -1


class PasswordValidator:
    """
    Validates password strength and generates strong passwords
    """
    
    @staticmethod
    def validate_password(password):
        """
        Validates a password strength and returns a tuple (is_valid, message)
        """
        if len(password) < 12:
            return False, "Password must be at least 12 characters long"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        # Check if password has common patterns
        if re.search(r'(12345|qwerty|password|admin|welcome)', password.lower()):
            return False, "Password contains common patterns"
        
        # Check for consecutive repeated characters
        if re.search(r'(.)\1{3,}', password):
            return False, "Password contains too many repeated characters"
        
        # Check for sequential characters
        sequences = ['abcdefghijklmnopqrstuvwxyz', '0123456789']
        for seq in sequences:
            for i in range(len(seq) - 3):
                if seq[i:i+4].lower() in password.lower():
                    return False, "Password contains sequential characters"
        
        # Check if password has been breached
        breach_count = PasswordBreachChecker.check_password(password)
        if breach_count > 0:
            return False, f"This password appears in data breaches {breach_count} times! Please choose a different password."
        elif breach_count == -1:
            # If the API check failed, we'll still validate the password
            return True, "Password is strong (breach check unavailable)"
        
        return True, "Password is strong"
    
    
    @staticmethod
    def generate_password(length=16, include_uppercase=True, include_lowercase=True, 
                          include_digits=True, include_symbols=True):
        """
        Generates a strong random password of the specified length
        """
        if length < 12:
            length = 12
        
        # Define character sets
        lowercase_chars = string.ascii_lowercase
        uppercase_chars = string.ascii_uppercase
        digit_chars = string.digits
        symbol_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Build the character set based on inclusion flags
        charset = ""
        if include_lowercase:
            charset += lowercase_chars
        if include_uppercase:
            charset += uppercase_chars
        if include_digits:
            charset += digit_chars
        if include_symbols:
            charset += symbol_chars
        
        # Ensure we have a non-empty charset
        if not charset:
            charset = lowercase_chars + uppercase_chars + digit_chars + symbol_chars
        
        # Generate password
        while True:
            password = ''.join(secrets.choice(charset) for _ in range(length))
            
            # Check if password meets complexity requirements
            has_lowercase = any(c in lowercase_chars for c in password) if include_lowercase else True
            has_uppercase = any(c in uppercase_chars for c in password) if include_uppercase else True
            has_digit = any(c in digit_chars for c in password) if include_digits else True
            has_symbol = any(c in symbol_chars for c in password) if include_symbols else True
            
            if has_lowercase and has_uppercase and has_digit and has_symbol:
                # Check if password is in breach database
                breach_count = PasswordBreachChecker.check_password(password)
                if breach_count == 0:
                    return password