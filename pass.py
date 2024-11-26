import re
import math
import hashlib
import requests
import os
import time

# Path to the common passwords file
COMMON_PASSWORDS_FILE = "common_passwords.txt"

def load_common_passwords():
    """Load common passwords from a file."""
    if not os.path.exists(COMMON_PASSWORDS_FILE):
        return set()
    with open(COMMON_PASSWORDS_FILE, "r") as file:
        return set(file.read().splitlines())

def save_common_password(password):
    """Add a password to the common passwords file."""
    with open(COMMON_PASSWORDS_FILE, "a") as file:
        file.write(password + "\n")

def calculate_entropy(password):
    """Calculate password entropy."""
    char_space = 0
    if re.search(r"[a-z]", password):
        char_space += 26
    if re.search(r"[A-Z]", password):
        char_space += 26
    if re.search(r"\d", password):
        char_space += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        char_space += 32
    if re.search(r"\s", password):
        char_space += 1
    return len(password) * math.log2(char_space) if char_space > 0 else 0

def check_pwned_api(password):
    """
    Check if a password has been exposed in data breaches using HaveIBeenPwned API.
    Returns the breach count if found, or 0 otherwise.
    """
    hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = hashed_password[:5]
    suffix = hashed_password[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code == 200:
        hashes = response.text.splitlines()
        for line in hashes:
            hash_suffix, count = line.split(":")
            if suffix == hash_suffix:
                return int(count)
        return 0
    else:
        raise ConnectionError("Unable to connect to HaveIBeenPwned API.")

def advanced_password_checker(password, common_passwords):
    # Print title
    print("\n" + "=" * 50)
    print("          \033[1m\033[34mPASSWORD STRENGTH CHECKER\033[0m          ")
    print("=" * 50 + "\n")
    
    # Password rules
    rules = {
        "min_length": 12,
        "uppercase": re.compile(r"[A-Z]"),
        "lowercase": re.compile(r"[a-z]"),
        "numbers": re.compile(r"\d"),
        "special_characters": re.compile(r"[!@#$%^&*(),.?\":{}|<>]")
    }
    
    feedback = []
    enhanced_feedback = []
    score = 0

    if len(password) < rules["min_length"]:
        feedback.append(f"Password should be at least {rules['min_length']} characters long.")
        enhanced_feedback.append(f"Try adding {rules['min_length'] - len(password)} more characters to increase length.")
    else:
        score += 1

    if not rules["uppercase"].search(password):
        feedback.append("Add at least one uppercase letter.")
        enhanced_feedback.append("Consider adding an uppercase letter, e.g., 'A'.")
    else:
        score += 1

    if not rules["lowercase"].search(password):
        feedback.append("Add at least one lowercase letter.")
        enhanced_feedback.append("Try adding a lowercase letter, e.g., 'a'.")
    else:
        score += 1

    if not rules["numbers"].search(password):
        feedback.append("Add at least one number.")
        enhanced_feedback.append("Include a number, e.g., '7' or '4'.")
    else:
        score += 1

    if not rules["special_characters"].search(password):
        feedback.append("Add at least one special character (e.g., !@#$%).")
        enhanced_feedback.append("Add a special character, e.g., '!'.")
    else:
        score += 1

    # Check against common passwords
    if password in common_passwords:
        feedback.append("This password has been flagged as commonly used. Avoid it!")
        enhanced_feedback.append("Use a unique password that isn't commonly used.")

    # Calculate entropy
    entropy = calculate_entropy(password)
    if entropy < 50:
        feedback.append("Increase password length and complexity to improve entropy.")
        enhanced_feedback.append("Combine uppercase, lowercase, numbers, and special characters to improve entropy.")

    # Check against breaches
    try:
        breach_count = check_pwned_api(password)
        if breach_count > 0:
            feedback.append(f"This password has been found in {breach_count} breaches. Do not use it.")
           
        else:
            feedback.append("Good news! This password has not been found in any known breaches.")
    except ConnectionError:
        feedback.append("Unable to check for data breaches. Please ensure your password is unique.")
        enhanced_feedback.append("Consider manually ensuring your password is not reused.")

    # Determine strength and categorization
    if score == 5 and entropy >= 70:
        strength = "Very Strong"
        category = "This password is highly secure. It meets all criteria and has high entropy."
    elif score >= 4 and entropy >= 50:
        strength = "Strong"
        category = "This password is secure but can still be improved with additional complexity."
    elif score >= 3:
        strength = "Moderate"
        category = "This password is moderately secure but lacks certain important criteria."
    else:
        strength = "Weak"
        category = "This password is insecure. It does not meet basic requirements and should not be used."

    return {
        "strength": strength,
        "entropy": entropy,
        "feedback": feedback,
        "enhanced_feedback": enhanced_feedback,
        "category": category
    }

# Main logic
def main():
    # Load common passwords
    common_passwords = load_common_passwords()

    # Input loop
    attempts = 0
    while True:
        password = input("\nEnter a password to check its strength (or type 'exit' to quit): ")
        if password.lower() == "exit":
            print("Exiting Password Strength Checker. Stay secure!")
            break

        # Check password
        result = advanced_password_checker(password, common_passwords)

        # Display results
        print(f"\nPassword Strength: \033[1m{result['strength']}\033[0m")
        print(f"Password Entropy: \033[1m{result['entropy']:.2f} bits\033[0m")
        print(f"\nCategory: {result['category']}")
        
        if result["feedback"]:
            print("\nGeneral Suggestions to improve your password:")
            for suggestion in result["feedback"]:
                print(f"- {suggestion}")
        
        if result["enhanced_feedback"]:
            print("\nEnhanced Suggestions:")
            for suggestion in result["enhanced_feedback"]:
                print(f"- {suggestion}")

        # Save weak passwords to the common list for tracking
        if result["strength"] in ["Weak", "Moderate"]:
            if password not in common_passwords:
                save_common_password(password)
                print("Password has been added to the common passwords list.")
        
        # Lockout after 3 weak attempts
        attempts += 1 if result["strength"] == "Weak" else 0
        if attempts >= 3:
            print("\nToo many weak password attempts. Please wait 10 seconds before trying again.")
            time.sleep(10)
            attempts = 0

if __name__ == "__main__":
    main()
