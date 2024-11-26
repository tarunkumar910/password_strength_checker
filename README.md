<div align="center">
    <h2 style="font-weight: bold; color: green;">Password Strength: Very Strong</h2>
</div>


A comprehensive and secure password strength checker that evaluates the strength of a password based on multiple factors such as length, complexity, entropy, common usage, and data breaches. This tool helps users create stronger passwords by providing detailed feedback and actionable suggestions.

---

## Features

- **Password Length Check**: Ensures the password is of adequate length (at least 12 characters).
- **Character Variety**: Checks for a mix of uppercase letters, lowercase letters, digits, and special characters.
- **Entropy Calculation**: Calculates password entropy to measure its randomness and complexity.
- **Common Password Check**: Alerts users if their password is among commonly used passwords.
- **Breach Check**: Checks if the password has been exposed in data breaches via the HaveIBeenPwned API.
- **Enhanced Feedback**: Provides detailed suggestions for improving weak passwords.
- **Auto Save Weak Passwords**: Tracks and saves weak or moderate passwords to a common passwords file for monitoring.

---

## Installation

### Prerequisites
To use this password checker, you will need:
- Python 3.x (Python 3.6 or above recommended)
- Access to the internet for breach checking (uses HaveIBeenPwned API)

### Step 1: Clone the repository
```bash
git clone https://github.com/yourusername/password-strength-checker.git
cd password-strength-checker
