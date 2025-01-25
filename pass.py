import re
import math
import hashlib
import requests
import os
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# Initialize the rich console
console = Console()

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
    """Check if a password has been exposed in data breaches using HaveIBeenPwned API."""
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
    # Title Panel
    console.print(Panel(Text("PASSWORD STRENGTH CHECKER", style="bold cyan"), style="bold blue"))

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
        feedback.append(f"[red]Password should be at least {rules['min_length']} characters long.[/red]")
        enhanced_feedback.append(f"[yellow]Try adding {rules['min_length'] - len(password)} more characters to increase length.[/yellow]")
    else:
        score += 1

    if not rules["uppercase"].search(password):
        feedback.append("[red]Add at least one uppercase letter.[/red]")
        enhanced_feedback.append("[yellow]Consider adding an uppercase letter, e.g., 'A'.[/yellow]")
    else:
        score += 1

    if not rules["lowercase"].search(password):
        feedback.append("[red]Add at least one lowercase letter.[/red]")
        enhanced_feedback.append("[yellow]Try adding a lowercase letter, e.g., 'a'.[/yellow]")
    else:
        score += 1

    if not rules["numbers"].search(password):
        feedback.append("[red]Add at least one number.[/red]")
        enhanced_feedback.append("[yellow]Include a number, e.g., '7' or '4'.[/yellow]")
    else:
        score += 1

    if not rules["special_characters"].search(password):
        feedback.append("[red]Add at least one special character (e.g., !@#$%).[/red]")
        enhanced_feedback.append("[yellow]Add a special character, e.g., '!'.[/yellow]")
    else:
        score += 1

    # Check against common passwords
    if password in common_passwords:
        feedback.append("[red]This password has been flagged as commonly used. Avoid it![/red]")
        enhanced_feedback.append("[yellow]Use a unique password that isn't commonly used.[/yellow]")

    # Calculate entropy
    entropy = calculate_entropy(password)
    if entropy < 50:
        feedback.append("[red]Increase password length and complexity to improve entropy.[/red]")
        enhanced_feedback.append("[yellow]Combine uppercase, lowercase, numbers, and special characters to improve entropy.[/yellow]")

    # Check against breaches
    try:
        breach_count = check_pwned_api(password)
        if breach_count > 0:
            feedback.append(f"[red]This password has been found in {breach_count} breaches. Do not use it.[/red]")
        else:
            feedback.append("[green]Good news! This password has not been found in any known breaches.[/green]")
    except ConnectionError:
        feedback.append("[yellow]Unable to check for data breaches. Please ensure your password is unique.[/yellow]")

    # Determine strength and categorization
    if score == 5 and entropy >= 70:
        strength = "Very Strong"
        category = "[green]This password is highly secure. It meets all criteria and has high entropy.[/green]"
    elif score >= 4 and entropy >= 50:
        strength = "Strong"
        category = "[yellow]This password is secure but can still be improved with additional complexity.[/yellow]"
    elif score >= 3:
        strength = "Moderate"
        category = "[orange3]This password is moderately secure but lacks certain important criteria.[/orange3]"
    else:
        strength = "Weak"
        category = "[red]This password is insecure. It does not meet basic requirements and should not be used.[/red]"

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
        password = console.input("\n[cyan]Enter a password to check its strength (or type 'exit' to quit): [/cyan]")
        if password.lower() == "exit":
            console.print("[green]Exiting Password Strength Checker. Stay secure![/green]")
            break

        # Check password
        result = advanced_password_checker(password, common_passwords)

        # Display results using `rich`
        console.print(f"\nPassword Strength: [bold]{result['strength']}[/bold]", style="cyan")
        console.print(f"Password Entropy: [bold]{result['entropy']:.2f} bits[/bold]", style="cyan")
        console.print(Panel(result["category"], style="bold"))

        if result["feedback"]:
            console.print("\n[bold magenta]General Suggestions to improve your password:[/bold magenta]")
            for suggestion in result["feedback"]:
                console.print(f"- {suggestion}")

        if result["enhanced_feedback"]:
            console.print("\n[bold magenta]Enhanced Suggestions:[/bold magenta]")
            for suggestion in result["enhanced_feedback"]:
             console.print(f"- {suggestion}")


        # Save weak passwords to the common list for tracking
        if result["strength"] in ["Weak", "Moderate"]:
            if password not in common_passwords:
                save_common_password(password)
                console.print("[yellow]Password has been added to the common passwords list.[/yellow]")

        # Lockout after 3 weak attempts
        attempts += 1 if result["strength"] == "Weak" else 0
        if attempts >= 3:
            console.print("\n[red]Too many weak password attempts. Please wait 10 seconds before trying again.[/red]")
            time.sleep(10)
            attempts = 0

if __name__ == "__main__":
    main()
