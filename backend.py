#!/usr/bin/env python3
"""
Simple Password Security Checker

This program checks a password for:
1. Basic length requirements
2. Known compromised passwords
3. Common patterns
4. Sequences such as abcd or 1234
5. Repeated characters such as aaaa
6. Username/email words inside the password

The program keeps standards-based checks separate from our own
password-strength checks.

Optional package:
    requests

Install it with:
    pip install requests
"""

import getpass
import hashlib
import re

# The online password check uses this address.
HIBP_URL = "https://api.pwnedpasswords.com/range/{}"

# Small local list used only when the online check cannot be used.
# Being absent from this list does NOT mean the password is safe.
COMMON_PASSWORDS = {
    "123456",
    "123456789",
    "12345678",
    "12345",
    "password",
    "password1",
    "password123",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "administrator",
    "welcome",
    "welcome1",
    "letmein",
    "monkey",
    "dragon",
    "master",
    "login",
    "princess",
    "football",
    "baseball",
    "soccer",
    "hello",
    "love",
    "shadow",
    "sunshine",
    "passw0rd",
    "trustno1",
    "superman",
    "michael",
    "jennifer",
    "hunter",
    "starwars",
    "ninja",
    "batman",
    "abc123",
    "secret",
    "donald",
    "asdfghjkl",
    "zxcvbnm",
    "1qaz2wsx",
}

# Words that are very commonly used in passwords.
COMMON_WORDS = {
    "password",
    "passwd",
    "pass",
    "admin",
    "administrator",
    "login",
    "user",
    "account",
    "email",
    "mail",
    "secure",
    "secret",
    "welcome",
    "qwerty",
    "letmein",
}

KEYBOARD_ROWS = (
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
NUMBERS = "0123456789"


def get_hibp_status(password, timeout=5):
    """
    Check whether a password appears in the online compromised-password list.

    Returns:
        "found"      -> password was found
        "not_found"  -> password was not found
        "unknown"    -> we could not check
    """
    try:
        import requests
    except ImportError:
        if password.lower() in COMMON_PASSWORDS:
            return {
                "status": "found",
                "count": 0,
                "source": "local list",
                "message": "Matched the local common-password list.",
            }

        return {
            "status": "unknown",
            "count": 0,
            "source": "local list",
            "message": "The requests package is not installed.",
        }

    # Create the hash locally.
    password_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    # Only part of the hash is used for the online request.
    prefix = password_hash[:5]
    suffix = password_hash[5:]

    try:
        response = requests.get(
            HIBP_URL.format(prefix),
            headers={
                "Add-Padding": "true",
                "User-Agent": "simple-password-checker",
            },
            timeout=timeout,
        )

        response.raise_for_status()

    except requests.RequestException as error:
        if password.lower() in COMMON_PASSWORDS:
            return {
                "status": "found",
                "count": 0,
                "source": "local list",
                "message": "Online check failed, but the local list matched.",
            }

        return {
            "status": "unknown",
            "count": 0,
            "source": "local list",
            "message": f"Online check failed: {error}",
        }

    for line in response.text.splitlines():
        found_suffix, separator, count_text = line.partition(":")

        if not separator:
            continue

        if found_suffix.strip().upper() == suffix:
            try:
                count = int(count_text.strip())
            except ValueError:
                count = 0

            return {
                "status": "found",
                "count": count,
                "source": "online service",
                "message": None,
            }

    return {
        "status": "not_found",
        "count": 0,
        "source": "online service",
        "message": None,
    }


def check_sequence(password, length=4):
    """
    Find simple sequences such as:
        abcd
        dcba
        1234
        4321
        qwer
        rewq

    Returns the sequence if found, otherwise None.
    """
    password = password.lower()

    sequences = [
        ALPHABET,
        NUMBERS,
        *KEYBOARD_ROWS,
    ]

    for sequence in sequences:
        for direction in (sequence, sequence[::-1]):
            for i in range(len(direction) - length + 1):
                part = direction[i : i + length]

                if part in password:
                    return part

    return None


def check_repeated(password, length=4):
    """
    Find repeated characters such as:
        aaaa
        1111
        $$$$
    """
    pattern = r"(.)\1{" + str(length - 1) + "}"
    match = re.search(pattern, password)

    if match:
        return match.group(0)

    return None


def check_number_sequence(password, length=4):
    """
    Find increasing or decreasing number sequences such as:
        1234
        4321
        5678
    """
    number_groups = re.findall(r"\d+", password)

    for numbers in number_groups:
        if len(numbers) < length:
            continue

        for i in range(len(numbers) - length + 1):
            part = numbers[i : i + length]
            values = [int(number) for number in part]

            increasing = all(
                values[j] + 1 == values[j + 1] for j in range(len(values) - 1)
            )

            decreasing = all(
                values[j] - 1 == values[j + 1] for j in range(len(values) - 1)
            )

            if increasing or decreasing:
                return part

    return None


def get_context_words(username):
    """
    Turn a username/email into useful words.

    Example:
        john.doe@example.com

    becomes roughly:
        john
        doe
        example
        john.doe
    """
    if not username:
        return []

    username = username.strip().lower()

    if not username:
        return []

    words = []

    # Split the email into its two main parts.
    name_part, at, domain_part = username.partition("@")

    parts = [name_part]

    if at:
        parts.append(domain_part)

    for part in parts:
        words.extend(re.findall(r"[a-z0-9]+", part))

    # Keep the local part too.
    if name_part and re.fullmatch(r"[a-z0-9._-]+", name_part):
        words.append(name_part)

    # Remove very short words and duplicates.
    clean_words = []
    for word in words:
        word = word.strip()

        if len(word) < 3:
            continue

        if word not in clean_words:
            clean_words.append(word)

    return clean_words


def check_context(password, username):
    """
    Look for common words and username/email words inside the password.
    """
    password = password.lower()

    words = set(COMMON_WORDS)
    words.update(get_context_words(username))

    found = []

    for word in sorted(words, key=len, reverse=True):
        if word in password:
            found.append(word)

    return found


def check_common_patterns(password):
    """
    Look for simple predictable patterns.

    These are our own warnings, not NIST requirements.
    """
    issues = []
    lower_password = password.lower()

    # Examples: password123, admin123, welcome123
    if re.search(r"\d{3,}$", password):
        issues.append("A number is added at the end.")

    for word in ("password", "admin", "pass", "user", "welcome"):
        if lower_password.startswith(word) and len(password) > len(word):
            issues.append(f"Common word at the beginning: '{word}'")
            break

    # Examples: 1999, 2024, 2026
    years = re.findall(r"(?<!\d)(19\d{2}|20\d{2})(?!\d)", password)

    for year in years:
        issues.append(f"Year pattern found: '{year}'")

    return issues


def get_character_types(password):
    """
    Check which kinds of characters the password contains.
    """
    return {
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "numbers": bool(re.search(r"\d", password)),
        "symbols": bool(re.search(r"[^a-zA-Z0-9]", password)),
    }


def check_repeated_block(password):
    """
    Find repeated blocks such as:
        abcabc
        123123
    """
    for size in range(1, len(password) // 2 + 1):
        block = password[:size]

        if len(password) % size != 0:
            continue

        if block * (len(password) // size) == password:
            if len(password) // size >= 2:
                return block

    return None


def calculate_score(
    password,
    breach_status,
    sequence,
    repeated,
    number_sequence,
    context_words,
    pattern_issues,
):
    """
    Calculate a simple 0-100 password strength score.

    This is our own score. It is NOT a NIST score.
    """
    score = 0
    issues = []

    length = len(password)

    # Length is the biggest positive factor.
    if length >= 20:
        score += 55
    elif length >= 15:
        score += 45
    elif length >= 12:
        score += 35
    elif length >= 8:
        score += 22
    else:
        score += length * 2

    # Character variety gives only a small bonus.
    types = get_character_types(password)
    type_count = sum(types.values())

    score += type_count * 2

    # A compromised password is a major problem.
    if breach_status == "found":
        score -= 60
        issues.append("Password was found in a compromised-password list.")

    # Simple patterns reduce the score.
    if sequence:
        score -= 15
        issues.append(f"Sequence found: '{sequence}'")

    if repeated:
        score -= 15
        issues.append(f"Repeated characters found: '{repeated}'")

    if number_sequence:
        score -= 12
        issues.append(f"Number sequence found: '{number_sequence}'")

    if context_words:
        score -= min(20, 5 + len(context_words) * 3)
        issues.append("Username/common word found: " + ", ".join(context_words[:5]))

    if pattern_issues:
        score -= min(12, len(pattern_issues) * 4)

        for issue in pattern_issues:
            if issue not in issues:
                issues.append(issue)

    repeated_block = check_repeated_block(password)

    if repeated_block:
        score -= 12
        issues.append(f"Repeated block found: '{repeated_block}'")

    score = max(0, min(100, round(score)))

    if breach_status == "found":
        rating = "Compromised"
    elif score >= 85:
        rating = "Excellent"
    elif score >= 70:
        rating = "Strong"
    elif score >= 50:
        rating = "Moderate"
    elif score >= 30:
        rating = "Weak"
    else:
        rating = "Very Weak"

    return score, rating, issues


def check_password(password, username=None, check_breach=True):
    """
    Run all password checks and return the results.
    """
    length = len(password)

    # Standards-based checks.
    minimum_length = length >= 8
    recommended_length = length >= 15

    if check_breach:
        breach = get_hibp_status(password)
    else:
        breach = {
            "status": "unknown",
            "count": 0,
            "source": "disabled",
            "message": "Online compromise check was disabled.",
        }

    # Our own security checks.
    sequence = check_sequence(password)
    repeated = check_repeated(password)
    number_sequence = check_number_sequence(password)
    context_words = check_context(password, username)
    pattern_issues = check_common_patterns(password)

    spaces = password != password.strip()

    score, rating, issues = calculate_score(
        password,
        breach["status"],
        sequence,
        repeated,
        number_sequence,
        context_words,
        pattern_issues,
    )

    if not minimum_length:
        issues.insert(0, "Password is shorter than 8 characters.")

    if spaces:
        issues.append("Leading or trailing spaces found.")

    # Decide the standards result.
    if not minimum_length:
        status = "FAIL"
    elif breach["status"] == "found":
        status = "FAIL"
    elif breach["status"] == "unknown":
        status = "UNKNOWN"
    else:
        status = "PASS"

    return {
        "length": length,
        "standards": {
            "minimum_8": minimum_length,
            "recommended_15": recommended_length,
            "status": status,
        },
        "breach": breach,
        "checks": {
            "sequence": sequence,
            "repeated": repeated,
            "number_sequence": number_sequence,
            "context_words": context_words,
            "common_patterns": pattern_issues,
            "leading_trailing_spaces": spaces,
            "character_types": get_character_types(password),
        },
        "score": score,
        "rating": rating,
        "issues": issues,
    }


def print_report(result):
    """
    Print the results in a simple format.
    """
    print("\n" + "=" * 65)
    print("PASSWORD SECURITY REPORT")
    print("=" * 65)

    print(f"Length:              {result['length']}")
    print(f"Strength score:      {result['score']} / 100")
    print(f"Strength:            {result['rating']}")
    print(f"Standards status:    {result['standards']['status']}")

    print("\nStandards checks:")

    if result["standards"]["minimum_8"]:
        print("  [OK]   At least 8 characters")
    else:
        print("  [FAIL] At least 8 characters")

    if result["standards"]["recommended_15"]:
        print("  [OK]   15 or more characters")
    else:
        print("  [INFO] 15 or more characters is recommended")

    print("\nCompromised-password check:")

    breach = result["breach"]

    if breach["status"] == "found":
        print("  [FAIL] Password was found")
        if breach["count"]:
            print(f"         Reported count: {breach['count']:,}")

    elif breach["status"] == "not_found":
        print("  [OK]   Password was not found")

    else:
        print("  [?]    Could not determine")
        if breach["message"]:
            print(f"         {breach['message']}")

    print("\nSecurity checks:")

    checks = result["checks"]

    if checks["sequence"]:
        print(f"  [WARN] Sequence: {checks['sequence']}")
    else:
        print("  [OK]   No simple sequence")

    if checks["repeated"]:
        print(f"  [WARN] Repeated characters: {checks['repeated']}")
    else:
        print("  [OK]   No repeated-character run")

    if checks["number_sequence"]:
        print(f"  [WARN] Number sequence: " f"{checks['number_sequence']}")
    else:
        print("  [OK]   No simple number sequence")

    if checks["context_words"]:
        print("  [WARN] Common/username words: " + ", ".join(checks["context_words"]))
    else:
        print("  [OK]   No common/username words")

    if checks["leading_trailing_spaces"]:
        print("  [WARN] Leading/trailing spaces")
    else:
        print("  [OK]   No leading/trailing spaces")

    type_count = sum(checks["character_types"].values())

    print(f"  [INFO] Character types: {type_count} / 4")

    print("\nIssues:")

    if result["issues"]:
        for issue in result["issues"]:
            print(f"  - {issue}")
    else:
        print("  - None found")

    print("=" * 65)


def main():
    print("Simple Password Security Checker")
    print("The password is hidden while you type.")
    print(
        "The online compromise check sends only a small part "
        "of a password hash, not the password itself."
    )
    print()

    try:
        password = getpass.getpass("Enter password: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return 130
    except Exception:
        print("Hidden input is not available here.")
        password = input("Enter password (visible): ")

    if not password:
        print("No password entered.")
        return 1

    try:
        username = input("Username/email (optional, press Enter to skip): ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return 130

    result = check_password(
        password,
        username=username or None,
    )

    print_report(result)

    if result["standards"]["status"] == "FAIL":
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
