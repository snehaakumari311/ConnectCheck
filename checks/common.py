
import re

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$"
)


def clean_domain(raw):
    """Return (domain, None) if valid, otherwise (None, error_message)."""
    if raw is None or not str(raw).strip():
        return None, "Please enter a domain name."

    domain = str(raw).strip().lower()

    if len(domain) > 300:
        return None, "Input is too long."

    if domain.startswith("https://"):
        domain = domain[8:]
    elif domain.startswith("http://"):
        domain = domain[7:]

    domain = re.split(r"[/?#]", domain, maxsplit=1)[0].rstrip(".")

    if ":" in domain or "@" in domain or " " in domain:
        return None, "Enter only a domain name (no port, username or spaces)."

    if not DOMAIN_REGEX.match(domain):
        return None, "Invalid domain name. Example of a valid input: example.com"

    return domain, None


def make_result(check, success, message, details=None, error_type=None, skipped=False):
    return {
        "check": check,
        "success": success,
        "skipped": skipped,
        "message": message,
        "error_type": error_type,
        "details": details or {},
    }


def skipped_result(check, reason):
    return make_result(check, False, reason, error_type="skipped", skipped=True)
