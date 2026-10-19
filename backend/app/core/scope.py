import urllib.parse
import ipaddress
from typing import Optional, Tuple

BLOCKED_METADATA_HOSTS = {
    "169.254.169.254",          # AWS / GCP / Azure link-local metadata
    "metadata.google.internal",
    "instance-data",
}

def validate_target_scope(url_str: str) -> Tuple[bool, Optional[str]]:
    """
    Validates whether a target URL is in scope for security scanning.
    Rejects:
    - Non-HTTP/HTTPS schemes (e.g. ftp://, file://, javascript:, gopher://)
    - Empty or malformed hostnames
    - Cloud metadata IP/endpoints or link-local addresses
    """
    try:
        parsed = urllib.parse.urlparse(str(url_str).strip())
        scheme = (parsed.scheme or "").lower()
        if scheme not in ["http", "https"]:
            return False, f"Unsupported scheme '{scheme}'. Only http:// and https:// URLs are permitted."

        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            return False, "Target URL is missing a valid hostname."

        if hostname in BLOCKED_METADATA_HOSTS:
            return False, f"Target host '{hostname}' is blocked (cloud metadata endpoint)."

        # Reject link-local IPs
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_link_local:
                return False, f"Target IP '{hostname}' is out of scope (link-local address)."
        except ValueError:
            pass  # Domain name, not an IP literal

        return True, None
    except Exception as e:
        return False, f"Invalid target URL: {str(e)}"
