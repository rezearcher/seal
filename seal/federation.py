"""VPE federation — cross-agent trust for Verified Prompt Envelopes.

Implements trust anchor registry, DNS-based discovery, DID-based discovery
(did:key), federated verify/sign with audit logging, and cross-agent audit trails.

Agent A can sign a prompt for Agent B if they share a trust anchor.
Trust anchors are pre-shared via a file-based registry or discovered via DNS/DID.

Core constraint: No external service dependency for core federation.
DNS/DID discovery are optional enhancements; the trust anchor registry
is file-based by default.
"""

from __future__ import annotations

import json
import os
import random
import re
import socket
import struct
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from seal._base import _load_private_key, _load_public_key
from seal.audit import AuditLog
from seal.core import vpe_sign, vpe_verify

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_REGISTRY_PATH = "~/.seal/trust_anchors.json"

# Base58 alphabet (Bitcoin-style, same as base58btc in multibase)
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_LOOKUP = {c: i for i, c in enumerate(_BASE58_ALPHABET)}

# Ed25519 multicodec prefix (varint-encoded as a single byte)
_ED25519_MULTICODEC_PREFIX = bytes([0xED])

# DNS prefix for VPE key discovery
_VPE_DNS_PREFIX = "_vpe."

# Default DNS resolver (Cloudflare)
_DEFAULT_DNS_SERVER = "1.1.1.1"
_DNS_PORT = 53
_DNS_TIMEOUT = 5  # seconds
_DNS_RETRIES = 2

# DNS query/response constants
_DNS_QR_QUERY = 0x0000
_DNS_QR_RESPONSE = 0x8000
_DNS_OPCODE_STANDARD = 0x0000
_DNS_FLAG_RD = 0x0100  # Recursion desired
_DNS_FLAG_TC = 0x0200  # Truncated response
_DNS_RCODE_NXDOMAIN = 3
_DNS_TYPE_TXT = 16
_DNS_CLASS_IN = 1


class FederationError(Exception):
    """Raised when a federation operation encounters invalid or malformed data.

    Distinct from standard Python exceptions — callers catch this
    specifically to handle corrupted trust material, malformed DNS
    responses, or protocol violations without crashing the caller.
    """


# ---------------------------------------------------------------------------
# Base58BTC decode (stdlib-only, no dependencies)
# ---------------------------------------------------------------------------


def _base58btc_decode(s: str) -> bytes:
    """Decode a base58btc (Bitcoin-style) string to bytes.

    Args:
        s: Base58-encoded string (no multibase prefix).

    Returns:
        Decoded bytes.

    Raises:
        ValueError: If the string contains invalid characters.
    """
    if not s:
        return b""

    # Count leading '1's (base58 encoding of zero bytes)
    leading_ones = 0
    for ch in s:
        if ch == "1":
            leading_ones += 1
        else:
            break

    # Decode the rest
    num = 0
    for ch in s:
        if ch not in _BASE58_LOOKUP:
            raise ValueError(f"Invalid base58 character: {ch!r}")
        num = num * 58 + _BASE58_LOOKUP[ch]

    # Convert to bytes
    if num == 0:
        return b"\x00" * leading_ones

    result = bytearray()
    while num > 0:
        result.append(num & 0xFF)
        num >>= 8
    result.reverse()

    # Prepend leading zeros
    return b"\x00" * leading_ones + bytes(result)


# ---------------------------------------------------------------------------
# Trust anchor registry
# ---------------------------------------------------------------------------


@dataclass
class TrustAnchorRegistry:
    """File-based registry of pre-shared Ed25519 public keys.

    Maps agent identities (e.g. ``"agent:alice"``, ``"service:ci-bot"``)
    to hex-encoded Ed25519 public keys for cross-agent trust.

    The registry is stored as a JSON file at a configurable path
    (default: ``~/.seal/trust_anchors.json``).

    Thread-safe for concurrent read/write access.
    """

    path: str = DEFAULT_REGISTRY_PATH
    _anchors: dict[str, str] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _loaded: bool = False

    def __post_init__(self) -> None:
        """Lazy-load on first access; no I/O in __init__."""
        pass

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self._load()

    def _load(self) -> None:
        resolved = Path(self.path).expanduser()
        if resolved.exists():
            try:
                data = json.loads(resolved.read_text())
                if isinstance(data, dict):
                    self._anchors = {str(k): str(v) for k, v in data.items()}
            except (json.JSONDecodeError, OSError):
                self._anchors = {}
        self._loaded = True

    def save(self) -> None:
        """Persist the current registry to disk."""
        resolved = Path(self.path).expanduser()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            resolved.write_text(json.dumps(self._anchors, indent=2, sort_keys=True) + "\n")
            resolved.chmod(0o600)

    def lookup(self, agent_id: str) -> bytes | None:
        """Look up an agent's Ed25519 public key.

        Args:
            agent_id: Agent identity string (e.g. ``"agent:alice"``).

        Returns:
            Raw 32-byte Ed25519 public key, or ``None`` if unknown.
        """
        self._ensure_loaded()
        with self._lock:
            hex_key = self._anchors.get(agent_id)
        if hex_key is None:
            return None
        try:
            return bytes.fromhex(hex_key)
        except ValueError:
            return None

    def register(self, agent_id: str, public_key: bytes) -> None:
        """Register or update a trust anchor.

        Args:
            agent_id: Agent identity string.
            public_key: Raw 32-byte Ed25519 public key.
        """
        self._ensure_loaded()
        with self._lock:
            self._anchors[agent_id] = public_key.hex()

    def remove(self, agent_id: str) -> bool:
        """Remove a trust anchor.

        Args:
            agent_id: Agent identity string.

        Returns:
            ``True`` if the anchor existed and was removed.
        """
        self._ensure_loaded()
        with self._lock:
            return self._anchors.pop(agent_id, None) is not None

    def list_anchors(self) -> dict[str, str]:
        """Return all registered trust anchors (copy)."""
        self._ensure_loaded()
        with self._lock:
            return dict(self._anchors)

    def __contains__(self, agent_id: str) -> bool:
        self._ensure_loaded()
        with self._lock:
            return agent_id in self._anchors

    def __len__(self) -> int:
        self._ensure_loaded()
        with self._lock:
            return len(self._anchors)


# ---------------------------------------------------------------------------
# DNS-based trust anchor discovery (stdlib-only)
# ---------------------------------------------------------------------------


def _get_system_resolver() -> str:
    """Return the system's configured DNS resolver from ``/etc/resolv.conf``.

    Falls back to ``1.1.1.1`` (Cloudflare) when the system file is
    unavailable, empty, or contains no ``nameserver`` directive.
    """
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    return parts[1]
    except (OSError, FileNotFoundError):
        pass
    return _DEFAULT_DNS_SERVER


def _build_dns_query(domain: str) -> tuple[bytes, int]:
    """Build a DNS query packet for a TXT record lookup.

    Wire format::

        12-byte header (ID, flags, counts)
        + question section (QNAME, QTYPE=16(TXT), QCLASS=1(IN))

    Args:
        domain: Fully qualified domain name to query.

    Returns:
        Tuple of ``(raw_query_packet, query_id)`` where ``query_id``
        is a random 16-bit identifier used to match the response.
    """
    query_id = random.randint(0, 65535)
    header = struct.pack(
        "!HHHHHH",
        query_id,
        _DNS_FLAG_RD,  # Standard query with recursion desired
        1,  # QDCOUNT
        0,  # ANCOUNT
        0,  # NSCOUNT
        0,  # ARCOUNT
    )

    # Encode domain as length-prefixed labels
    question = b""
    for part in domain.encode("ascii").split(b"."):
        question += bytes([len(part)]) + part
    question += b"\x00"  # Root label (name terminator)

    # QTYPE + QCLASS
    question += struct.pack("!HH", _DNS_TYPE_TXT, _DNS_CLASS_IN)

    return header + question, query_id


def _parse_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a DNS name starting at ``offset``, handling compression pointers.

    DNS names are sequences of length-prefixed labels terminated by a
    zero-length root label. Compression pointers (``0xC0``) redirect
    to an earlier position in the packet.

    Args:
        data: Full DNS response packet.
        offset: Starting position of the name.

    Returns:
        ``(decoded_name, new_offset)`` where ``new_offset`` is the position
        in the packet *immediately after* the name representation that
        started at the original offset (2 bytes for a pointer, or past
        the root terminator for an uncompressed name). For compressed
        names, the jumps happen internally but only the 2 pointer bytes
        are consumed at the outer offset.
    """
    labels: list[str] = []
    current = offset
    jumped = False

    while current < len(data):
        length = data[current]
        if length & 0xC0:  # Compression pointer (upper 2 bits set)
            if current + 2 > len(data):
                raise FederationError("Truncated DNS compression pointer")
            if not jumped:
                # Only advance the caller's offset past the pointer itself
                offset = current + 2
                jumped = True
            pointer = ((length & 0x3F) << 8) | data[current + 1]
            current = pointer
        elif length == 0:  # Root label (end of name)
            if not jumped:
                offset = current + 1  # Past the terminating zero
            break
        else:
            if current + 1 + length > len(data):
                raise FederationError("Truncated DNS label in name")
            label = data[current + 1 : current + 1 + length].decode("ascii", errors="replace")
            labels.append(label)
            current += 1 + length
            if not jumped:
                offset = current

    return ".".join(labels), offset


def _parse_dns_response(data: bytes, expected_id: int) -> list[str]:
    """Parse a DNS response and extract TXT record strings.

    Handles the full response parsing chain: header validation, question
    section skipping, answer section iteration with compression-aware
    name parsing, and TXT RDATA extraction.

    Args:
        data: Raw DNS response bytes (UDP response payload).
        expected_id: The query ID that was sent; responses with a
            mismatched ID are rejected.

    Returns:
        List of TXT record string values found in the answer section.
        Returns an empty list for NXDOMAIN (no records).

    Raises:
        FederationError: If the response is malformed (truncated,
            ID mismatch, not a response), truncated (TC=1), or has
            a non-NXDOMAIN error code.
    """
    if len(data) < 12:
        raise FederationError("DNS response too short")

    resp_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])

    if resp_id != expected_id:
        raise FederationError(f"DNS response ID mismatch: {resp_id} != {expected_id}")

    if not (flags & _DNS_QR_RESPONSE):
        raise FederationError("Not a DNS response (QR bit not set)")

    rcode = flags & 0x000F
    if rcode == _DNS_RCODE_NXDOMAIN:
        return []  # Domain does not exist — not an error, just empty
    if rcode != 0:
        raise FederationError(f"DNS server error: RCODE={rcode}")

    if flags & _DNS_FLAG_TC:
        raise FederationError("DNS response truncated (TC=1); try TCP fallback")

    offset = 12

    # Skip question section
    for _ in range(qdcount):
        _, offset = _parse_name(data, offset)
        offset += 4  # Skip QTYPE + QCLASS

    records: list[str] = []

    for _ in range(ancount):
        if offset >= len(data):
            raise FederationError("Truncated DNS answer section")

        # Parse answer name (may be compressed)
        _, offset = _parse_name(data, offset)
        if offset + 10 > len(data):
            raise FederationError("Truncated DNS answer header")

        atype, aclass, attl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        _ = attl  # TTL is available but unused here
        offset += 10

        if offset + rdlength > len(data):
            raise FederationError(f"Truncated DNS RDATA: declared {rdlength} bytes, {len(data) - offset} available")

        # Only extract TXT records (type 16) of class IN (1)
        if atype == _DNS_TYPE_TXT and aclass == _DNS_CLASS_IN:
            rdata = data[offset : offset + rdlength]
            pos = 0
            while pos < rdlength:
                txt_len = rdata[pos]
                pos += 1
                if pos + txt_len > rdlength:
                    break  # Malformed TXT length; skip remaining
                txt = rdata[pos : pos + txt_len].decode("ascii", errors="replace")
                records.append(txt)
                pos += txt_len

        offset += rdlength

    return records


def _send_dns_query(domain: str, resolver: str | None = None) -> list[str]:
    """Send a DNS TXT query over UDP and return the parsed records.

    Implements retry logic: up to ``_DNS_RETRIES`` attempts on
    socket timeout, with a short per-attempt timeout of ``_DNS_TIMEOUT``
    seconds. Uses the system resolver from ``/etc/resolv.conf`` when
    ``resolver`` is ``None``.

    Args:
        domain: Fully qualified domain name to query.
        resolver: Optional DNS server address (IP string).
            Defaults to the system resolver.

    Returns:
        List of TXT record strings.

    Raises:
        FederationError: On socket errors, timeouts (after retries
            exhausted), or malformed responses.
    """
    if resolver is None:
        resolver = _get_system_resolver()

    query_packet, query_id = _build_dns_query(domain)
    last_error: str | None = None

    for attempt in range(_DNS_RETRIES):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(_DNS_TIMEOUT)
        try:
            sock.sendto(query_packet, (resolver, _DNS_PORT))

            response_data, _ = sock.recvfrom(4096)
            return _parse_dns_response(response_data, query_id)
        except TimeoutError:
            last_error = f"DNS timeout after {_DNS_TIMEOUT}s (attempt {attempt + 1}/{_DNS_RETRIES})"
        except OSError as exc:
            last_error = f"DNS socket error: {exc}"
        finally:
            sock.close()

    raise FederationError(last_error or "DNS query failed after all retries")


def _resolve_dns_txt(domain: str) -> list[str]:
    """Query TXT records for a domain using a Python-native DNS resolver.

    Resolver uses the system DNS server (from ``/etc/resolv.conf``)
    with a Cloudflare ``1.1.1.1`` fallback. No external ``dig`` or
    ``host`` tools required.

    Args:
        domain: Fully qualified domain name.

    Returns:
        List of TXT record values. Empty list on NXDOMAIN, socket
        errors, or malformed responses (never raises).
    """
    try:
        return _send_dns_query(domain)
    except (FederationError, OSError):
        return []


def resolve_via_dns(agent_domain: str) -> bytes | None:
    """Resolve an agent's VPE public key via DNS TXT record.

    Queries ``_vpe.<agent_domain>`` for a TXT record in the format::

        vpe-key=<hex_encoded_ed25519_public_key>

    The expected key is a 64-character hex string (32 bytes) suitable
    for Ed25519 signature verification.

    Example DNS TXT record::

        _vpe.alice.internal.corp.com. 300 IN TXT "vpe-key=0123456789abcdef0123456789abcdef0123456789"

    Args:
        agent_domain: Domain name of the target agent
            (e.g. ``"hermes.internal.corp.com"``).

    Returns:
        Raw 32-byte Ed25519 public key, or ``None`` if not found.

    Raises:
        FederationError: If the DNS response is malformed or truncated
            (the response exists but cannot be interpreted). Callers that
            prefer graceful degradation should catch this.
    """
    dns_name = f"{_VPE_DNS_PREFIX}{agent_domain}"
    records = _resolve_dns_txt(dns_name)

    for record in records:
        # Match vpe-key=<hex> (64 hex chars = 32 bytes)
        match = re.search(r"vpe-key=([a-fA-F0-9]{64})\b", record)
        if match:
            try:
                return bytes.fromhex(match.group(1).lower())
            except ValueError:
                continue

    return None


# ---------------------------------------------------------------------------
# DID-based trust anchor discovery (did:key)
# ---------------------------------------------------------------------------


def _decode_did_key(did_str: str) -> bytes | None:
    """Decode an Ed25519 public key from a ``did:key`` URI.

    Supports the ``did:key:z<base58btc>`` format (multibase base58btc
    with Ed25519 multicodec prefix ``0xed``).

    The format is::

        did:key:z<base58btc(multicodec_ed25519 + raw_public_key)>

    Args:
        did_str: Full DID string, e.g.
            ``"did:key:z6MkhaXgBZDvB5ABmTkVnYLSF2dQhGt3fJX3tLx3J3d9J6vR"``.

    Returns:
        Raw 32-byte Ed25519 public key, or ``None`` if parsing fails.
    """
    if not did_str.startswith("did:key:"):
        return None

    encoded = did_str[len("did:key:") :]
    if not encoded:
        return None

    # Multibase indicator: 'z' = base58btc
    if encoded[0] != "z":
        return None

    try:
        decoded = _base58btc_decode(encoded[1:])
    except (ValueError, OverflowError):
        return None

    if len(decoded) < 33:
        return None

    # First byte(s) = multicodec varint. Ed25519 = 0xed (1-byte varint)
    if decoded[0] != _ED25519_MULTICODEC_PREFIX[0]:
        return None

    public_key = decoded[1:]
    if len(public_key) != 32:
        return None

    return public_key


def resolve_via_did(did_str: str) -> bytes | None:
    """Resolve an Ed25519 public key from a did:key identifier.

    Alias for ``_decode_did_key``.  Separate function so the resolver API
    is consistent (all ``resolve_via_*`` return ``bytes | None``).

    Args:
        did_str: DID string (``"did:key:z..."``).

    Returns:
        Raw 32-byte Ed25519 public key, or ``None``.
    """
    return _decode_did_key(did_str)


# ---------------------------------------------------------------------------
# DID document resolution via HTTPS (did:web / did:ion)
# ---------------------------------------------------------------------------


def _parse_did_web(did: str) -> str:
    """Parse a ``did:web`` identifier and return the HTTPS URL for its DID document.

    ``did:web:example.com`` → ``https://example.com/.well-known/did.json``

    ``did:web:example.com:path:to:file`` → ``https://example.com/path/to/file/did.json``

    Args:
        did: Full DID string starting with ``did:web:``.

    Returns:
        The HTTPS URL where the DID document is published.

    Raises:
        FederationError: If the DID is malformed (empty domain, invalid chars).
    """
    if not did.startswith("did:web:"):
        raise FederationError(f"Expected did:web: prefix, got {did!r}")

    rest = did[len("did:web:") :]
    if not rest:
        raise FederationError("Empty domain in did:web URI")

    # Split on ':' to map path segments
    segments = rest.split(":")
    domain = segments[0]
    if not domain:
        raise FederationError("Empty domain in did:web URI")

    if len(segments) == 1:
        # bare domain → .well-known/did.json
        return f"https://{domain}/.well-known/did.json"
    else:
        # domain:path:to:file → domain/path/to/file/did.json
        path = "/".join(segments[1:])
        return f"https://{domain}/{path}/did.json"


def _parse_did_ion(did: str, resolver_base: str | None = None) -> str:
    """Parse a ``did:ion`` identifier and return the ION resolution URL.

    Note: ION resolution goes through a configured ION endpoint (e.g.
    https://discover.did.msidentity.com/1.0/identifiers/{suffix}).
    This is a best-effort resolution that depends on network access to a
    public ION node.

    Args:
        did: Full DID string starting with ``did:ion:``.
        resolver_base: Optional custom ION resolver base URL override.
            Defaults to a public Microsoft ION resolver endpoint.

    Returns:
        The ION resolution URL.

    Raises:
        FederationError: If the DID is malformed.
    """
    if not did.startswith("did:ion:"):
        raise FederationError(f"Expected did:ion: prefix, got {did!r}")

    # ION uses a short-form identifier after did:ion:
    # did:ion:<suffix> where suffix is the hash of the initial state
    suffix = did[len("did:ion:") :]
    if not suffix:
        raise FederationError("Empty suffix in did:ion URI")

    base = resolver_base or "https://discover.did.msidentity.com/1.0/identifiers"
    return f"{base}/{suffix}"


def _fetch_json_https(url: str, timeout_read: int = 10, timeout_connect: int = 5) -> dict | None:
    """Fetch a JSON document from an HTTPS URL with timeouts.

    Args:
        url: The full HTTPS URL to fetch.
        timeout_read: Socket read timeout in seconds (default 10).
        timeout_connect: Socket connect timeout in seconds (default 5).

    Returns:
        Parsed JSON dict, or ``None`` on any failure.

    Raises:
        FederationError: On network errors or non-200 responses.
    """
    import urllib.error as _urllib_error
    import urllib.request as _urllib_request

    try:
        req = _urllib_request.Request(url, method="GET")
        req.add_header("Accept", "application/did+json, application/json")
        req.add_header("User-Agent", "seal-vpe/0.1")

        response = _urllib_request.urlopen(
            req,
            timeout=timeout_read,
            # We set the connect timeout via the opener
        )
        # Note: urllib doesn't separate connect/read timeouts cleanly.
        # We use the combined timeout for simplicity.

        if response.status != 200:
            raise FederationError(f"HTTP {response.status} fetching DID document from {url}")

        body = response.read()
        if not body:
            raise FederationError(f"Empty response body from {url}")

        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise FederationError(f"Expected JSON object, got {type(data).__name__}")
        return data

    except _urllib_error.HTTPError as exc:
        raise FederationError(f"HTTP {exc.code} fetching DID document from {url}") from exc
    except _urllib_error.URLError as exc:
        raise FederationError(f"URL error fetching DID document from {url}: {exc.reason}") from exc
    except OSError as exc:
        raise FederationError(f"Network error fetching DID document from {url}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise FederationError(f"Malformed JSON in DID document from {url}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise FederationError(f"Non-UTF-8 response body from {url}: {exc}") from exc


def _extract_ed25519_from_did_document(doc: dict, expected_did: str = "") -> bytes | None:
    """Extract an Ed25519 public key from a DID document's verificationMethod section.

    Traverses the ``verificationMethod`` array and looks for entries where:
    - ``type`` is ``\"Ed25519VerificationKey2018\"``, ``\"Ed25519VerificationKey2020\"``,
      or ``\"Multikey\"`` with Ed25519 multicodec
    - Unless ``expected_did`` is set, matches the controller or ID

    Args:
        doc: Parsed DID document (JSON dict).
        expected_did: Optional expected DID to match against the verificationMethod
            ``controller`` field. When empty, returns the first Ed25519 key found.

    Returns:
        Raw 32-byte Ed25519 public key, or ``None`` if no suitable key is found.
    """
    vm_list = doc.get("verificationMethod")
    if not isinstance(vm_list, list):
        return None

    for vm in vm_list:
        if not isinstance(vm, dict):
            continue

        vm_type = vm.get("type", "")
        controller = vm.get("controller", "")
        public_key_multi = vm.get("publicKeyMultibase", "")
        public_key_jwk = vm.get("publicKeyJwk", {})

        # If we have an expected DID, check controller matches
        if expected_did and controller and controller != expected_did:
            continue

        # Skip if no key material at all
        if not public_key_multi and not public_key_jwk:
            continue

        # --- Ed25519VerificationKey2018 / Ed25519VerificationKey2020 ---
        if vm_type in ("Ed25519VerificationKey2018", "Ed25519VerificationKey2020"):
            if public_key_multi:
                try:
                    key_bytes = _decode_multibase_key(public_key_multi)
                    if key_bytes and len(key_bytes) == 32:
                        return key_bytes
                except (ValueError, FederationError):
                    continue

            # Fallback: publicKeyJwk for Ed25519
            if public_key_jwk and isinstance(public_key_jwk, dict):
                crv = public_key_jwk.get("crv", "")
                if crv == "Ed25519":
                    try:
                        import base64 as _base64

                        # JWK 'x' is base64url-encoded (no padding)
                        x_b64 = public_key_jwk.get("x", "")
                        if not x_b64:
                            continue
                        # Add padding
                        padding = 4 - len(x_b64) % 4
                        if padding != 4:
                            x_b64 += "=" * padding
                        key_bytes = _base64.urlsafe_b64decode(x_b64)
                        if len(key_bytes) == 32:
                            return key_bytes
                    except Exception:
                        continue

        # --- Multikey (W3C CCG 2023) with Ed25519 multicodec ---
        if vm_type == "Multikey" and public_key_multi:
            try:
                key_bytes = _decode_multibase_key(public_key_multi)
                if key_bytes and len(key_bytes) == 32:
                    return key_bytes
            except (ValueError, FederationError):
                continue

    return None


def _decode_multibase_key(multibase_str: str) -> bytes | None:
    """Decode a multibase-encoded public key, stripping the Ed25519 multicodec prefix.

    Supports:
    - ``z`` prefix (base58btc): ``z<base58btc(multicodec + raw_key)>``

    Args:
        multibase_str: Multibase-encoded key string.

    Returns:
        Raw 32-byte key bytes, or ``None`` on failure.
    """
    if not multibase_str or multibase_str[0] != "z":
        return None

    try:
        decoded = _base58btc_decode(multibase_str[1:])
    except (ValueError, OverflowError):
        return None

    if not decoded:
        return None

    # Strip known Ed25519 multicodec prefixes
    # 0xED (1 byte) — most common
    # 0x1301 (2 bytes varint, LE) — also used in some specs
    if len(decoded) >= 1 and decoded[0] == 0xED:
        key_bytes = decoded[1:]
    elif len(decoded) >= 2 and decoded[:2] == bytes([0x01, 0x13]):
        key_bytes = decoded[2:]
    else:
        return None  # Unknown multicodec

    if len(key_bytes) != 32:
        return None

    return key_bytes


def resolve_via_did_document(
    did: str,
    *,
    timeout_read: int = 10,
    timeout_connect: int = 5,
    ion_resolver: str | None = None,
) -> bytes | None:
    """Resolve an Ed25519 public key from a DID document via HTTPS.

    Supported DID methods:
    - ``did:web:<domain>[:<path>]`` — fetches from ``https://<domain>/.well-known/did.json``
      or ``https://<domain>/<path>/did.json``
    - ``did:ion:<suffix>`` — resolves via a public ION endpoint
      (https://discover.did.msidentity.com/1.0/identifiers/<suffix>)

    The function parses the JSON-LD DID document, extracts the first suitable
    Ed25519 ``verificationMethod`` entry, and returns the raw 32-byte public key.

    Args:
        did: DID string to resolve (``did:web:...`` or ``did:ion:...``).
        timeout_read: HTTP read timeout in seconds (default 10).
        timeout_connect: HTTP connect timeout in seconds (deprecated;
            urllib uses a single combined timeout).
        ion_resolver: Optional custom ION resolver URL override.

    Returns:
        Raw 32-byte Ed25519 public key, or ``None`` if resolution fails.

    Raises:
        FederationError: On malformed DID URIs, network errors, HTTP errors,
            malformed JSON, missing or unsupported verification methods.
    """
    if did.startswith("did:web:"):
        url = _parse_did_web(did)
        doc = _fetch_json_https(url, timeout_read=timeout_read)
        if doc is None:
            return None

        key = _extract_ed25519_from_did_document(doc, expected_did=did)
        return key

    elif did.startswith("did:ion:"):
        url = _parse_did_ion(did, resolver_base=ion_resolver)
        doc = _fetch_json_https(url, timeout_read=timeout_read)
        if doc is None:
            return None

        # ION responses wrap the document in a 'didDocument' key
        inner_doc = doc.get("didDocument") or doc
        if not isinstance(inner_doc, dict):
            raise FederationError("ION response missing didDocument")

        key = _extract_ed25519_from_did_document(inner_doc, expected_did=did)
        return key

    else:
        raise FederationError(f"Unsupported DID method: {did!r} — supported methods: did:web:, did:ion:")


# ---------------------------------------------------------------------------
# Trust anchor bundle export/import
# ---------------------------------------------------------------------------

_TRUST_BUNDLE_FIELDS = [
    "vpe_trust_bundle",
    "exported_at",
    "exporter_agent_id",
    "exporter_public_key_hex",
    "anchors",
]


def _canonical_trust_bundle(bundle: dict) -> bytes:
    """Deterministic canonical JSON of a trust bundle (minus signature).

    Uses ``_TRUST_BUNDLE_FIELDS`` ordering and sorts ``anchors`` keys
    lexicographically. Missing fields default to empty string or empty dict.
    """
    ordered: dict[str, object] = OrderedDict()
    for bundle_field in _TRUST_BUNDLE_FIELDS:
        if bundle_field == "anchors":
            value = bundle.get("anchors", {})
            if isinstance(value, dict):
                value = OrderedDict(sorted(value.items()))
            ordered[bundle_field] = value
        else:
            ordered[bundle_field] = bundle.get(bundle_field, "")
    return json.dumps(ordered, separators=(",", ":")).encode("utf-8")


def export_trust_bundle(
    registry: TrustAnchorRegistry,
    *,
    exporter_agent_id: str,
    private_key: bytes,
) -> str:
    """Export all registered trust anchors as a signed JSON bundle.

    The bundle is a JSON envelope with an Ed25519 signature (self-signed
    by the exporting agent), suitable for out-of-band transfer to another
    agent's trust anchor registry.

    Args:
        registry: The trust anchor registry to export from.
        exporter_agent_id: Identity of the exporting agent
            (e.g. ``\"agent:alice\"``).
        private_key: Raw Ed25519 private key bytes of the exporting agent.

    Returns:
        Signed JSON bundle string suitable for ``import_trust_bundle``.

    Raises:
        FederationError: If the registry is empty or the private key
            is invalid.
    """
    anchors = registry.list_anchors()
    if not anchors:
        raise FederationError("Cannot export trust bundle: no trust anchors registered")

    # Derive public key from the private key for bundle verification
    sk = _load_private_key(private_key)
    pk = sk.public_key()
    pk_bytes = pk.public_bytes_raw()

    # Build bundle payload (without signature)
    import datetime as _datetime

    bundle: dict[str, object] = {
        "vpe_trust_bundle": "1",
        "exported_at": _datetime.datetime.now(_datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "exporter_agent_id": exporter_agent_id,
        "exporter_public_key_hex": pk_bytes.hex(),
        "anchors": dict(anchors),
    }

    # Sign the canonical payload
    canon = _canonical_trust_bundle(bundle)
    bundle["signature"] = sk.sign(canon).hex()

    return json.dumps(bundle, separators=(",", ":"))


def import_trust_bundle(
    bundle_str: str,
    registry: TrustAnchorRegistry,
    *,
    trusted_exporter_ids: set[str] | None = None,
) -> dict:
    """Verify and import trust anchors from a signed JSON bundle.

    Args:
        bundle_str: The signed JSON bundle string (from ``export_trust_bundle``).
        registry: The target trust anchor registry to import into.
        trusted_exporter_ids: Optional set of allowed exporter agent IDs.
            If provided, import is rejected unless the exporter's agent_id
            is in this set.

    Returns:
        dict: ``{\"ok\": bool, \"reason\": str, \"imported_count\": int,
        \"exporter_agent_id\": str}``

    Raises:
        FederationError: If the bundle is malformed, has an invalid
            version, signature verification fails, or the exporter is
            not trusted.
    """
    # Parse JSON
    try:
        bundle = json.loads(bundle_str)
    except (json.JSONDecodeError, ValueError) as exc:
        raise FederationError(f"Invalid trust bundle JSON: {exc}") from exc

    if not isinstance(bundle, dict):
        raise FederationError("Trust bundle must be a JSON object")

    # Check version
    version = bundle.get("vpe_trust_bundle", "")
    if version != "1":
        raise FederationError(f"Unsupported trust bundle version: {version!r} — expected '1'")

    exporter_id = bundle.get("exporter_agent_id", "")
    if not exporter_id:
        raise FederationError("Trust bundle missing exporter_agent_id")

    pk_hex = bundle.get("exporter_public_key_hex", "")
    if not pk_hex:
        raise FederationError("Trust bundle missing exporter_public_key_hex")

    try:
        pk_bytes = bytes.fromhex(pk_hex)
        if len(pk_bytes) != 32:
            raise FederationError(f"Invalid public key length in bundle: {len(pk_bytes)} bytes, expected 32")
    except ValueError as exc:
        raise FederationError(f"Invalid exporter_public_key_hex (not valid hex): {exc}") from exc

    sig_hex = bundle.get("signature", "")
    if not sig_hex:
        raise FederationError("Trust bundle missing signature")
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError as exc:
        raise FederationError(f"Invalid signature (not valid hex): {exc}") from exc

    # Check trusted exporter
    if trusted_exporter_ids is not None and exporter_id not in trusted_exporter_ids:
        raise FederationError(f"Untrusted exporter: {exporter_id!r} — not in trusted_exporter_ids")

    # Verify signature
    try:
        pk = _load_public_key(pk_bytes)
        canon = _canonical_trust_bundle(bundle)
        pk.verify(sig_bytes, canon)
    except InvalidSignature:
        raise FederationError("Trust bundle signature verification failed")
    except Exception as exc:
        raise FederationError(f"Trust bundle signature verification error: {exc}") from exc

    # Import anchors (idempotent — re-importing the same anchor is a no-op)
    anchors = bundle.get("anchors", {})
    if not isinstance(anchors, dict):
        raise FederationError("Trust bundle anchors must be a JSON object")

    imported_count = 0
    for agent_id, key_hex in anchors.items():
        if not isinstance(agent_id, str) or not isinstance(key_hex, str):
            continue
        try:
            key_bytes = bytes.fromhex(key_hex)
            if len(key_bytes) != 32:
                continue
            # Idempotent: register even if already exists (register updates)
            registry.register(agent_id, key_bytes)
            imported_count += 1
        except (ValueError, TypeError):
            continue

    # Persist the updated registry
    registry.save()

    return {
        "ok": True,
        "reason": f"imported {imported_count} anchors from {exporter_id}",
        "imported_count": imported_count,
        "exporter_agent_id": exporter_id,
    }


# ---------------------------------------------------------------------------
# Cross-agent audit trail
# ---------------------------------------------------------------------------


@dataclass
class FederationAuditLog:
    """Cross-agent audit trail for VPE federation operations.

    Records issuance (Agent A signs a prompt for Agent B) and
    verification (Agent B verifies and accepts/rejects) events.

    Uses the existing ``seal.audit.AuditLog`` as the underlying store
    so all audit entries are written to the same append-only JSONL file.
    """

    audit: AuditLog = field(default_factory=AuditLog)

    def log_issuance(
        self,
        *,
        issuer: str,
        audience: str,
        prompt_summary: str,
        envelope_nonce: str,
        source: str = "federation",
    ) -> None:
        """Record that an issuer signed a prompt for an audience.

        Args:
            issuer: Who signed the envelope.
            audience: Intended recipient.
            prompt_summary: Short description or first N chars of the prompt.
            envelope_nonce: The envelope's nonce for correlation.
            source: How the trust anchor was resolved (registry, dns, did).
        """
        self.audit.log_access(
            label=f"vpe:federation:issuance:{issuer}->{audience}",
            caller=issuer,
            action="sign",
        )
        # Also write a structured cross-audit entry
        self._write_cross_entry(
            event_type="issuance",
            issuer=issuer,
            audience=audience,
            prompt_summary=prompt_summary[:80],
            envelope_nonce=envelope_nonce,
            source=source,
            result="granted",
        )

    def log_verification(
        self,
        *,
        issuer: str,
        verifier: str,
        envelope_nonce: str,
        result: str,
        source: str = "federation",
        reason: str = "",
    ) -> None:
        """Record that a verifier checked a federated envelope.

        Args:
            issuer: Who signed the envelope.
            verifier: Who verified it.
            envelope_nonce: The envelope's nonce for correlation.
            result: ``"granted"`` or ``"denied"``.
            source: How the trust anchor was resolved.
            reason: Human-readable reason (for denials).
        """
        self.audit.log_access(
            label=f"vpe:federation:verification:{issuer}->{verifier}",
            caller=verifier,
            action="verify",
        )
        self._write_cross_entry(
            event_type="verification",
            issuer=issuer,
            audience=verifier,
            prompt_summary="",
            envelope_nonce=envelope_nonce,
            source=source,
            result=result,
            reason=reason,
        )

    def _write_cross_entry(self, **fields: str) -> None:
        """Write a structured cross-audit entry to the audit log."""
        from seal.audit import _utc_now_iso

        entry: dict[str, object] = {
            "timestamp": _utc_now_iso(),
            "event": "vpe_cross_audit",
        }
        entry.update(fields)

        # Write to the same JSONL file via a raw append
        path = Path(self.audit.path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (json.dumps(entry) + "\n").encode("utf-8"))
        finally:
            os.close(fd)


# ---------------------------------------------------------------------------
# Resolution chain
# ---------------------------------------------------------------------------


@dataclass
class ResolutionResult:
    """Result of resolving a trust anchor.

    Attributes:
        public_key: The resolved Ed25519 public key (raw bytes), or None.
        source: How it was resolved (``"registry"``, ``"dns"``, ``"did"``, ``"none"``).
        agent_id: The resolved agent identity, if known.
    """

    public_key: bytes | None
    source: str = "none"
    agent_id: str = ""


def resolve_trust_anchor(
    issuer: str,
    *,
    registry: TrustAnchorRegistry | None = None,
    dns_domain: str | None = None,
    did_str: str | None = None,
    did_web: str | None = None,
) -> ResolutionResult:
    """Resolve a trust anchor for a given issuer using the available methods.

    Resolution order:
        1. Trust anchor registry (pre-shared keys)
        2. DNS discovery (TXT record)
        3. DID discovery (did:key)
        4. DID document resolution via HTTPS (did:web / did:ion)

    Args:
        issuer: The issuer identity string (e.g. ``"agent:alice"``).
        registry: Optional pre-configured registry instance.
        dns_domain: Optional domain for DNS TXT lookup.
        did_str: Optional did:key string for DID resolution.
        did_web: Optional ``did:web:`` or ``did:ion:`` URL for HTTPS DID
            document resolution (resolved via ``resolve_via_did_document()``).

    Returns:
        ``ResolutionResult`` with the resolved public key and source.
    """
    # 1. Registry
    if registry is not None:
        pk = registry.lookup(issuer)
        if pk is not None:
            return ResolutionResult(public_key=pk, source="registry", agent_id=issuer)

    # 2. DNS discovery
    if dns_domain is not None:
        pk = resolve_via_dns(dns_domain)
        if pk is not None:
            return ResolutionResult(public_key=pk, source="dns", agent_id=dns_domain)

    # 3. DID discovery
    if did_str is not None:
        pk = resolve_via_did(did_str)
        if pk is not None:
            did_agent = f"did:{did_str}"
            return ResolutionResult(public_key=pk, source="did", agent_id=did_agent)

    # 4. DID document resolution via HTTPS (did:web / did:ion)
    if did_web is not None:
        pk = resolve_via_did_document(did_web)
        if pk is not None:
            return ResolutionResult(public_key=pk, source="did_web", agent_id=did_web)

    return ResolutionResult(public_key=None, source="none")


# ---------------------------------------------------------------------------
# Federated sign / verify
# ---------------------------------------------------------------------------


@dataclass
class FederatedSignResult:
    """Result of a federated signing operation."""

    envelope: str = ""
    nonce: str = ""
    error: str = ""


def vpe_federated_sign(
    prompt: str,
    *,
    issuer: str,
    audience: str,
    private_key: bytes,
    scope: dict | None = None,
    doc_sha256: str = "",
    ttl_seconds: int = 300,
    counter: int | None = None,
    audit_log: FederationAuditLog | None = None,
    **kwargs: object,
) -> FederatedSignResult:
    """Sign a VPE envelope for cross-agent federation.

    Wraps ``vpe_sign()`` and optionally logs the issuance to the
    cross-agent audit trail.

    Args:
        prompt: The actionable instruction.
        issuer: Who is signing (e.g. ``"agent:alice"``).
        audience: Who should execute (e.g. ``"agent:bob"``).
        private_key: Raw Ed25519 private key bytes.
        scope: Execution constraints.
        doc_sha256: SHA-256 binding to source document.
        ttl_seconds: Time-to-live in seconds.
        counter: Monotonic counter (auto-generated if omitted).
        audit_log: Optional audit log for cross-agent tracking.
        **kwargs: Additional keyword arguments passed to ``vpe_sign``.

    Returns:
        ``FederatedSignResult`` with the signed envelope and nonce.
    """
    try:
        envelope_str = vpe_sign(
            prompt=prompt,
            scope=scope,
            issuer=issuer,
            audience=audience,
            doc_sha256=doc_sha256,
            ttl_seconds=ttl_seconds,
            counter=counter,
            private_key=private_key,
        )
    except Exception as exc:
        return FederatedSignResult(error=str(exc))

    # Extract nonce for audit correlation
    import json as _json

    try:
        parsed = _json.loads(envelope_str)
        nonce = parsed.get("nonce", "")
    except (ValueError, _json.JSONDecodeError):
        nonce = ""

    if audit_log is not None:
        audit_log.log_issuance(
            issuer=issuer,
            audience=audience,
            prompt_summary=prompt[:80],
            envelope_nonce=nonce,
        )

    return FederatedSignResult(envelope=envelope_str, nonce=nonce)


def vpe_federated_verify(
    envelope_str: str,
    *,
    registry: TrustAnchorRegistry | None = None,
    dns_domain: str | None = None,
    did_str: str | None = None,
    issuer_override: str | None = None,
    audit_log: FederationAuditLog | None = None,
) -> dict:
    """Verify a VPE envelope using the federation trust resolution chain.

    Resolves the issuer's Ed25519 public key via:
        1. Trust anchor registry
        2. DNS TXT record
        3. did:key identifier

    Then delegates to ``vpe_verify()`` for the actual cryptographic check.

    Args:
        envelope_str: The VPE envelope JSON string.
        registry: Optional trust anchor registry.
        dns_domain: Optional domain for DNS TXT lookup.
        did_str: Optional did:key string for DID resolution.
        issuer_override: Override the issuer identity for key lookup
            (if not provided, uses the ``issuer`` field from the envelope).
        audit_log: Optional audit log for cross-agent tracking.

    Returns:
        dict: ``{"valid": bool, "reason": str, "source": str}``
    """
    # Parse envelope to get issuer
    try:
        import json as _json

        envelope = _json.loads(envelope_str)
    except (ValueError, _json.JSONDecodeError) as exc:
        result = {"valid": False, "reason": f"invalid_json: {exc}"}
        if audit_log is not None:
            audit_log.log_verification(
                issuer="unknown",
                verifier="unknown",
                envelope_nonce="",
                result="denied",
                reason=result["reason"],
            )
        return {**result, "source": "none"}

    if not isinstance(envelope, dict):
        result = {"valid": False, "reason": "invalid_json: not a dict"}
        if audit_log is not None:
            audit_log.log_verification(
                issuer="unknown",
                verifier="unknown",
                envelope_nonce="",
                result="denied",
                reason=result["reason"],
            )
        return {**result, "source": "none"}

    issuer = issuer_override or envelope.get("issuer", "")
    nonce = envelope.get("nonce", "")

    # Resolve trust anchor
    resolution = resolve_trust_anchor(
        issuer,
        registry=registry,
        dns_domain=dns_domain,
        did_str=did_str,
    )

    if resolution.public_key is None:
        reason = f"unknown_issuer: no trust anchor for {issuer!r}"
        if audit_log is not None:
            audit_log.log_verification(
                issuer=issuer,
                verifier="federation",
                envelope_nonce=nonce,
                result="denied",
                reason=reason,
                source="none",
            )
        return {"valid": False, "reason": reason, "source": "none"}

    # Delegate to vpe_verify
    verify_result = vpe_verify(envelope_str, public_key=resolution.public_key)

    # Augment result with source
    result = {
        "valid": verify_result.get("valid", False),
        "reason": verify_result.get("reason", "unknown"),
        "source": resolution.source,
    }

    if audit_log is not None:
        audit_log.log_verification(
            issuer=issuer,
            verifier="federation",
            envelope_nonce=nonce,
            result="granted" if result["valid"] else "denied",
            reason=result["reason"],
            source=resolution.source,
        )

    return result
