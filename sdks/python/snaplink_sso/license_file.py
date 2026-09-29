"""Local verification of a signed commercial entitlement file.

``docs/commercial-model.md`` requires that offline and private deployments gate
paid features from a signed file, and that authentication never calls a vendor
licensing service on a login path. The second clause is only satisfiable if the
SDK can verify the file itself: without a local verifier an air-gapped
deployment has to call ``/api/v1/me/account-context``, which puts a vendor on
the login path and violates the rule this module exists to satisfy.

Verification is entirely local. It performs no network I/O on any path,
including login.

Trust roots
-----------
The signing private key never enters this package, the repository, or CI, and is
never transmitted here; only the payload and its signature are. A trust root is
always supplied by the caller, which is what makes OEM and private-CA
deployments possible. :func:`vendor_pinned_trust` is the slot for Snaplink's
own root and reports :class:`LicenseTrustUnconfigured` until a release populates
it, rather than carrying a placeholder key that would read as vendor authority
while verifying nothing.

Why a verifier is supplied
--------------------------
This package is stdlib-only by design (``dependencies = []``) and the standard
library has no Ed25519. Rather than add a mandatory dependency or hand-roll a
signature implementation, the package accepts a :class:`LicenseVerifier`: a
one-argument callable over the public key, the payload bytes, and the signature.
Pass ``cryptography``'s Ed25519PublicKey, PyNaCl, or any equivalent::

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    def verify(public_key, payload, signature):
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
            return True
        except Exception:
            return False

Everything except that one primitive -- envelope parsing, the algorithm and
version gate, the key-id lookup, the no-downgrade policy, and the three-state
classification -- is identical in every SDK and is what the shared conformance
fixture pins.

Envelope
--------
``{"version": 1, "algorithm": "Ed25519", "key_id": "...",
"payload": "<base64 of the entitlement JSON bytes>",
"signature": "<base64 of the Ed25519 signature over those bytes>"}``

The signature covers the decoded payload bytes, not a re-serialisation of them,
so verification cannot depend on a canonicalisation rule that two
implementations might disagree about.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Optional

from .entitlement import Entitlement, LicenseState

#: The only algorithm this build accepts.
ALGORITHM = "Ed25519"
#: The only envelope version this build accepts.
VERSION = 1
#: Raw Ed25519 public key length in bytes.
PUBLIC_KEY_BYTES = 32
#: Raw Ed25519 signature length in bytes.
SIGNATURE_BYTES = 64


class LicenseError(Exception):
    """An entitlement-file verification failure.

    These codes originate in the SDK, never on the wire, and are namespaced so a
    caller cannot confuse them with a network failure. None is recoverable by
    retrying.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _malformed(message: str) -> LicenseError:
    return LicenseError("license_malformed", message)


def _algorithm_unsupported(message: str) -> LicenseError:
    return LicenseError("license_algorithm_unsupported", message)


#: A verifier answers one question: does this signature cover these bytes?
#: ``verify(public_key, payload, signature) -> bool`` and must return False
#: rather than raise for a bad signature.
LicenseVerifier = Callable[[bytes, bytes, bytes], bool]


@dataclass
class LicenseTrust:
    """Public keys an entitlement file may be signed by.

    A file names the ``key_id`` it was signed with, so a deployment can hold a
    current and a next key during rotation without weakening verification.
    """

    keys: Dict[str, bytes] = field(default_factory=dict)
    verifier: Optional[LicenseVerifier] = None

    def add_key(self, key_id: str, public_key: bytes) -> None:
        """Trust a raw 32-byte Ed25519 public key.

        A key of the wrong length is rejected rather than stored, so a typo
        cannot silently widen or narrow trust.
        """
        if not key_id:
            raise _malformed("key id is required")
        if len(public_key) != PUBLIC_KEY_BYTES:
            raise _malformed(f"key {key_id} is not {PUBLIC_KEY_BYTES} bytes")
        self.keys[key_id] = bytes(public_key)

    def add_base64_key(self, key_id: str, encoded: str) -> None:
        """Trust a base64 standard-encoded Ed25519 public key."""
        try:
            raw = base64.b64decode(encoded.strip(), validate=True)
        except Exception as exc:  # noqa: BLE001 - any decode failure is malformed
            raise _malformed(f"key {key_id} is not base64: {exc}") from exc
        self.add_key(key_id, raw)

    def is_empty(self) -> bool:
        return not self.keys

    def key_ids(self) -> list:
        return sorted(self.keys)

    def lookup(self, key_id: str) -> Optional[bytes]:
        return self.keys.get(key_id)


def license_trust_from_key(
    key_id: str, public_key: str, verifier: LicenseVerifier
) -> LicenseTrust:
    """Build a trust root holding a single key."""
    trust = LicenseTrust(verifier=verifier)
    trust.add_base64_key(key_id, public_key)
    return trust


def vendor_pinned_trust() -> LicenseTrust:
    """Snaplink's own pinned trust root.

    Deliberately not a placeholder key: a hardcoded constant that verifies
    nothing would read as vendor authority while granting nothing. A release
    populates this from the real key and the supplied verifier.
    """
    raise LicenseError(
        "license_trust_unconfigured",
        "no vendor trust root is configured in this build",
    )


@dataclass(frozen=True)
class EntitlementFile:
    """A verified commercial entitlement read from a local file."""

    entitlement: Entitlement
    key_id: str

    def state_at(self, now: int) -> LicenseState:
        """Classify at ``now``.

        The three-state classification is identical to the online path, so a
        deployment that moves between the two does not change behaviour.
        """
        return self.entitlement.state_at(now)


_REQUIRED_ENVELOPE_FIELDS = ("version", "algorithm", "key_id", "payload", "signature")


def verify_license_file(raw: bytes, trust: LicenseTrust) -> EntitlementFile:
    """Verify ``raw`` against ``trust`` and decode the entitlement it carries.

    Checks the declared algorithm and version before any signature work, then
    verifies against the key the file names. Any failure raises; this function
    never returns an inactive or free-tier entitlement in place of a rejected
    file.
    """
    if trust is None or trust.is_empty() or trust.verifier is None:
        raise LicenseError("license_trust_unconfigured", "no trust root was supplied")
    try:
        envelope = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise _malformed(str(exc)) from exc
    if not isinstance(envelope, dict):
        raise _malformed("envelope must be an object")
    missing = [field for field in _REQUIRED_ENVELOPE_FIELDS if field not in envelope]
    if missing:
        raise _malformed(f"envelope is missing {', '.join(missing)}")
    if envelope["version"] != VERSION:
        raise _algorithm_unsupported(f"envelope version {envelope['version']}")
    if envelope["algorithm"] != ALGORITHM:
        raise _algorithm_unsupported(str(envelope["algorithm"]))
    key = trust.lookup(str(envelope["key_id"]))
    if key is None:
        raise LicenseError("license_untrusted_key", str(envelope["key_id"]))
    payload = _decode(envelope["payload"], "payload")
    signature = _decode(envelope["signature"], "signature")
    if len(signature) != SIGNATURE_BYTES:
        raise _malformed(f"signature is not {SIGNATURE_BYTES} bytes")
    try:
        verified = trust.verifier(key, payload, signature)
    except Exception as exc:  # noqa: BLE001 - a raising verifier has not verified
        raise LicenseError("license_signature_invalid", "verifier failed") from exc
    if not verified:
        raise LicenseError("license_signature_invalid", "signature did not verify")
    try:
        entitlement = Entitlement.from_wire(json.loads(payload))
    except (ValueError, AttributeError) as exc:
        raise _malformed(f"payload is not an entitlement: {exc}") from exc
    return EntitlementFile(entitlement=entitlement, key_id=str(envelope["key_id"]))


def _decode(value: object, name: str) -> bytes:
    if not isinstance(value, str):
        raise _malformed(f"{name} must be a string")
    try:
        return base64.b64decode(value.strip(), validate=True)
    except Exception as exc:  # noqa: BLE001 - any decode failure is malformed
        raise _malformed(f"{name} is not base64: {exc}") from exc


def fixture_case_ids() -> Iterable[str]:
    """The case ids in the shared conformance fixture.

    Exposed so a test can assert this package implements every case rather than
    silently drifting from the other SDKs.
    """
    import pathlib

    path = (
        pathlib.Path(__file__).resolve().parents[3]
        / "ops"
        / "build"
        / "sdk-conformance"
        / "license_file.json"
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    return [case["id"] for case in document["cases"]]
