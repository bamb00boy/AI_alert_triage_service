import pytest

from triage import hmac_auth

SECRET = b"s3cret"
BODY = b'{"rule_title":"x"}'


def _headers(secret=SECRET, body=BODY, ts=1_700_000_000):
    h = hmac_auth.sign(secret, body, ts)
    return h[hmac_auth.TIMESTAMP_HEADER], h[hmac_auth.SIGNATURE_HEADER]


def test_valid_signature_passes():
    ts, sig = _headers()
    hmac_auth.verify([SECRET], BODY, ts, sig, now=1_700_000_010)


def test_rotated_secret_accepted():
    ts, sig = _headers(secret=b"old")
    hmac_auth.verify([b"new", b"old"], BODY, ts, sig, now=1_700_000_000)


@pytest.mark.parametrize(
    "mutate, reason",
    [
        (lambda ts, sig, body: (ts, sig, body + b" "), "mismatch"),
        (lambda ts, sig, body: (str(int(ts) + 1), sig, body), "mismatch"),
        (lambda ts, sig, body: (ts, "v1=" + "0" * 64, body), "mismatch"),
        (lambda ts, sig, body: (ts, "v0=abc", body), "no v1"),
        (lambda ts, sig, body: (None, sig, body), "missing"),
        (lambda ts, sig, body: ("yesterday", sig, body), "malformed"),
    ],
)
def test_tampering_rejected(mutate, reason):
    ts, sig = _headers()
    ts, sig, body = mutate(ts, sig, BODY)
    with pytest.raises(hmac_auth.SignatureError, match=reason):
        hmac_auth.verify([SECRET], body, ts, sig, now=1_700_000_000)


def test_stale_timestamp_rejected():
    ts, sig = _headers()
    with pytest.raises(hmac_auth.SignatureError, match="window"):
        hmac_auth.verify([SECRET], BODY, ts, sig, now=1_700_000_000 + 301, max_skew=300)
