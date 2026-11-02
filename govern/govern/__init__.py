"""Govern: the release gate and the signed certificate.

Gate = thresholds in risk-policy.yaml applied to the measured results (incident target, optional
breadth harness and judge calibration). Certificate = the gate's verdict plus the numbers behind it,
HMAC-SHA256 signed with a key the verifier shares, with an expiry (the agentcert / agentops-sdk pattern,
re-pointed at model releases). Verification needs no secret beyond the shared key; the certificate
carries every number it attests so a reader can re-derive the verdict.
"""

from .gate import evaluate_gate, sign_certificate, verify_certificate  # noqa: F401
