"""
QRShield smoke test – runs the full pipeline directly (no HTTP server needed).
Tests 4 scenarios: safe UPI, suspicious URL, malicious URL, plain text.
"""

import asyncio
from app.core.pipeline import run_pipeline


CASES = [
    {
        "label": "✅ Legitimate UPI payment",
        "payload": "upi://pay?pa=merchant@okicici&pn=Coffee+Shop&am=150.00&cu=INR&tn=Coffee",
        "expect_verdict_not": "CRITICAL",
    },
    {
        "label": "⚠️  Suspicious HTTP URL (no HTTPS)",
        "payload": "http://secure-login.paytm.free.tk/verify?redirect=http://evil.com",
        "expect_verdict_in": ["SUSPICIOUS", "HIGH_RISK", "CRITICAL"],
    },
    {
        "label": "🚨 IP-address payment URL",
        "payload": "http://192.168.1.1/pay?amount=9999",
        "expect_verdict_in": ["SUSPICIOUS", "HIGH_RISK", "CRITICAL"],
    },
    {
        "label": "🛑 Sensitive data in plain text",
        "payload": "Your OTP is 482910 — enter to verify",
        "expect_verdict_in": ["SUSPICIOUS", "HIGH_RISK", "CRITICAL"],
    },
    {
        "label": "ℹ️  Zero-amount UPI (token collection risk)",
        "payload": "upi://pay?pa=attacker@ybl&pn=Refund&am=0&cu=INR",
        "expect_verdict_in": ["SUSPICIOUS", "HIGH_RISK", "CRITICAL"],
    },
]


async def run():
    passed = 0
    failed = 0

    for case in CASES:
        result = await run_pipeline(raw_payload=case["payload"])
        verdict = result["verdict"]
        score   = result["score"]
        top     = [f["rule"] for f in result["top_findings"]]

        ok = True
        if "expect_verdict_not" in case and verdict == case["expect_verdict_not"]:
            ok = False
        if "expect_verdict_in" in case and verdict not in case["expect_verdict_in"]:
            ok = False

        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1

        print(f"\n[{status}] {case['label']}")
        print(f"       Verdict : {verdict}  |  Score : {score}/100")
        print(f"       Top rules: {top[:3]}")

    print(f"\n{'─'*55}")
    print(f"  Results: {passed} passed, {failed} failed out of {len(CASES)} cases")
    print(f"{'─'*55}")
    return failed


if __name__ == "__main__":
    failed = asyncio.run(run())
    raise SystemExit(failed)
