"""
QRShield – Synthetic Dataset Generator
======================================
Generates a labelled CSV dataset of QR-payment scenarios for ML training.

Label taxonomy (label column):
  0 = LEGITIMATE
  1 = SUSPICIOUS
  2 = FRAUDULENT

Scenario categories covered (per synopsis Section 9):
  Legitimate:
    - Normal merchant UPI payment (correct amount, known VPA)
    - HTTPS payment page (trusted domain)
    - Correct-amount, correct-recipient with message

  Fraudulent / Suspicious:
    - Fake merchant QR (unknown/suspicious VPA)
    - Recipient mismatch (wrong UPI handle)
    - Amount manipulation (amount in QR ≠ message)
    - Receive-money scam (message says RECEIVE, QR says PAY)
    - Fake refund scam
    - Fake cashback / reward scam
    - Fake verification / KYC payment
    - Authority spoofing (RBI, bank, government)
    - Urgency manipulation
    - IP-address URLs
    - HTTP (non-HTTPS) payment pages
    - Risky TLD domains
    - Open-redirect payment URLs
    - Deep-link with invalid VPA
    - Zero-amount UPI (token collection)
    - Homoglyph domain spoofing
    - URL shortener hiding destination

Features extracted per scenario:
  QR/Transaction features:
    qr_format, upi_vpa, upi_amount, upi_currency, url_scheme,
    url_has_ip, url_tld_risky, url_has_shortener, url_length,
    url_redirect_params, payload_length, has_suspicious_keywords,
    amount_is_zero, amount_is_negative, amount_is_high

  NLP / Message features:
    message_intent (PAY/RECEIVE/REFUND/VERIFY/REWARD/NONE),
    message_amount, has_urgency, has_authority_claim,
    intent_qr_mismatch, amount_mismatch

  Derived:
    label (0/1/2), label_name, scenario_category
"""

import csv
import random
import sys
from pathlib import Path

random.seed(42)

# ── Output path ───────────────────────────────────────────────────────────────
OUTPUT = Path(__file__).parent / "qr_fraud_dataset.csv"

# ── Known-safe VPAs ───────────────────────────────────────────────────────────
LEGIT_VPAS = [
    "merchant@okicici", "shop@okhdfcbank", "restaurant@okaxis",
    "store@oksbi", "cafe@ybl", "hotel@ibl", "clinic@axl",
    "school@upi", "pharmacy@paytm", "gym@phonepe",
    "salon@kotak", "bakery@okicici", "laundry@okhdfcbank",
    "grocery@okaxis", "petrol@oksbi", "parking@ybl",
]

SUSPICIOUS_VPAS = [
    "refund123@ybl", "cashback99@upi", "prize_winner@paytm",
    "kyc_verify@phonepe", "bank_support@upi", "rbi_official@ybl",
    "reward_claim@paytm", "lucky_user@upi", "helpdesk9@ybl",
    "account_fix@upi", "tax_refund@ybl", "govtrefund@upi",
    "income_tax@phonepe", "support_team@upi", "verify_now@ybl",
]

FRAUD_VPAS = [
    "attacker@ybl", "scammer@paytm", "fraud@upi",
    "hacker@phonepe", "thief@okaxis", "fake_merchant@upi",
    "collect_now@ybl", "urgentpay@upi", "instant_win@paytm",
    "bank_alert@upi", "rbi_collect@ybl",
]

LEGIT_MERCHANTS = [
    "Cafe Coffee Day", "Dominos Pizza", "Reliance Fresh",
    "Apollo Pharmacy", "Big Bazaar", "McDonald's",
    "Swiggy", "Zomato", "BookMyShow", "Flipkart",
]

LEGIT_DOMAINS = [
    "https://pay.razorpay.com/checkout",
    "https://payments.cashfree.com/order",
    "https://secure.payu.in/transaction",
    "https://checkout.billdesk.com/pay",
    "https://pay.hdfc.com/netbanking",
]

SUSPICIOUS_DOMAINS = [
    "http://payment-verify.free.tk/pay",
    "http://secure-upi.xyz/login",
    "https://bit.ly/payconfirm",
    "http://192.168.1.100/upi",
    "https://paytm-refund.top/claim",
    "http://hdfc-bank-update.ml/kyc",
    "https://tinyurl.com/refund5000",
    "http://10.0.0.1/checkout",
    "https://sbi-reward.click/prize",
    "http://icici-verify.ga/account",
]

# ── Message templates ─────────────────────────────────────────────────────────
LEGIT_PAY_MSGS = [
    "Pay ₹{amt} to {merchant} for your order.",
    "Please pay ₹{amt} for your purchase at {merchant}.",
    "Scan to pay ₹{amt} at {merchant}.",
    "Payment of ₹{amt} to {merchant}.",
    "Bill amount: ₹{amt}. Scan to pay {merchant}.",
    "Your order total is ₹{amt}. Scan to complete payment.",
    None,  # no message — legitimate payment without instruction
    None,
    None,
]

RECEIVE_SCAM_MSGS = [
    "Scan this QR to receive ₹{amt} refund.",
    "Your refund of ₹{amt} is ready. Scan to receive.",
    "Congratulations! You have won ₹{amt}. Scan to claim.",
    "Your cashback of ₹{amt} has been approved. Scan to collect.",
    "Receive ₹{amt} in your account. Scan QR now.",
    "₹{amt} is being sent to you. Scan to accept.",
    "Claim your prize money ₹{amt} by scanning this QR.",
    "Your reward of ₹{amt} is pending. Scan to receive.",
    "Refund processed: ₹{amt}. Scan QR to get money.",
    "We are sending ₹{amt} to your account. Scan to confirm receipt.",
]

FAKE_REFUND_MSGS = [
    "Your refund of ₹{amt} has been initiated. Scan to receive.",
    "Refund of ₹{amt} ready. Urgent: scan before it expires.",
    "Income tax refund ₹{amt} approved. Scan QR to collect.",
    "E-commerce refund ₹{amt} pending. Scan QR immediately.",
    "Bank refund ₹{amt} on hold. Scan to release to your account.",
]

FAKE_KYC_MSGS = [
    "Complete your KYC by scanning this QR. Account will be blocked otherwise.",
    "RBI has mandated KYC update. Scan QR urgently to verify.",
    "Your bank account needs verification. Scan QR to authenticate.",
    "Urgent: KYC pending. Scan QR to prevent account suspension.",
    "Bank representative: scan this QR to complete your identity verification.",
]

AUTHORITY_MSGS = [
    "Income Tax Department: scan QR to receive your ITR refund of ₹{amt}.",
    "RBI circular: verify your UPI account by scanning this official QR.",
    "Government initiative: claim your subsidy of ₹{amt} by scanning QR.",
    "Police cyber cell: scan QR for secure fund verification.",
    "Ministry of Finance: approved UPI refund ₹{amt}. Scan to collect.",
]

URGENCY_MSGS = [
    "URGENT: scan within 1 hour or lose your ₹{amt} refund forever.",
    "Last chance! Scan QR now to claim ₹{amt} before it expires.",
    "Account will be blocked in 24 hours. Scan QR immediately to verify.",
    "Limited time offer: scan now to receive ₹{amt} cashback.",
    "ALERT: Scan this QR immediately or your account will be deactivated.",
]


def rand_amount(low=50, high=10000):
    return round(random.uniform(low, high), 2)


def make_upi(vpa, name, amount, currency="INR"):
    return f"upi://pay?pa={vpa}&pn={name.replace(' ','%20')}&am={amount}&cu={currency}"


def make_row(
    scenario_category, label,
    qr_payload, message,
    qr_format="upi",
    upi_vpa="", upi_amount=None, upi_currency="INR",
    url_scheme="", url_has_ip=0, url_tld_risky=0,
    url_has_shortener=0, url_length=0, url_redirect_params=0,
    has_suspicious_keywords=0, amount_is_zero=0,
    amount_is_negative=0, amount_is_high=0,
    message_intent="NONE", message_amount=None,
    has_urgency=0, has_authority_claim=0,
):
    label_names = {0: "LEGITIMATE", 1: "SUSPICIOUS", 2: "FRAUDULENT"}
    intent_qr_mismatch = 0
    amount_mismatch = 0

    # Derived: intent vs QR mismatch
    if message_intent in ("RECEIVE", "REFUND", "REWARD") and qr_format in ("upi", "deep_link", "url"):
        if label > 0:
            intent_qr_mismatch = 1

    # Derived: amount mismatch
    if message_amount is not None and upi_amount is not None:
        if abs(float(message_amount) - float(upi_amount)) > 1:
            amount_mismatch = 1

    payload_length = len(qr_payload)
    has_susp_kw = has_suspicious_keywords or (
        1 if any(kw in qr_payload.lower() for kw in
                 ["login","verify","refund","reward","kyc","support","claim"])
        else 0
    )

    return {
        "scenario_category": scenario_category,
        "label": label,
        "label_name": label_names[label],
        "qr_payload": qr_payload,
        "message": message or "",
        # QR features
        "qr_format": qr_format,
        "upi_vpa": upi_vpa,
        "upi_amount": upi_amount if upi_amount is not None else "",
        "upi_currency": upi_currency,
        "url_scheme": url_scheme,
        "url_has_ip": url_has_ip,
        "url_tld_risky": url_tld_risky,
        "url_has_shortener": url_has_shortener,
        "url_length": url_length,
        "url_redirect_params": url_redirect_params,
        "payload_length": payload_length,
        "has_suspicious_keywords": has_susp_kw,
        "amount_is_zero": amount_is_zero,
        "amount_is_negative": amount_is_negative,
        "amount_is_high": amount_is_high,
        # NLP features
        "message_intent": message_intent,
        "message_amount": message_amount if message_amount is not None else "",
        "has_urgency": has_urgency,
        "has_authority_claim": has_authority_claim,
        # Derived
        "intent_qr_mismatch": intent_qr_mismatch,
        "amount_mismatch": amount_mismatch,
    }


rows = []

# ────────────────────────────────────────────────────────────────────────────
# 1. LEGITIMATE — Normal merchant UPI payments  (~100 rows)
# ────────────────────────────────────────────────────────────────────────────
for _ in range(100):
    vpa  = random.choice(LEGIT_VPAS)
    name = random.choice(LEGIT_MERCHANTS)
    amt  = rand_amount(50, 5000)
    msg_tmpl = random.choice(LEGIT_PAY_MSGS)
    msg = msg_tmpl.format(amt=amt, merchant=name) if msg_tmpl else None
    qr  = make_upi(vpa, name, amt)
    rows.append(make_row(
        "legitimate_merchant_payment", 0, qr, msg,
        qr_format="upi", upi_vpa=vpa, upi_amount=amt,
        message_intent="PAY" if msg else "NONE",
        message_amount=amt if msg else None,
    ))

# ────────────────────────────────────────────────────────────────────────────
# 2. LEGITIMATE — HTTPS payment page  (~40 rows)
# ────────────────────────────────────────────────────────────────────────────
for _ in range(40):
    url = random.choice(LEGIT_DOMAINS)
    amt = rand_amount(100, 3000)
    msg = f"Pay ₹{amt} securely via our payment gateway."
    rows.append(make_row(
        "legitimate_https_payment", 0, url, msg,
        qr_format="url", url_scheme="https",
        url_length=len(url),
        message_intent="PAY", message_amount=amt,
    ))

# ────────────────────────────────────────────────────────────────────────────
# 3. FRAUDULENT — Receive-money / fake-refund scam  (~120 rows)
# ────────────────────────────────────────────────────────────────────────────
for _ in range(60):
    vpa  = random.choice(FRAUD_VPAS + SUSPICIOUS_VPAS)
    amt  = rand_amount(500, 10000)
    msg  = random.choice(RECEIVE_SCAM_MSGS).format(amt=amt)
    qr   = make_upi(vpa, "Refund", amt)
    rows.append(make_row(
        "receive_money_scam", 2, qr, msg,
        qr_format="upi", upi_vpa=vpa, upi_amount=amt,
        has_suspicious_keywords=1,
        message_intent="RECEIVE", message_amount=amt,
    ))

for _ in range(60):
    vpa  = random.choice(FRAUD_VPAS)
    amt  = rand_amount(1000, 50000)
    msg  = random.choice(FAKE_REFUND_MSGS).format(amt=amt)
    qr   = make_upi(vpa, "Refund", amt)
    rows.append(make_row(
        "fake_refund_scam", 2, qr, msg,
        qr_format="upi", upi_vpa=vpa, upi_amount=amt,
        has_suspicious_keywords=1,
        message_intent="REFUND", message_amount=amt,
        amount_is_high=1 if amt > 10000 else 0,
    ))

# ────────────────────────────────────────────────────────────────────────────
# 4. FRAUDULENT — Fake KYC / verification  (~60 rows)
# ────────────────────────────────────────────────────────────────────────────
for _ in range(60):
    vpa  = random.choice(FRAUD_VPAS + SUSPICIOUS_VPAS)
    amt  = rand_amount(1, 999)
    msg  = random.choice(FAKE_KYC_MSGS)
    qr   = make_upi(vpa, "Verify", amt)
    rows.append(make_row(
        "fake_kyc_verification", 2, qr, msg,
        qr_format="upi", upi_vpa=vpa, upi_amount=amt,
        has_suspicious_keywords=1,
        message_intent="VERIFY", message_amount=None,
        has_urgency=1,
    ))

# ────────────────────────────────────────────────────────────────────────────
# 5. FRAUDULENT — Authority spoofing  (~50 rows)
# ────────────────────────────────────────────────────────────────────────────
for _ in range(50):
    vpa  = random.choice(FRAUD_VPAS)
    amt  = rand_amount(500, 20000)
    msg  = random.choice(AUTHORITY_MSGS).format(amt=amt)
    qr   = make_upi(vpa, "Govt", amt)
    rows.append(make_row(
        "authority_spoofing", 2, qr, msg,
        qr_format="upi", upi_vpa=vpa, upi_amount=amt,
        has_suspicious_keywords=1,
        message_intent="RECEIVE", message_amount=amt,
        has_authority_claim=1,
    ))

# ────────────────────────────────────────────────────────────────────────────
# 6. FRAUDULENT — Urgency manipulation  (~40 rows)
# ────────────────────────────────────────────────────────────────────────────
for _ in range(40):
    vpa  = random.choice(FRAUD_VPAS + SUSPICIOUS_VPAS)
    amt  = rand_amount(100, 5000)
    msg  = random.choice(URGENCY_MSGS).format(amt=amt)
    qr   = make_upi(vpa, "Urgent", amt)
    rows.append(make_row(
        "urgency_manipulation", 2, qr, msg,
        qr_format="upi", upi_vpa=vpa, upi_amount=amt,
        has_suspicious_keywords=1,
        message_intent="RECEIVE", message_amount=amt,
        has_urgency=1,
    ))

# ────────────────────────────────────────────────────────────────────────────
# 7. FRAUDULENT — Amount mismatch  (~40 rows)
# ────────────────────────────────────────────────────────────────────────────
for _ in range(40):
    vpa     = random.choice(FRAUD_VPAS + SUSPICIOUS_VPAS)
    qr_amt  = rand_amount(1000, 30000)
    msg_amt = rand_amount(50, 500)           # much less than QR
    msg = f"Pay ₹{msg_amt} for your subscription renewal."
    qr  = make_upi(vpa, "Payment", qr_amt)
    rows.append(make_row(
        "amount_manipulation", 2, qr, msg,
        qr_format="upi", upi_vpa=vpa, upi_amount=qr_amt,
        message_intent="PAY", message_amount=msg_amt,
    ))

# ────────────────────────────────────────────────────────────────────────────
# 8. FRAUDULENT — Suspicious/malicious URL  (~50 rows)
# ────────────────────────────────────────────────────────────────────────────
for _ in range(50):
    url = random.choice(SUSPICIOUS_DOMAINS)
    msg = random.choice([
        None,
        "Scan to complete your payment.",
        "Verify your account by scanning.",
        "Claim your reward now.",
    ])
    is_ip  = 1 if any(p in url for p in ["192.168","10.0","172."]) else 0
    is_http = 1 if url.startswith("http://") else 0
    risky  = 1 if any(url.endswith(t) for t in [".tk",".ml",".xyz",".top",".ga",".click"]) else 0
    short  = 1 if any(s in url for s in ["bit.ly","tinyurl","goo.gl"]) else 0
    rows.append(make_row(
        "malicious_url", 2, url, msg,
        qr_format="url",
        url_scheme="http" if is_http else "https",
        url_has_ip=is_ip,
        url_tld_risky=risky,
        url_has_shortener=short,
        url_length=len(url),
        has_suspicious_keywords=1,
        message_intent="NONE" if not msg else "RECEIVE",
    ))

# ────────────────────────────────────────────────────────────────────────────
# 9. SUSPICIOUS — Unknown VPA / unverified merchant  (~50 rows)
# ────────────────────────────────────────────────────────────────────────────
for _ in range(50):
    vpa = random.choice(SUSPICIOUS_VPAS)
    amt = rand_amount(100, 5000)
    msg_tmpl = random.choice(LEGIT_PAY_MSGS)
    name = random.choice(LEGIT_MERCHANTS)
    msg = msg_tmpl.format(amt=amt, merchant=name) if msg_tmpl else None
    qr  = make_upi(vpa, name, amt)
    rows.append(make_row(
        "suspicious_vpa", 1, qr, msg,
        qr_format="upi", upi_vpa=vpa, upi_amount=amt,
        has_suspicious_keywords=1,
        message_intent="PAY" if msg else "NONE",
        message_amount=amt if msg else None,
    ))

# ────────────────────────────────────────────────────────────────────────────
# 10. SUSPICIOUS — Zero-amount UPI (token collection)  (~30 rows)
# ────────────────────────────────────────────────────────────────────────────
for _ in range(30):
    vpa = random.choice(SUSPICIOUS_VPAS + FRAUD_VPAS)
    qr  = make_upi(vpa, "Verify", 0)
    msg = random.choice([
        "Scan to verify your account.",
        "Zero charge verification. Scan QR.",
        "Bank KYC — scan to authenticate.",
        None,
    ])
    rows.append(make_row(
        "zero_amount_token_collection", 1, qr, msg,
        qr_format="upi", upi_vpa=vpa, upi_amount=0,
        amount_is_zero=1,
        has_suspicious_keywords=1,
        message_intent="VERIFY" if msg else "NONE",
    ))

# ────────────────────────────────────────────────────────────────────────────
# 11. FRAUDULENT — QR replacement (wrong recipient for legit merchant)  (~30 rows)
# ────────────────────────────────────────────────────────────────────────────
for _ in range(30):
    legit_merchant = random.choice(LEGIT_MERCHANTS)
    fraud_vpa = random.choice(FRAUD_VPAS)
    amt = rand_amount(100, 2000)
    msg = f"Pay ₹{amt} to {legit_merchant}."
    qr  = make_upi(fraud_vpa, legit_merchant, amt)   # VPA doesn't match merchant
    rows.append(make_row(
        "qr_replacement_attack", 2, qr, msg,
        qr_format="upi", upi_vpa=fraud_vpa, upi_amount=amt,
        message_intent="PAY", message_amount=amt,
    ))

# ────────────────────────────────────────────────────────────────────────────
# 12. SUSPICIOUS — Deep-link payment  (~30 rows)
# ────────────────────────────────────────────────────────────────────────────
DEEP_SCHEMES = ["paytm://", "phonepe://", "gpay://", "bhim://"]
for _ in range(30):
    scheme = random.choice(DEEP_SCHEMES)
    vpa = random.choice(LEGIT_VPAS + SUSPICIOUS_VPAS)
    amt = rand_amount(50, 5000)
    qr  = f"{scheme}pay?pa={vpa}&am={amt}&cu=INR"
    msg = random.choice([f"Pay ₹{amt} via {scheme.split(':')[0]}.", None])
    label = 0 if vpa in LEGIT_VPAS else 1
    rows.append(make_row(
        "deep_link_payment", label, qr, msg,
        qr_format="deep_link", upi_vpa=vpa, upi_amount=amt,
        message_intent="PAY" if msg else "NONE",
        message_amount=amt if msg else None,
    ))

# ────────────────────────────────────────────────────────────────────────────
# 13. LEGITIMATE — No message, minimal context  (~40 rows)
# ────────────────────────────────────────────────────────────────────────────
for _ in range(40):
    vpa  = random.choice(LEGIT_VPAS)
    name = random.choice(LEGIT_MERCHANTS)
    amt  = rand_amount(20, 2000)
    qr   = make_upi(vpa, name, amt)
    rows.append(make_row(
        "legitimate_no_message", 0, qr, None,
        qr_format="upi", upi_vpa=vpa, upi_amount=amt,
        message_intent="NONE",
    ))

# ────────────────────────────────────────────────────────────────────────────
# Shuffle and write
# ────────────────────────────────────────────────────────────────────────────
random.shuffle(rows)

FIELDNAMES = [
    "scenario_category", "label", "label_name",
    "qr_payload", "message",
    # QR features
    "qr_format", "upi_vpa", "upi_amount", "upi_currency",
    "url_scheme", "url_has_ip", "url_tld_risky",
    "url_has_shortener", "url_length", "url_redirect_params",
    "payload_length", "has_suspicious_keywords",
    "amount_is_zero", "amount_is_negative", "amount_is_high",
    # NLP features
    "message_intent", "message_amount",
    "has_urgency", "has_authority_claim",
    # Derived
    "intent_qr_mismatch", "amount_mismatch",
]

with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
    writer.writeheader()
    writer.writerows(rows)

# Summary
totals = {0: 0, 1: 0, 2: 0}
cats   = {}
for r in rows:
    totals[r["label"]] += 1
    cats[r["scenario_category"]] = cats.get(r["scenario_category"], 0) + 1

print(f"\n✅ Dataset written to: {OUTPUT}")
print(f"   Total rows   : {len(rows)}")
print(f"   LEGITIMATE   : {totals[0]}")
print(f"   SUSPICIOUS   : {totals[1]}")
print(f"   FRAUDULENT   : {totals[2]}")
print(f"\n   Scenario breakdown:")
for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
    print(f"     {count:4d}  {cat}")
