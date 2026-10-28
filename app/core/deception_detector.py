"""
QRShield – NLP Deception Detector  (Module 3)
=============================================
Central research contribution of QRShield.

The key insight from the synopsis:
  A QR code can look normal while the actual transaction differs from
  what the user was told.

  Example:
    Message: "Scan this QR to receive ₹5,000."
    QR:       upi://pay?pa=attacker@upi&am=5000
    → The user is being tricked into PAYING, not receiving.

This module:
  1. Extracts structured intent from a free-text message using
     keyword/pattern NLP (no external model needed).
  2. Derives the actual QR action from the parsed payload.
  3. Compares them and surfaces deception findings.
  4. Returns a DeceptionResult that feeds into the risk engine.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from app.core.url_analyzer import Finding, Severity, SEVERITY_WEIGHTS

logger = logging.getLogger(__name__)


# ── Intent taxonomy ───────────────────────────────────────────────────────────

class Intent(str, Enum):
    PAY          = "PAY"           # user wants to make a payment
    RECEIVE      = "RECEIVE"       # user expects to receive money
    REFUND       = "REFUND"        # fake/real refund scenario
    VERIFY       = "VERIFY"        # KYC / account verification
    REWARD       = "REWARD"        # cashback / prize / reward
    DONATION     = "DONATION"      # charitable payment
    UNKNOWN      = "UNKNOWN"


class QRAction(str, Enum):
    PAY          = "PAY"           # QR initiates a payment from user
    RECEIVE      = "RECEIVE"       # QR collects payment to user (collect request)
    UNKNOWN      = "UNKNOWN"


class DeceptionType(str, Enum):
    NONE                    = "NONE"
    PAY_RECEIVE_MISMATCH    = "PAY_RECEIVE_MISMATCH"    # told RECEIVE, QR says PAY
    AMOUNT_MISMATCH         = "AMOUNT_MISMATCH"         # told ₹X, QR says ₹Y
    FAKE_REFUND             = "FAKE_REFUND"             # fake refund → payment
    FAKE_REWARD             = "FAKE_REWARD"             # cashback/prize → payment
    FAKE_VERIFY             = "FAKE_VERIFY"             # verification → payment
    FAKE_RECEIVE            = "FAKE_RECEIVE"            # "receive" framing → payment
    URGENCY_MANIPULATION    = "URGENCY_MANIPULATION"    # "urgent/expires soon" pressure
    AUTHORITY_SPOOFING      = "AUTHORITY_SPOOFING"      # impersonating bank/govt
    SUSPICIOUS_PURPOSE      = "SUSPICIOUS_PURPOSE"      # suspicious purpose keywords


# ── Keyword lists ─────────────────────────────────────────────────────────────

# Words that indicate the user EXPECTS to receive money
RECEIVE_KEYWORDS = [
    "receive", "get", "collect", "claim", "credit", "credited",
    "cashback", "refund", "reward", "prize", "winning", "won",
    "bonus", "gift", "return", "reimburse", "reimbursement",
    "payment received", "money back", "back into your account",
    "transfer to you", "sending you", "sent you",
]

# Words that indicate a payment action
PAY_KEYWORDS = [
    "pay", "payment", "paying", "paid", "send", "transfer",
    "debit", "charge", "purchase", "buy", "order", "checkout",
    "invoice", "bill", "fee", "dues",
]

# Refund-specific patterns
REFUND_KEYWORDS = [
    "refund", "refunding", "return your money", "money back",
    "reimbursement", "reimburse", "reversal", "reversed",
    "credit back", "credited back",
]

# Reward/cashback patterns
REWARD_KEYWORDS = [
    "cashback", "reward", "prize", "won", "winner", "lucky",
    "bonus", "gift", "offer", "congratulations", "congrats",
    "selected", "eligible", "free", "discount",
]

# Verification/KYC patterns
VERIFY_KEYWORDS = [
    "verify", "verification", "kyc", "authenticate", "authentication",
    "confirm", "complete your kyc", "update your kyc", "bank verification",
    "account verification", "otp verification",
]

# Urgency manipulation patterns
URGENCY_KEYWORDS = [
    "urgent", "immediately", "expires", "expiry", "last chance",
    "limited time", "act now", "do it now", "hurry", "deadline",
    "today only", "within 24 hours", "within 1 hour", "asap",
    "account will be blocked", "account blocked", "suspended",
    "will be deactivated", "legal action",
]

# Authority spoofing patterns
AUTHORITY_KEYWORDS = [
    "rbi", "reserve bank", "income tax", "it department", "sebi",
    "government", "govt", "ministry", "police", "court",
    "bank helpdesk", "customer care", "official", "authorised",
    "from your bank", "bank representative",
]

# Amount extraction pattern
_AMOUNT_RE = re.compile(
    r"(?:rs\.?|₹|inr)\s*([0-9,]+(?:\.[0-9]{1,2})?)"
    r"|([0-9,]+(?:\.[0-9]{1,2})?)\s*(?:rs\.?|₹|rupees?|inr)",
    re.IGNORECASE,
)


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class MessageIntent:
    """Structured intent extracted from free-text message."""
    raw_message:    str
    intent:         Intent
    amounts:        List[float]                  # all amounts mentioned
    primary_amount: Optional[float]              # most prominent amount
    purpose:        Optional[str]                # refund / reward / verify etc.
    urgency:        bool = False
    authority_claim: bool = False
    confidence:     float = 0.0                  # 0–1, how confident the intent is


@dataclass
class DeceptionResult:
    """Output of the deception detection comparison."""
    deception_types:     List[DeceptionType] = field(default_factory=list)
    findings:            List[Finding]       = field(default_factory=list)
    raw_score_contribution: int = 0
    message_intent:      Optional[MessageIntent] = None
    qr_action:           QRAction = QRAction.UNKNOWN
    qr_amount:           Optional[float] = None
    qr_vpa:              Optional[str]  = None
    is_deceptive:        bool = False
    summary:             str  = ""

    def add(self, rule: str, severity: Severity,
            description: str, evidence: Optional[str] = None) -> None:
        self.findings.append(Finding(rule, severity, description, evidence))
        self.raw_score_contribution += SEVERITY_WEIGHTS[severity]


# ── NLP helpers ───────────────────────────────────────────────────────────────

def _extract_amounts(text: str) -> List[float]:
    amounts = []
    for m in _AMOUNT_RE.finditer(text):
        raw = (m.group(1) or m.group(2) or "").replace(",", "")
        try:
            amounts.append(float(raw))
        except ValueError:
            pass
    return amounts


def _count_keywords(text: str, keywords: List[str]) -> int:
    lower = text.lower()
    return sum(1 for kw in keywords if kw in lower)


def extract_message_intent(message: str) -> MessageIntent:
    """
    Rule-based NLP intent extractor.
    Returns a MessageIntent from a free-text payment instruction.
    """
    lower = message.lower()
    amounts = _extract_amounts(message)
    primary_amount = amounts[0] if amounts else None

    # Score each intent
    scores: Dict[Intent, float] = {i: 0.0 for i in Intent}

    receive_score = _count_keywords(lower, RECEIVE_KEYWORDS)
    pay_score     = _count_keywords(lower, PAY_KEYWORDS)
    refund_score  = _count_keywords(lower, REFUND_KEYWORDS)
    reward_score  = _count_keywords(lower, REWARD_KEYWORDS)
    verify_score  = _count_keywords(lower, VERIFY_KEYWORDS)

    scores[Intent.RECEIVE]  = receive_score * 1.0
    scores[Intent.PAY]      = pay_score     * 1.0
    scores[Intent.REFUND]   = refund_score  * 1.5   # refund has strong signal
    scores[Intent.REWARD]   = reward_score  * 1.5
    scores[Intent.VERIFY]   = verify_score  * 1.5

    # Refund / reward / verify all imply RECEIVE intent
    if refund_score > 0: scores[Intent.RECEIVE] += refund_score * 0.8
    if reward_score > 0: scores[Intent.RECEIVE] += reward_score * 0.8
    if verify_score > 0: scores[Intent.RECEIVE] += verify_score * 0.3

    # Determine top intent
    best_intent = max(scores, key=lambda i: scores[i])
    best_score  = scores[best_intent]

    if best_score == 0:
        intent = Intent.UNKNOWN
        confidence = 0.0
    else:
        intent = best_intent
        total = sum(scores.values()) or 1
        confidence = min(1.0, best_score / total + 0.2)

    # Purpose label
    purpose = None
    if refund_score > 0:  purpose = "REFUND"
    elif reward_score > 0: purpose = "REWARD/CASHBACK"
    elif verify_score > 0: purpose = "VERIFICATION"
    elif receive_score > 0: purpose = "RECEIVE"
    elif pay_score > 0:    purpose = "PAYMENT"

    urgency         = _count_keywords(lower, URGENCY_KEYWORDS) > 0
    authority_claim = _count_keywords(lower, AUTHORITY_KEYWORDS) > 0

    return MessageIntent(
        raw_message=message,
        intent=intent,
        amounts=amounts,
        primary_amount=primary_amount,
        purpose=purpose,
        urgency=urgency,
        authority_claim=authority_claim,
        confidence=confidence,
    )


# ── QR action derivation ──────────────────────────────────────────────────────

def derive_qr_action(parsed_payload) -> Tuple[QRAction, Optional[float], Optional[str]]:
    """
    Derive what the QR code actually *does* from the parsed payload.
    Returns (action, amount, vpa).
    """
    fmt = getattr(parsed_payload, "format", "unknown")
    fields = getattr(parsed_payload, "fields", {})

    vpa    = fields.get("vpa") or fields.get("pa") or None
    amount_str = fields.get("amount") or fields.get("am") or ""

    amount: Optional[float] = None
    try:
        if amount_str:
            amount = float(str(amount_str).replace(",", ""))
    except (ValueError, TypeError):
        pass

    # UPI pay: always a payment FROM the user
    if fmt == "upi":
        # UPI collect requests use 'mc' (merchant code) or mode=collect
        params = fields.get("all_params") or {}
        mode = str(params.get("mode", [""])[0]).lower() if isinstance(params, dict) else ""
        if mode == "collect":
            return QRAction.RECEIVE, amount, vpa
        return QRAction.PAY, amount, vpa

    # Deep links — generally payment initiators
    if fmt == "deep_link":
        return QRAction.PAY, amount, vpa

    # HTTPS payment page — assumed PAY
    if fmt == "url":
        return QRAction.PAY, amount, vpa

    return QRAction.UNKNOWN, amount, vpa


# ── Core deception checks ─────────────────────────────────────────────────────

def _check_pay_receive_mismatch(
    intent: MessageIntent, qr_action: QRAction, result: DeceptionResult
) -> None:
    """
    The core deception: message says RECEIVE, QR says PAY.
    This catches: fake refund, fake cashback, fake receive-money scams.
    """
    if intent.intent in (Intent.RECEIVE, Intent.REFUND, Intent.REWARD) \
            and qr_action == QRAction.PAY:

        dtype = DeceptionType.FAKE_REFUND  if intent.intent == Intent.REFUND \
           else DeceptionType.FAKE_REWARD  if intent.intent == Intent.REWARD  \
           else DeceptionType.FAKE_RECEIVE

        result.deception_types.append(dtype)
        result.add(
            "PAY_RECEIVE_MISMATCH", Severity.CRITICAL,
            f"🚨 PAYMENT DECEPTION DETECTED: The message implies you will "
            f"RECEIVE money ({intent.purpose or 'RECEIVE'}), but the QR code "
            f"initiates a PAYMENT from your account.",
            evidence=f"Message intent={intent.intent.value}, QR action=PAY",
        )


def _check_amount_mismatch(
    intent: MessageIntent, qr_amount: Optional[float], result: DeceptionResult
) -> None:
    """Flag when the amount in the message differs from the QR amount."""
    if intent.primary_amount is None or qr_amount is None:
        return
    if abs(intent.primary_amount - qr_amount) < 0.01:
        return  # match — no issue

    pct_diff = abs(intent.primary_amount - qr_amount) / max(intent.primary_amount, 1) * 100
    sev = Severity.CRITICAL if pct_diff > 50 else Severity.HIGH

    result.deception_types.append(DeceptionType.AMOUNT_MISMATCH)
    result.add(
        "AMOUNT_MISMATCH", sev,
        f"Amount mismatch: message mentions ₹{intent.primary_amount:,.2f} "
        f"but QR encodes ₹{qr_amount:,.2f} "
        f"(difference: {pct_diff:.0f}%).",
        evidence=f"message_amount=₹{intent.primary_amount}, qr_amount=₹{qr_amount}",
    )


def _check_fake_verify(
    intent: MessageIntent, qr_action: QRAction, result: DeceptionResult
) -> None:
    """Verification/KYC QR that actually initiates a payment."""
    if intent.intent == Intent.VERIFY and qr_action == QRAction.PAY:
        result.deception_types.append(DeceptionType.FAKE_VERIFY)
        result.add(
            "FAKE_VERIFICATION_PAYMENT", Severity.CRITICAL,
            "The message claims to be a KYC/verification request but the QR "
            "initiates a payment from your account. Banks never ask you to pay "
            "to verify your account.",
            evidence="intent=VERIFY, qr=PAY",
        )


def _check_urgency(intent: MessageIntent, result: DeceptionResult) -> None:
    if intent.urgency:
        result.deception_types.append(DeceptionType.URGENCY_MANIPULATION)
        result.add(
            "URGENCY_MANIPULATION", Severity.HIGH,
            "The message uses urgency language to pressure you into scanning "
            "quickly ('urgent', 'expires', 'account blocked', etc.). "
            "Legitimate payment requests are never time-pressured.",
            evidence="urgency keywords detected",
        )


def _check_authority(intent: MessageIntent, result: DeceptionResult) -> None:
    if intent.authority_claim:
        result.deception_types.append(DeceptionType.AUTHORITY_SPOOFING)
        result.add(
            "AUTHORITY_SPOOFING", Severity.HIGH,
            "The message claims to be from an authority (RBI, bank, government, "
            "police, etc.). Legitimate government/bank communications never "
            "ask you to scan QR codes.",
            evidence="authority keywords detected",
        )


def _check_suspicious_purpose(
    intent: MessageIntent, qr_action: QRAction, result: DeceptionResult
) -> None:
    """General suspicious-purpose check even without clear mismatch."""
    if intent.purpose in ("REWARD/CASHBACK", "REFUND") and qr_action == QRAction.UNKNOWN:
        result.deception_types.append(DeceptionType.SUSPICIOUS_PURPOSE)
        result.add(
            "SUSPICIOUS_PURPOSE_QR", Severity.MEDIUM,
            f"Message claims a '{intent.purpose}' purpose. Verify the QR "
            "directly with the merchant before scanning — fake refund and "
            "cashback QR scams are common.",
        )


# ── Build summary ─────────────────────────────────────────────────────────────

def _build_summary(result: DeceptionResult, intent: MessageIntent) -> str:
    if not result.deception_types or DeceptionType.NONE in result.deception_types:
        if intent.intent == Intent.UNKNOWN:
            return "No message provided or intent could not be determined."
        return (
            f"Message intent ({intent.intent.value}) appears consistent "
            f"with the QR action ({result.qr_action.value})."
        )

    lines = ["🚨 DECEPTION DETECTED\n"]
    lines.append(f"  Message:    \"{intent.raw_message[:120]}\"")
    lines.append(f"  Msg intent: {intent.intent.value}"
                 + (f" — ₹{intent.primary_amount:,.2f}" if intent.primary_amount else ""))
    lines.append(f"  QR action:  {result.qr_action.value}"
                 + (f" — ₹{result.qr_amount:,.2f}" if result.qr_amount else ""))
    if result.qr_vpa:
        lines.append(f"  Recipient:  {result.qr_vpa}")
    lines.append(f"\n  Detected issues:")
    for dtype in set(result.deception_types):
        lines.append(f"    • {dtype.value.replace('_', ' ')}")
    lines.append("\n  ⚠️  Do NOT authorize this transaction.")
    return "\n".join(lines)


# ── Public entry point ────────────────────────────────────────────────────────

def detect_deception(
    message: Optional[str],
    parsed_payload,
) -> DeceptionResult:
    """
    Main entry point.
    Accepts the user-supplied message (may be None) and the ParsedPayload.
    Returns a DeceptionResult with findings and score contribution.
    """
    result = DeceptionResult()

    # Derive QR action
    qr_action, qr_amount, qr_vpa = derive_qr_action(parsed_payload)
    result.qr_action = qr_action
    result.qr_amount = qr_amount
    result.qr_vpa    = qr_vpa

    # No message → nothing to compare
    if not message or not message.strip():
        result.summary = "No accompanying message provided — context analysis skipped."
        return result

    # Extract intent from message
    intent = extract_message_intent(message.strip())
    result.message_intent = intent

    # Run all deception checks
    _check_pay_receive_mismatch(intent, qr_action, result)
    _check_amount_mismatch(intent, qr_amount, result)
    _check_fake_verify(intent, qr_action, result)
    _check_urgency(intent, result)
    _check_authority(intent, result)
    _check_suspicious_purpose(intent, qr_action, result)

    result.is_deceptive = any(
        dt not in (DeceptionType.NONE, DeceptionType.URGENCY_MANIPULATION)
        for dt in result.deception_types
    ) or (
        result.raw_score_contribution >= SEVERITY_WEIGHTS[Severity.CRITICAL]
    )

    result.summary = _build_summary(result, intent)
    return result
