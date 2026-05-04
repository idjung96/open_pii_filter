"""Custom Presidio recognizers for Korean PII (§1.2)."""

from __future__ import annotations

from app.core.recognizers.kr_bank_account import (
    KrBankAccountStrongRecognizer,
    KrBankAccountWeakRecognizer,
)
from app.core.recognizers.kr_business_num import KrBusinessNumRecognizer
from app.core.recognizers.kr_driver_license import KrDriverLicenseRecognizer
from app.core.recognizers.kr_passport import KrPassportRecognizer
from app.core.recognizers.kr_phone import KrPhoneRecognizer
from app.core.recognizers.kr_rrn import KrRrnRecognizer

__all__ = [
    "KrBankAccountStrongRecognizer",
    "KrBankAccountWeakRecognizer",
    "KrBusinessNumRecognizer",
    "KrDriverLicenseRecognizer",
    "KrPassportRecognizer",
    "KrPhoneRecognizer",
    "KrRrnRecognizer",
]
