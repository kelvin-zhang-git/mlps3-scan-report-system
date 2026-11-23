"""模型密钥只以 Fernet 密文入库，接口层只回传掩码。"""
from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from core.settings import vault_key


def encrypt_secret(plain: str) -> str:
    return Fernet(vault_key().encode()).encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt_secret(token: str) -> str:
    if not token:
        return ""
    try:
        return Fernet(vault_key().encode()).decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""


def mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}****{value[-4:]}"
