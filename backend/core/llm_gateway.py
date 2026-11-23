"""跨境模型经过 OUTBOUND_PROXY，国内通道不使用该代理。"""
from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx

from core.policy import CompliancePolicyError, gemini_safety_settings
from core.secrets import decrypt_secret


def proxy_for_profile(profile: dict) -> str | None:
    if not profile.get("is_cross_border"):
        return None
    name = profile.get("proxy_env") or "OUTBOUND_PROXY"
    proxy = os.environ.get(name, "").strip()
    if not proxy:
        raise CompliancePolicyError("跨境模型要先配置 OUTBOUND_PROXY，请求经该代理发出")
    return proxy


def resolve_api_key(profile: dict) -> str:
    if profile.get("auth_mode") == "encrypted_key":
        return decrypt_secret(profile.get("api_key_encrypted") or "")
    env_name = (profile.get("api_key_env") or "").strip()
    if env_name:
        return os.environ.get(env_name, "").strip()
    model = str(profile.get("fast_mapper_model", ""))
    if "gemini" in model:
        return os.environ.get("GEMINI_API_KEY", "").strip()
    return ""


def model_id_of(profile: dict, slot: str = "fast") -> str:
    # 报告研判等深度分析优先使用 deep_reasoner_model，缺省回退到 fast_mapper_model。
    raw = profile.get("deep_reasoner_model") if slot == "deep" else profile.get("fast_mapper_model")
    model = str(raw or profile.get("fast_mapper_model") or "")
    return model.split("/", 1)[-1]


def _parse_json_text(text: str) -> dict:
    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    return json.loads(cleaned)


def review_with_profile(
    profile: dict,
    prompt: str,
    *,
    system_prompt: str = "",
    model_slot: str = "fast",
    timeout: float = 60.0,
    temperature: float = 0.1,
) -> dict[str, Any]:
    provider = profile.get("provider") or ""
    model = str(profile.get("deep_reasoner_model") if model_slot == "deep" else profile.get("fast_mapper_model") or "")
    if not model:
        model = str(profile.get("fast_mapper_model", ""))
    if provider == "local_rules" or model.startswith("local/"):
        return {"status": "skipped", "model_id": model_id_of(profile, model_slot), "error_detail": "本地规则通道不调用远程模型"}
    if provider == "gemini" or "gemini" in model:
        return review_with_gemini(
            profile,
            prompt,
            system_prompt=system_prompt,
            model_slot=model_slot,
            timeout=timeout,
            temperature=temperature,
        )
    return review_openai_compatible(
        profile,
        prompt,
        system_prompt=system_prompt,
        model_slot=model_slot,
        timeout=timeout,
        temperature=temperature,
    )


def review_with_gemini(
    profile: dict,
    prompt: str,
    *,
    system_prompt: str = "",
    model_slot: str = "fast",
    timeout: float = 60.0,
    temperature: float = 0.1,
) -> dict[str, Any]:
    proxy = proxy_for_profile(profile)
    api_key = resolve_api_key(profile)
    model_id = model_id_of(profile, model_slot) or "gemini-2.0-flash"
    if not api_key:
        return {"status": "skipped", "model_id": model_id, "error_detail": "跨境代理已就绪，缺少 API Key"}
    safety = gemini_safety_settings(profile) or []
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent"
    started = time.perf_counter()
    body: dict[str, Any] = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "safetySettings": safety,
        "generationConfig": {"temperature": temperature, "responseMimeType": "application/json"},
    }
    if system_prompt.strip():
        body["systemInstruction"] = {"parts": [{"text": system_prompt.strip()}]}
    response = httpx.post(
        url,
        headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
        json=body,
        proxy=proxy,
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    text = payload["candidates"][0]["content"]["parts"][0]["text"]
    return {
        "status": "ok",
        "model_id": model_id,
        "text": text,
        "parsed": _parse_json_text(text),
        "latency_ms": int((time.perf_counter() - started) * 1000),
    }


def review_openai_compatible(
    profile: dict,
    prompt: str,
    *,
    system_prompt: str = "",
    model_slot: str = "fast",
    timeout: float = 60.0,
    temperature: float = 0.1,
) -> dict[str, Any]:
    # 国内或本地模型明确不走跨境代理。
    if profile.get("is_cross_border"):
        proxy_for_profile(profile)
    api_key = resolve_api_key(profile)
    model_id = model_id_of(profile, model_slot)
    base = (profile.get("api_base") or "").rstrip("/")
    if not base:
        return {"status": "skipped", "model_id": model_id, "error_detail": "未配置 API Base"}
    if not api_key and "127.0.0.1" not in base and "localhost" not in base:
        return {"status": "skipped", "model_id": model_id, "error_detail": "缺少 API Key"}
    url = base if base.endswith("/chat/completions") else f"{base}/chat/completions"
    started = time.perf_counter()
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    messages: list[dict[str, str]] = []
    if system_prompt.strip():
        messages.append({"role": "system", "content": system_prompt.strip()})
    messages.append({"role": "user", "content": prompt})
    response = httpx.post(
        url,
        headers=headers,
        json={
            "model": model_id,
            "temperature": temperature,
            "messages": messages,
            "response_format": {"type": "json_object"},
        },
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    text = payload["choices"][0]["message"]["content"]
    return {
        "status": "ok",
        "model_id": model_id,
        "text": text,
        "parsed": _parse_json_text(text),
        "latency_ms": int((time.perf_counter() - started) * 1000),
    }


def test_profile(profile: dict) -> dict[str, Any]:
    started = time.perf_counter()
    if profile.get("provider") == "local_rules":
        return {"ok": True, "latency_ms": 0, "model_id": model_id_of(profile), "detail": "本地规则通道无需联网"}
    try:
        if profile.get("is_cross_border"):
            proxy_for_profile(profile)
        result = review_with_profile(profile, '只返回 JSON：{"ok":true,"note":"连通"}')
    except Exception as exc:
        return {"ok": False, "latency_ms": int((time.perf_counter() - started) * 1000), "model_id": model_id_of(profile), "detail": str(exc)}
    ok = result.get("status") == "ok"
    return {
        "ok": ok,
        "latency_ms": result.get("latency_ms") or int((time.perf_counter() - started) * 1000),
        "model_id": result.get("model_id"),
        "detail": "连通正常" if ok else (result.get("error_detail") or result.get("status")),
    }
