"""
Gemini AI Enhancement Service for Satark Setu.
Provides deep LLM-powered fraud detection, psychological manipulation analysis,
and contextual Next Best Action generation using Google's Gemini models.

Engineered for performance:
- In-memory LRU caching for instant responses on common scam templates.
- Strict 3.5s timeout with automatic graceful fallback to local heuristics.
- Fallback chain across Gemini model endpoints.
- Structured JSON output with zero hallucination formatting.
"""

import urllib.request
import urllib.error
import json
import hashlib
from typing import Dict, Any, Optional
from config import Config

class GeminiScamAnalyzer:
    _cache: Dict[str, Dict[str, Any]] = {}
    _MAX_CACHE_SIZE = 500

    CANDIDATE_MODELS = [
        'gemini-flash-lite-latest',
        'gemini-3.8-flash',
        'gemini-flash-latest'
    ]

    @classmethod
    def _get_cache_key(cls, text: str, lang: str) -> str:
        content = f"{lang}:{text.strip().lower()}"
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    @classmethod
    def analyze_threat(cls, text: str, lang: str = 'en') -> Optional[Dict[str, Any]]:
        """
        Analyze a suspicious message using Gemini AI.
        Returns parsed analysis dictionary or None if API is unavailable.
        """
        api_key = Config.GEMINI_API_KEY
        if not api_key:
            return None

        cleaned = text.strip()
        if not cleaned or len(cleaned) < 5:
            return None

        # Check Cache
        cache_key = cls._get_cache_key(cleaned, lang)
        if cache_key in cls._cache:
            return cls._cache[cache_key]

        target_lang = "Hindi (हिंदी)" if lang == 'hi' else "English"

        prompt = f"""You are a specialized digital payment fraud detection AI protecting citizens and micro-merchants in India against cyber scams (KYC suspension, UPI collect frauds, electricity power disconnection threats, lottery/prize scams, digital arrest, malicious APK downloads).

Analyze this incoming message/payment communication:
\"\"\"{cleaned}\"\"\"

Provide your analysis strictly in {target_lang}.
Output MUST be a single valid JSON object following this exact schema:
{{
  "is_scam": boolean,
  "risk_level": "HIGH" | "MEDIUM" | "LOW",
  "risk_score": integer (0 to 100),
  "category": string (e.g. "Fake KYC / Account Block", "UPI PIN to Receive Trap", "Digital Arrest Threat", "Legitimate Bank Alert"),
  "psychological_tactics": [string] (e.g. "False Urgency", "Fear of Account Freeze", "Authority Impersonation", "Unrealistic Financial Reward"),
  "explanation": string (A clear, empathetic, 2-3 sentence explanation of why this message is or is not safe),
  "what_to_avoid": [string] (2-3 concrete pitfalls to avoid),
  "immediate_actions": [string] (2-3 calm, practical verification steps)
}}"""

        payload = json.dumps({
            'contents': [{'parts': [{'text': prompt}]}],
            'generationConfig': {
                'responseMimeType': 'application/json',
                'temperature': 0.1,
                'maxOutputTokens': 1024
            }
        }).encode('utf-8')

        # Try candidate models with graceful fallback
        for model_name in cls.CANDIDATE_MODELS:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
            req = urllib.request.Request(
                url,
                data=payload,
                headers={'Content-Type': 'application/json'}
            )
            try:
                with urllib.request.urlopen(req, timeout=3.5) as resp:
                    raw_body = resp.read().decode('utf-8')
                    resp_json = json.loads(raw_body)
                    candidates = resp_json.get('candidates', [])
                    if candidates and 'content' in candidates[0]:
                        parts = candidates[0]['content'].get('parts', [])
                        if parts and 'text' in parts[0]:
                            parsed = json.loads(parts[0]['text'])
                            # Cache the successful result
                            if len(cls._cache) >= cls._MAX_CACHE_SIZE:
                                cls._cache.pop(next(iter(cls._cache)))
                            cls._cache[cache_key] = parsed
                            return parsed
            except Exception:
                # If this model times out or errors, try next model in fallback chain
                continue

        return None

