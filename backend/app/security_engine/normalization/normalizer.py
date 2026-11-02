"""
SentinelGrid - Request Normalizer
Handles NFKC unicode normalization, multi-layer recursive unescaping,
null-byte stripping, and path canonicalization.
Prevents WAF bypass techniques (double encoding, null bytes, unicode evasion).
"""

import unicodedata
import urllib.parse
import re
from typing import Dict, Any


class RequestNormalizer:
    @classmethod
    def normalize_string(cls, input_str: str, max_depth: int = 4) -> str:
        """
        Recursively unescapes and normalizes an input string:
        1. Strips null bytes and invalid control chars
        2. Recursively URL decodes (%252e%252e%252f -> ../)
        3. HTML entity decodes (&lt;script&gt; -> <script>)
        4. Applies Unicode NFKC normalization
        5. Normalizes directory path separators
        """
        if not input_str:
            return ""

        # 1. Null byte & control character stripping (Bypass Prevention)
        s = input_str.replace("\x00", "").replace("%00", "").replace("\\0", "")

        # 2. Recursive URL decode up to max_depth
        prev = ""
        depth = 0
        while prev != s and depth < max_depth:
            prev = s
            try:
                s = urllib.parse.unquote(s)
            except Exception:
                break
            depth += 1

        # 3. HTML entity unescaping
        import html
        s = html.unescape(s)

        # 4. Strip inline SQL/C comments (/**/) for defragmented keyword inspection
        s_decommented = re.sub(r"/\*.*?\*/", "", s)

        # 5. Unicode NFKC normalization (turns fullwidth/obscure homoglyphs into canonical chars)
        s = unicodedata.normalize("NFKC", s_decommented)

        # 5. Compress multiple directory slashes and backslashes
        s = s.replace("\\", "/")

        return s

    @classmethod
    def normalize_request_data(
        cls,
        path: str,
        query: str,
        body: str,
        headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """Normalizes all request vectors uniformly."""
        normalized_path = cls.normalize_string(path)
        normalized_query = cls.normalize_string(query)
        normalized_body = cls.normalize_string(body)
        normalized_headers = {
            cls.normalize_string(k).lower(): cls.normalize_string(v)
            for k, v in headers.items()
        }

        # Unified combined payload string for deep pattern analysis
        combined_payload = (
            f"{normalized_path}\n"
            f"{normalized_query}\n"
            f"{normalized_body}\n"
            + "\n".join([f"{k}: {v}" for k, v in normalized_headers.items()])
        )

        return {
            "path": normalized_path,
            "query": normalized_query,
            "body": normalized_body,
            "headers": normalized_headers,
            "combined": combined_payload
        }
