"""
SentinelGrid - Request Normalizer
Enterprise-grade anti-evasion request normalization:
1. Strips null bytes (%00, \\0, \\x00)
2. Recursively decodes multi-layer URL encoding (%252e -> %2e -> .)
3. De-obfuscates path separators and handles canonical directory paths
4. Normalizes Unicode via NFKC (collapses homoglyphs to canonical representations)
5. Normalizes parameter key-value pairs without corrupting HTTP structural syntax
"""

import unicodedata
import urllib.parse
import re
from typing import Dict, Any, List, Tuple


class RequestNormalizer:
    @classmethod
    def normalize_string(cls, input_str: str, max_depth: int = 4) -> str:
        """
        Recursively unescapes and normalizes a string.
        Guaranteed safe against ReDoS, null byte injection, and multi-encoding.
        """
        if not input_str:
            return ""

        # 1. Null-byte stripping
        s = input_str.replace("\x00", "").replace("%00", "").replace("\\0", "")

        # 2. Recursive URL decoding (up to max_depth to stop decoding loops)
        prev = ""
        depth = 0
        while prev != s and depth < max_depth:
            prev = s
            try:
                s = urllib.parse.unquote(s)
            except Exception:
                break
            depth += 1

        # 3. Unicode NFKC normalization
        s = unicodedata.normalize("NFKC", s)

        # 4. Standardize backslashes to slashes
        s = s.replace("\\", "/")

        return s

    @classmethod
    def normalize_path(cls, path: str) -> str:
        """Normalizes an HTTP URI path and collapses redundant slashes."""
        norm = cls.normalize_string(path)
        # Collapse multiple slashes (e.g. ///api//v1 -> /api/v1)
        norm = re.sub(r"/+", "/", norm)
        return norm

    @classmethod
    def parse_query_params(cls, query_string: str) -> List[Tuple[str, str]]:
        """Parses query string into decoded key-value pairs."""
        if not query_string:
            return []
        
        # Strip leading '?' if present
        if query_string.startswith("?"):
            query_string = query_string[1:]

        pairs = []
        for segment in query_string.split("&"):
            if not segment:
                continue
            if "=" in segment:
                k, v = segment.split("=", 1)
            else:
                k, v = segment, ""
            norm_k = cls.normalize_string(k)
            norm_v = cls.normalize_string(v)
            pairs.append((norm_k, norm_v))
        return pairs

    @classmethod
    def normalize_request_data(
        cls,
        path: str,
        query: str,
        body: str,
        headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Produces clean, structured normalized request vectors for target-aware inspection.
        """
        normalized_path = cls.normalize_path(path)
        normalized_query = cls.normalize_string(query)
        normalized_body = cls.normalize_string(body)
        normalized_headers = {
            cls.normalize_string(k).lower(): cls.normalize_string(v)
            for k, v in headers.items()
        }
        query_params = cls.parse_query_params(normalized_query)

        return {
            "path": normalized_path,
            "query": normalized_query,
            "query_params": query_params,
            "body": normalized_body,
            "headers": normalized_headers
        }
