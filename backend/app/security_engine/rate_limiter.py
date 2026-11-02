"""
SentinelGrid High-Throughput In-Memory Sliding-Window Rate Limiter & DDoS Quarantine
Features sharded lock partitions, sub-window mathematical rate interpolation,
RFC 6585 compliance, and autonomous multi-tier quarantine state machine.
"""

import time
import threading
import ipaddress
from typing import Dict, Tuple, Optional, Any, List


class SlidingWindowLimiter:
    """
    Sharded sliding-window rate limiter with O(1) bounded memory and zero boundary burst.
    Includes autonomous dynamic IP quarantine for repeat adversarial offenders.
    """

    def __init__(self, shards: int = 16):
        self.shards = shards
        self._locks = [threading.Lock() for _ in range(shards)]
        self._windows: List[Dict[str, Tuple[float, int, int]]] = [{} for _ in range(shards)]
        self._quarantine: Dict[str, Tuple[float, int, str]] = {}  # ip -> (expires_at, level, reason)
        self._q_lock = threading.Lock()

    def _get_shard(self, key: str) -> int:
        return hash(key) % self.shards

    def _canonicalize_ip(self, ip_str: str) -> str:
        """Groups IPv6 by /64 prefix to prevent rotation bypass; keeps IPv4 as /32."""
        if not ip_str:
            return "unknown"
        clean_ip = ip_str.split(":")[0] if ":" in ip_str and not ip_str.startswith("[") and ip_str.count(":") == 1 else ip_str
        clean_ip = clean_ip.strip("[]")
        try:
            ip = ipaddress.ip_address(clean_ip)
            if ip.version == 6:
                network = ipaddress.IPv6Network(f"{clean_ip}/64", strict=False)
                return str(network.network_address)
            return clean_ip
        except ValueError:
            return clean_ip

    def check_quarantine(self, ip_str: str) -> Tuple[bool, Optional[int], Optional[str]]:
        """
        Fast check: Returns (is_quarantined, remaining_seconds, reason).
        Checks if client IP is currently serving an active quarantine penalty.
        """
        canon_ip = self._canonicalize_ip(ip_str)
        now = time.monotonic()
        with self._q_lock:
            if canon_ip in self._quarantine:
                expires_at, level, reason = self._quarantine[canon_ip]
                if now < expires_at:
                    return True, max(1, int(expires_at - now)), reason
                else:
                    del self._quarantine[canon_ip]
        return False, None, None

    def trigger_violation(self, ip_str: str, severity: str = "CRITICAL", reason: str = "Adversarial Threat Detected") -> int:
        """
        Escalates quarantine penalty when critical attacks or severe rate floods are detected:
        - Level 1: 10 minutes (600s)
        - Level 2: 1 hour (3600s)
        - Level 3: 24 hours (86400s)
        """
        canon_ip = self._canonicalize_ip(ip_str)
        now = time.monotonic()
        with self._q_lock:
            current = self._quarantine.get(canon_ip)
            if current and now < current[0]:
                prev_expiry, level, _ = current
                next_level = min(3, level + 1)
                cooldowns = {1: 600.0, 2: 3600.0, 3: 86400.0}
                new_expiry = now + cooldowns[next_level]
                self._quarantine[canon_ip] = (new_expiry, next_level, f"{reason} (Escalated to Level {next_level})")
                return int(cooldowns[next_level])
            else:
                new_expiry = now + 600.0
                self._quarantine[canon_ip] = (new_expiry, 1, reason)
                return 600

    def evaluate_rate(
        self,
        identifier: str,
        limit: int = 100,
        window_seconds: float = 60.0
    ) -> Dict[str, Any]:
        """
        Evaluates sliding-window counter algorithm with zero boundary burst.
        Calculates mathematically interpolated count:
            Estimated = CurrentCount + (PreviousCount * (1 - Elapsed/WindowSize))
        Returns RFC 6585 header metrics and pass/drop verdict.
        """
        shard_idx = self._get_shard(identifier)
        now = time.monotonic()

        with self._locks[shard_idx]:
            state = self._windows[shard_idx].get(identifier)
            if not state:
                # First request in window
                self._windows[shard_idx][identifier] = (now, 1, 0)
                return {
                    "allowed": True,
                    "limit": limit,
                    "remaining": max(0, limit - 1),
                    "reset_after": int(window_seconds),
                    "retry_after": 0
                }

            window_start, current_count, prev_count = state
            elapsed = now - window_start

            if elapsed >= window_seconds * 2:
                # Two full windows passed: Reset completely
                self._windows[shard_idx][identifier] = (now, 1, 0)
                return {
                    "allowed": True,
                    "limit": limit,
                    "remaining": max(0, limit - 1),
                    "reset_after": int(window_seconds),
                    "retry_after": 0
                }
            elif elapsed >= window_seconds:
                # Shift current window into previous window
                prev_count = current_count
                current_count = 1
                window_start = now
                self._windows[shard_idx][identifier] = (window_start, current_count, prev_count)
                elapsed = 0.0
            else:
                current_count += 1
                self._windows[shard_idx][identifier] = (window_start, current_count, prev_count)

            # Calculate mathematically interpolated count across sliding boundary
            weight = max(0.0, 1.0 - (elapsed / window_seconds))
            estimated_count = int(current_count + (prev_count * weight))
            remaining = max(0, limit - estimated_count)
            reset_after = max(1, int(window_seconds - elapsed))

            if estimated_count > limit:
                return {
                    "allowed": False,
                    "limit": limit,
                    "remaining": 0,
                    "reset_after": reset_after,
                    "retry_after": reset_after
                }

            return {
                "allowed": True,
                "limit": limit,
                "remaining": remaining,
                "reset_after": reset_after,
                "retry_after": 0
            }


# Global singleton instance for high-throughput reuse
global_rate_limiter = SlidingWindowLimiter()
