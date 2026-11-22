"""Bounded OSV v1 API client; OSV performs all affected-version matching."""

import json
import math
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

ENDPOINT = "https://api.osv.dev/v1/query"
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


class ProviderError(ValueError):
    pass


def validate_advisory(advisory):
    if not isinstance(advisory, dict) or not isinstance(advisory.get("id"), str) or not advisory["id"].strip():
        raise ProviderError("Invalid OSV advisory ID")
    for key in ("aliases", "affected", "severity", "references"):
        if key in advisory and not isinstance(advisory[key], list):
            raise ProviderError(f"Invalid OSV advisory {key}")
    if any(not isinstance(alias, str) or not alias for alias in advisory.get("aliases", [])):
        raise ProviderError("Invalid OSV advisory aliases")
    for key in ("affected", "severity", "references"):
        if any(not isinstance(item, dict) for item in advisory.get(key, [])):
            raise ProviderError(f"Invalid OSV advisory {key} entries")
    if "database_specific" in advisory and not isinstance(advisory["database_specific"], dict):
        raise ProviderError("Invalid OSV database_specific")
    for key in ("modified", "published", "withdrawn", "summary", "details"):
        if key in advisory and not isinstance(advisory[key], str):
            raise ProviderError(f"Invalid OSV advisory {key}")


def retry_delay(value, fallback):
    if value is None:
        return fallback
    try:
        seconds = float(value)
    except ValueError:
        try:
            seconds = (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return fallback
    return max(0, seconds) if math.isfinite(seconds) else fallback


class OSVClient:
    def __init__(self, timeout=30, retries=2):
        if not math.isfinite(timeout) or timeout <= 0 or not 0 <= retries <= 5:
            raise ValueError("OSV timeout must be positive and finite; retries must be between 0 and 5")
        self.timeout, self.retries = timeout, retries

    def _request(self, query, deadline, identifier=None):
        for attempt in range(self.retries + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProviderError("OSV query deadline exceeded")
            url = ENDPOINT if identifier is None else "https://api.osv.dev/v1/vulns/" + quote(identifier, safe="")
            request = Request(url, data=json.dumps(query).encode("utf-8") if identifier is None else None,
                              headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "cvefuzz"},
                              method="POST" if identifier is None else "GET")
            delay = 2 ** attempt
            try:
                with urlopen(request, timeout=remaining) as response:
                    # read1 returns after one underlying read, so trickling data cannot
                    # postpone deadline checks until a full 64 KiB has arrived.
                    chunks, size = [], 0
                    while True:
                        if time.monotonic() >= deadline:
                            raise ProviderError("OSV query deadline exceeded while reading response")
                        chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - size))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        size += len(chunk)
                        if size > MAX_RESPONSE_BYTES:
                            raise ProviderError("OSV response exceeds 32 MiB")
                    if time.monotonic() >= deadline:
                        raise ProviderError("OSV query deadline exceeded while reading response")
                    payload = json.loads(b"".join(chunks))
                if not isinstance(payload, dict) or "error" in payload:
                    raise ProviderError("Invalid OSV response object")
                return payload
            except HTTPError as error:
                status = error.code
                delay = retry_delay(error.headers.get("Retry-After") if error.headers else None, delay)
                error.close()
                if status == 404 and identifier is not None:
                    return None
                if status not in (408, 429, 500, 502, 503, 504) or attempt == self.retries:
                    raise ProviderError(f"OSV HTTP {status}") from error
            except (URLError, TimeoutError, OSError, HTTPException) as error:
                if attempt == self.retries:
                    raise ProviderError(f"OSV unavailable: {error}") from error
            except ProviderError:
                raise
            except (ValueError, UnicodeError) as error:
                raise ProviderError(f"Invalid OSV response: {error}") from error
            if delay >= deadline - time.monotonic():
                raise ProviderError("OSV retry exceeds query deadline; previous cache retained")
            time.sleep(delay)
        raise ProviderError("OSV retries exhausted")

    def query(self, component):
        query = {"package": {"name": component["name"], "ecosystem": component["ecosystem"]}, "version": component["version"]}
        deadline, seen, advisories = time.monotonic() + self.timeout, set(), {}
        for _ in range(100):
            payload = self._request(query, deadline)
            if payload and not ({"vulns", "next_page_token"} & payload.keys()):
                raise ProviderError("Unrecognized OSV query response")
            entries = payload.get("vulns", [])
            if not isinstance(entries, list):
                raise ProviderError("Invalid OSV vulnerabilities array")
            for advisory in entries:
                validate_advisory(advisory)
                identifier = advisory["id"]
                if identifier in advisories and advisories[identifier] != advisory:
                    raise ProviderError(f"OSV advisory changed during pagination: {identifier}; retry refresh")
                advisories[identifier] = advisory
            token = payload.get("next_page_token")
            if token is None or token == "":
                return list(advisories.values())
            if not isinstance(token, str) or token in seen:
                raise ProviderError("Invalid or repeated OSV pagination token")
            seen.add(token)
            query["page_token"] = token
        raise ProviderError("OSV pagination limit exceeded")

    def advisory(self, identifier):
        payload = self._request(None, time.monotonic() + self.timeout, identifier)
        if payload is not None:
            validate_advisory(payload)
            if payload["id"] != identifier:
                raise ProviderError("OSV returned a different advisory ID")
        return payload
