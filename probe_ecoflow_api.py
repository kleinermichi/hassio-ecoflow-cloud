#!/usr/bin/env python3
"""Probe EcoFlow public API endpoints with an access key and secret key.

Usage:
  python probe_ecoflow_api.py --api-domain api.ecoflow.com --access-key ... --secret-key ...

Or set environment variables:
  ECOFLOW_API_DOMAIN, ECOFLOW_ACCESS_KEY, ECOFLOW_SECRET_KEY
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class EcoflowApiError(RuntimeError):
    pass


class EcoflowProbe:
    def __init__(self, api_domain: str, access_key: str, secret_key: str) -> None:
        self.api_domain = api_domain
        self.access_key = access_key
        self.secret_key = secret_key
        self.nonce = str(random.randint(10000, 1000000))
        self.timestamp = str(int(time.time() * 1000))

    def _request(self, endpoint: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        params_str = ""
        if params is not None:
            params_str = self._sort_and_concat_params(params)

        sign = self._gen_sign(params_str)
        headers = {
            "accessKey": self.access_key,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "sign": sign,
        }

        url = f"https://{self.api_domain}/iot-open/sign{endpoint}"
        if params_str:
            url += f"?{params_str}"

        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise EcoflowApiError(f"HTTP {exc.code}: {exc.read().decode('utf-8', 'ignore')}") from exc
        except Exception as exc:  # pragma: no cover - network fallback
            raise EcoflowApiError(f"Request failed: {exc}") from exc

        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise EcoflowApiError(f"Invalid JSON: {body}") from exc

        if data.get("message", "").lower() != "success":
            raise EcoflowApiError(f"API returned error: {data}")

        return data

    def _gen_sign(self, query_params: str | None) -> str:
        target_str = f"accessKey={self.access_key}&nonce={self.nonce}&timestamp={self.timestamp}"
        if query_params:
            target_str = query_params + "&" + target_str
        return self._encrypt_hmac_sha256(target_str, self.secret_key)

    def _sort_and_concat_params(self, params: dict[str, str]) -> str:
        items = sorted(params.items(), key=lambda x: x[0])
        return "&".join(f"{key}={urllib.parse.quote(str(value))}" for key, value in items)

    def _encrypt_hmac_sha256(self, message: str, secret_key: str) -> str:
        return hmac.new(secret_key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()

    def certification(self) -> dict[str, Any]:
        return self._request("/certification")

    def device_list(self) -> dict[str, Any]:
        return self._request("/device/list")

    def quota_all(self, device_sn: str) -> dict[str, Any]:
        return self._request("/device/quota/all", {"sn": device_sn})


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe EcoFlow public API")
    parser.add_argument("--api-domain", default=os.environ.get("ECOFLOW_API_DOMAIN", "api.ecoflow.com"))
    parser.add_argument("--access-key", default=os.environ.get("ECOFLOW_ACCESS_KEY"))
    parser.add_argument("--secret-key", default=os.environ.get("ECOFLOW_SECRET_KEY"))
    parser.add_argument("--device-sn", default=None)
    args = parser.parse_args()

    if not args.access_key or not args.secret_key:
        print("Missing access key or secret key. Provide them with --access-key/--secret-key or environment variables.", file=sys.stderr)
        return 2

    probe = EcoflowProbe(args.api_domain, args.access_key, args.secret_key)

    try:
        cert = probe.certification()
        print("Certification OK")
        print(json.dumps(cert.get("data", {}), indent=2)[:2000])
        print()

        devices = probe.device_list()
        print("Devices:")
        data = devices.get("data", [])
        if not data:
            print("No devices returned")
            return 0

        for idx, device in enumerate(data, 1):
            print(f"{idx}. {device.get('deviceName', device.get('productName', 'unknown'))} [{device.get('sn')}]")
            print(f"   online={device.get('online')} product={device.get('productName')}")

        if args.device_sn:
            print(f"\nQuota for {args.device_sn}:")
            quota = probe.quota_all(args.device_sn)
            print(json.dumps(quota.get("data", {}), indent=2)[:6000])
        else:
            first_sn = data[0].get("sn")
            if first_sn:
                print(f"\nQuota sample for {first_sn}:")
                quota = probe.quota_all(first_sn)
                print(json.dumps(quota.get("data", {}), indent=2)[:6000])
    except EcoflowApiError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
