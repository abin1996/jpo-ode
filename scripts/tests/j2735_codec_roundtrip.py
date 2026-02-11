#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import j2735_codec
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import j2735_codec


def build_compilers(asn1_path: Path) -> dict[str, object]:
    """Build one compiler per encoding since asn1tools compilers are codec-specific."""
    return {encoding: j2735_codec.build_compiler([str(asn1_path)], encoding) for encoding in ("uper", "jer")}


def run_roundtrip() -> int:
    fixtures_dir = Path(__file__).resolve().parent / "fixtures"
    asn1_path = fixtures_dir / "j2735_minimal.asn"
    payloads = {
        "bsm": fixtures_dir / "bsm.json",
        "tim": fixtures_dir / "tim.json",
        "rsm": fixtures_dir / "rsm.json",
    }

    compilers = build_compilers(asn1_path)
    for encoding, compiler in compilers.items():
        for alias, payload_path in payloads.items():
            message_type = j2735_codec.resolve_message_type(alias)
            payload = json.loads(payload_path.read_text(encoding="utf-8"))
            encoded = j2735_codec.encode_payload(compiler, message_type, payload, encoding)
            decoded = j2735_codec.decode_payload(compiler, message_type, encoded, encoding)
            if decoded != payload:
                print(
                    f"Round-trip failed for {alias} using {encoding}: expected {payload} got {decoded}",
                    file=sys.stderr,
                )
                return 1
    print("J2735 codec round-trip tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(run_roundtrip())
