#!/usr/bin/env python3
"""Standalone J2735 encoder/decoder built around the ASN.1 workflow used by asn1_codec."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

import asn1tools

MESSAGE_ALIASES = {
    "bsm": "BasicSafetyMessage",
    "tim": "TravelerInformation",
    "rsm": "RoadSafetyMessage",
    "roadsafety": "RoadSafetyMessage",
}
SUPPORTED_ENCODINGS = {"uper", "jer"}


def _flatten_asn1_paths(values: Iterable[str]) -> list[str]:
    paths: list[str] = []
    for value in values:
        for item in value.split(","):
            item = item.strip()
            if item:
                paths.append(item)
    return paths


def resolve_message_type(value: str) -> str:
    if not value:
        return value
    normalized = value.strip()
    alias = normalized.lower()
    return MESSAGE_ALIASES.get(alias, normalized)


def validate_encoding(encoding: str) -> None:
    if encoding not in SUPPORTED_ENCODINGS:
        raise ValueError(
            f"Unsupported encoding '{encoding}'. Expected one of {sorted(SUPPORTED_ENCODINGS)}."
        )


def load_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def parse_json_payload(raw_text: str) -> Any:
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Input JSON is invalid: {exc}") from exc


def convert_hex_strings(value: Any) -> Any:
    if isinstance(value, str) and value.lower().startswith("0x"):
        return bytes.fromhex(value[2:])
    if isinstance(value, list):
        return [convert_hex_strings(item) for item in value]
    if isinstance(value, dict):
        return {key: convert_hex_strings(item) for key, item in value.items()}
    return value


def convert_bytes_to_hex(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return f"0x{bytes(value).hex()}"
    if isinstance(value, list):
        return [convert_bytes_to_hex(item) for item in value]
    if isinstance(value, dict):
        return {key: convert_bytes_to_hex(item) for key, item in value.items()}
    return value


def build_compiler(asn1_paths: list[str], encoding: str) -> asn1tools.compiler.Compiler:
    if not asn1_paths:
        raise ValueError("At least one ASN.1 file must be provided.")
    return asn1tools.compile_files(asn1_paths, encoding)


def format_encoded(encoded: Any, encoding: str) -> str:
    """Format encoded output as a string.

    Raises:
        ValueError: If the encoder returns an unsupported output type.
    """
    if isinstance(encoded, bytes):
        if encoding == "uper":
            return encoded.hex()
        return encoded.decode("utf-8")
    if isinstance(encoded, str):
        return encoded
    raise ValueError(
        f"Encoded output type {type(encoded).__name__} is not supported. Expected bytes or str."
    )


def parse_encoded_input(raw_text: str | bytes, encoding: str) -> Any:
    validate_encoding(encoding)
    if encoding == "uper":
        if isinstance(raw_text, bytes):
            raw_text = raw_text.decode("utf-8")
        cleaned = "".join(raw_text.split())
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        return bytes.fromhex(cleaned)
    if isinstance(raw_text, bytes):
        return raw_text
    return raw_text.encode("utf-8")


def encode_payload(compiler: asn1tools.compiler.Compiler, message_type: str, payload: Any, encoding: str) -> str:
    """Encode a payload using the selected ASN.1 compiler and encoding rules.

    Returns:
        Encoded payload as a string.

    Raises:
        ValueError: If the encoding is unsupported or the encoder returns an unsupported output type.
    """
    validate_encoding(encoding)
    if encoding == "uper":
        payload = convert_hex_strings(payload)
    encoded = compiler.encode(message_type, payload)
    return format_encoded(encoded, encoding)


def decode_payload(
    compiler: asn1tools.compiler.Compiler,
    message_type: str,
    encoded_text: str | bytes,
    encoding: str,
) -> Any:
    """Decode an encoded payload and return JSON-serializable data.

    Args:
        compiler: ASN.1 compiler to use for decoding.
        message_type: ASN.1 message name to decode.
        encoded_text: Encoded input payload.
        encoding: Encoding rules to use.

    Returns:
        Decoded data with bytes converted to hex strings.

    Raises:
        ValueError: If the encoding is unsupported.
    """
    decoded = compiler.decode(message_type, parse_encoded_input(encoded_text, encoding))
    return convert_bytes_to_hex(decoded)


def _write_output(output: str, output_path: str | None) -> None:
    if output_path:
        Path(output_path).write_text(output, encoding="utf-8")
    else:
        print(output)


def main() -> int:
    parser = argparse.ArgumentParser(description="Encode/decode SAE J2735 messages with ASN.1 definitions.")
    parser.add_argument(
        "--asn1",
        action="append",
        required=True,
        help="ASN.1 file path(s). Can be repeated and/or comma-separated.",
    )
    parser.add_argument(
        "--message",
        required=True,
        help="Message name or alias (bsm, tim, rsm, roadsafety). Use ASN.1 type names for additional messages.",
    )
    parser.add_argument("--encoding", choices=["uper", "jer"], default="uper", help="Encoding rules to use.")
    parser.add_argument("--direction", choices=["encode", "decode"], required=True, help="Encode or decode payloads.")
    parser.add_argument("--input", required=True, help="JSON file (encode) or encoded text file (decode). Use - for stdin.")
    parser.add_argument("--output", help="Optional output file path. Defaults to stdout.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print decoded JSON output.")
    args = parser.parse_args()

    asn1_paths = _flatten_asn1_paths(args.asn1)
    compiler = build_compiler(asn1_paths, args.encoding)
    message_type = resolve_message_type(args.message)

    raw_text = load_text(args.input)

    if args.direction == "encode":
        payload = parse_json_payload(raw_text)
        encoded = encode_payload(compiler, message_type, payload, args.encoding)
        _write_output(encoded, args.output)
        return 0

    decoded = decode_payload(compiler, message_type, raw_text, args.encoding)
    indent = 2 if args.pretty else None
    output_json = json.dumps(decoded, indent=indent, sort_keys=True)
    _write_output(output_json, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
