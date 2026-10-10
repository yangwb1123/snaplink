#!/usr/bin/env python3
"""Validate the Docker Hub release index and its immutable digest, offline."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

INDEX_TYPES = {"application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json"}
MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json",
                  "application/vnd.docker.distribution.manifest.v2+json"}
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
EXPECTED = {("linux", "amd64"), ("linux", "arm64")}


def validate(index: dict) -> None:
    if type(index.get("schemaVersion")) is not int or index["schemaVersion"] != 2 or index.get("mediaType") not in INDEX_TYPES:
        raise ValueError("release must be a schema-2 multi-platform image index")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        raise ValueError("empty platform index")
    platforms = set()
    executable = set()
    attestations = set()
    for entry in manifests:
        if not isinstance(entry, dict) or not DIGEST.fullmatch(str(entry.get("digest", ""))):
            raise ValueError("invalid child manifest digest")
        if entry.get("mediaType") not in MANIFEST_TYPES or type(entry.get("size")) is not int or entry["size"] <= 0:
            raise ValueError("invalid child manifest descriptor")
        platform = entry.get("platform") or {}
        pair = (platform.get("os"), platform.get("architecture"))
        if pair == ("unknown", "unknown"):
            annotations = entry.get("annotations") or {}
            if annotations.get("vnd.docker.reference.type") != "attestation-manifest":
                raise ValueError("unknown platform is not a BuildKit attestation")
            attestations.add(annotations.get("vnd.docker.reference.digest"))
        elif pair in EXPECTED and pair not in platforms and entry["digest"] not in executable:
            platforms.add(pair)
            executable.add(entry["digest"])
        else:
            raise ValueError(f"unexpected or duplicate executable platform: {pair}")
    if platforms != EXPECTED:
        raise ValueError("release must contain exactly linux/amd64 and linux/arm64")
    if attestations != executable:
        raise ValueError("every executable platform must have a linked attestation")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--digest", help="expected sha256 of the exact registry index bytes")
    args = parser.parse_args()
    try:
        raw = args.manifest.read_bytes()
        validate(json.loads(raw))
        if args.digest and (not DIGEST.fullmatch(args.digest) or
                            args.digest != "sha256:" + hashlib.sha256(raw).hexdigest()):
            raise ValueError("registry index bytes do not match the immutable digest")
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(f"container-manifest: FAIL ({exc})")
        return 1
    print("container-manifest: PASS (amd64 + arm64, linked attestations, schema/digests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
