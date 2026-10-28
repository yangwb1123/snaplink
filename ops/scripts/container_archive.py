#!/usr/bin/env python3
"""Extract a verified OCI archive for scanning without Docker config rewriting."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tarfile

MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_TAR_BYTES = MAX_ARCHIVE_BYTES + 16 * 1024 * 1024
MAX_MEMBERS = 10000
MAX_INDEX_DESCRIPTORS = 4096
INDEX_TYPES = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
BLOB = re.compile(r"blobs/sha256/([a-f0-9]{64})\Z")
FILES = {"oci-layout", "index.json"}
DIRECTORIES = {".", "blobs", "blobs/sha256"}


def extract(archive: Path, destination: Path, platform: str | None = None) -> None:
    # Refuse existing/symlink destinations rather than mixing scan generations.
    destination.mkdir(mode=0o700)
    try:
        _extract_files(archive, destination)
        layout = json.loads((destination / "oci-layout").read_text())
        index = json.loads((destination / "index.json").read_text())
        if layout.get("imageLayoutVersion") != "1.0.0" or type(index.get("schemaVersion")) is not int or index["schemaVersion"] != 2:
            raise ValueError("invalid OCI layout or index version")
        if not isinstance(index.get("manifests"), list) or not index["manifests"]:
            raise ValueError("OCI index has no manifests")
        if platform is not None:
            _select_platform(destination, index, platform)
    except BaseException as error:
        shutil.rmtree(destination)
        if isinstance(error, tarfile.TarError):
            raise ValueError("invalid OCI tar stream") from error
        raise


class _OCIInfo(tarfile.TarInfo):
    @classmethod
    def frombuf(cls, buffer, encoding, errors):
        member = super().frombuf(buffer, encoding, errors)
        # BuildKit OCI names fit normal headers. Reject extensions before the
        # tar parser can allocate attacker-sized PAX/long-name metadata.
        if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
            raise ValueError("unsupported OCI tar header type")
        return member


def _extract_files(archive: Path, destination: Path) -> None:
    seen, total = set(), 0
    if archive.stat().st_size > MAX_TAR_BYTES:
        raise ValueError("OCI tar stream exceeds extraction budget")
    with tarfile.open(archive, mode="r:", tarinfo=_OCIInfo) as source:
        for count, member in enumerate(source, 1):
            if count > MAX_MEMBERS:
                raise ValueError("OCI tar member count exceeds extraction budget")
            if member.isdir() and member.name.rstrip("/") in DIRECTORIES:
                continue
            match = BLOB.fullmatch(member.name)
            if not member.isfile() or not (member.name in FILES or match):
                raise ValueError("archive contains a non-regular or non-OCI path")
            if member.name in seen:
                raise ValueError("archive contains duplicate files")
            seen.add(member.name)
            total += member.size
            if member.size < 0 or total > MAX_ARCHIVE_BYTES:
                raise ValueError("OCI archive exceeds extraction budget")
            if member.name in FILES and member.size > MAX_METADATA_BYTES:
                raise ValueError("OCI metadata exceeds extraction budget")
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with source.extractfile(member) as incoming, target.open("xb") as outgoing:
                while chunk := incoming.read(1024 * 1024):
                    digest.update(chunk)
                    outgoing.write(chunk)
            if match and digest.hexdigest() != match.group(1):
                raise ValueError("OCI blob digest mismatch")
    if not FILES <= seen:
        raise ValueError("archive lacks required OCI layout files")


def _blob_json(destination: Path, digest: str) -> dict:
    name = "blobs/" + digest.replace(":", "/")
    if not BLOB.fullmatch(name):
        raise ValueError("invalid OCI metadata digest")
    path = destination / name
    if path.stat().st_size > MAX_METADATA_BYTES:
        raise ValueError("OCI metadata exceeds extraction budget")
    body = json.loads(path.read_bytes())
    if not isinstance(body, dict):
        raise ValueError("OCI metadata must be an object")
    return body


def _select_platform(destination: Path, index: dict, platform: str) -> None:
    os_name, architecture = platform.split("/")
    candidates, visited = [], set()
    visits = 0

    def visit(body: dict, depth: int) -> None:
        nonlocal visits
        if depth > 8:
            raise ValueError("OCI index nesting exceeds scan budget")
        for descriptor in body.get("manifests", []):
            visits += 1
            if visits > MAX_INDEX_DESCRIPTORS:
                raise ValueError("OCI descriptor count exceeds scan budget")
            if descriptor.get("mediaType") in INDEX_TYPES:
                digest = descriptor["digest"]
                if digest in visited:
                    raise ValueError("OCI index reference is repeated")
                visited.add(digest)
                visit(_blob_json(destination, digest), depth + 1)
            elif descriptor.get("platform", {}).get("os") == os_name and descriptor.get("platform", {}).get("architecture") == architecture:
                candidates.append(descriptor)

    visit(index, 0)
    if len(candidates) != 1:
        raise ValueError("OCI archive must contain exactly one requested platform")
    image = _blob_json(destination, candidates[0]["digest"])
    config = _blob_json(destination, image["config"]["digest"])
    if config.get("os") != os_name or config.get("architecture") != architecture:
        raise ValueError("OCI descriptor/config platform mismatch")
    # Trivy's layout reader can ignore --platform; select only the descriptor,
    # never rewrite content-addressed manifests, configs, layers or the archive.
    index["manifests"] = candidates
    (destination / "index.json").write_text(json.dumps(index))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), required=True)
    args = parser.parse_args()
    try:
        extract(args.archive, args.destination, args.platform)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError) as error:
        parser.exit(1, f"container-archive: {error}\n")
    print("container-archive: verified OCI layout extracted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
