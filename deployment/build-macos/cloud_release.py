#!/usr/bin/env python3
"""Repackage the public, frozen Orvala Mac release on a native Apple runner.

This file contains distribution orchestration only, with no game/editor sources.
The default --plan and --self-test need neither credentials nor network access.
--run contacts Apple; --run --publish also changes the OWN release repository.
Never invoke --run before authorizing the temporary Apple credentials in that
repository. No portal, Windows release, installed game, or user save is changed.

API JSON schema: https://github.com/indygreg/apple-platform-rs/blob/main/
app-store-connect/src/api_key.rs (issuer_id, key_id, private_key: base64 DER).
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import io
import json
import os
import platform
import plistlib
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid
from pathlib import Path, PurePosixPath
from zipfile import ZIP_STORED, ZipFile, ZipInfo


REPOSITORY = "DaneAz61/orvala-releases"
VERSION = "1.0.5"
BASE_VERSION = "1.0.3"
TEAM_ID = "WN9MP7LBRW"
MINIMUM_MACOS = "13.0"
BASE_SIZE = 4_367_280_606
BASE_SHA256 = "aabd0a7e2dde7ee0f157549bcca8b30d39b7e70989a86cf98617ebb28757fd64"
PCK_SIZE = 4_192_008_472
PCK_SHA256 = "69a41ae720bc2d989d48c5f2b15c4950f83c513dec0bf3f5b84988285e5bb3e5"
BOOTSTRAP_NAME = "Instalar-Orvala-Mac-1.0.4.zip"
BOOTSTRAP_VERSION = "1.0.4"
BOOTSTRAP_SIZE = 1_364_034
BOOTSTRAP_SHA256 = "01e958b0a74e5d19c5ccef0e4f5e204d2dfe985b8d7101ddada487daa418d038"
DEVELOPER_ID_CA_URL = "https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer"
DEVELOPER_ID_CA_SIZE = 1_090
DEVELOPER_ID_CA_SHA256 = "f16cd3c54c7f83cea4bf1a3e6a0819c8aaa8e4a1528fd144715f350643d2df3a"
RELEASE_ROOT = f"https://github.com/{REPOSITORY}/releases/download"
BOOTSTRAP_URL = f"{RELEASE_ROOT}/v{BOOTSTRAP_VERSION}/{BOOTSTRAP_NAME}"
EVIDENCE_NAME = f"macos-{VERSION}-evidence.json"
PART_LIMIT = 700_000_000
RESERVE = 512 * 1024 * 1024
ZIP_METADATA_BUDGET = 64 * 1024 * 1024
SECRET_NAMES = (
    "APPLE_SIGNING_P12_BASE64", "APPLE_SIGNING_P12_PASSWORD", "APPLE_NOTARY_API_JSON",
)
PART_SPECS = (
    (700_000_000, "98c9b70c7c5627c3967d6efb85ebd03acd7648980d3b1355b73c684d8ef1a4a4"),
    (700_000_000, "d9cf93d088340e5860bfe921992ce602a468dbded82575b4f93f977ca1e434e4"),
    (700_000_000, "2e89569ff39922a659488fdeac9b7506e4e85f0c494c83b9d7c60d52c2fdeb20"),
    (700_000_000, "c32df73071cbe8eefc4b2db443d8c014cfbe3ab2c20c4189d98a0b20dd832eb5"),
    (700_000_000, "58c411db7021d2532606a1f87e7b7758e43ad883a0ce4ab0aa335dfb0efb3b59"),
    (700_000_000, "9853da145fd9ef4f341e268bdd90376410977c5fa867ab8ff47b08d9ff4d40ea"),
    (167_280_606, "c6d94b25728fc005083b4b49393b1833db6f89b604237063f47e3c36a1d283c3"),
)
MACHO_MAGICS = {
    bytes.fromhex(value) for value in (
        "feedface", "cefaedfe", "feedfacf", "cffaedfe",
        "cafebabe", "bebafeca", "cafebabf", "bfbafeca",
    )
}
JIT_ENTITLEMENTS = {
    "com.apple.security.cs.allow-jit": True,
    "com.apple.security.cs.allow-unsigned-executable-memory": True,
    "com.apple.security.cs.allow-dyld-environment-variables": True,
    "com.apple.security.cs.disable-library-validation": True,
}
BOOT_MARKER = "LIBRARY ENTRY SMOKE OK: Biblioteca, modelos iniciais no seletor e retorno."
BOOT_FAILURE_PATTERN = re.compile(
    r"(?:^|\n)\s*(?:ERROR:|SCRIPT\s*ERROR:|Unhandled exception)|"
    r"(?:unable to find|failed to (?:load|initialize|open)|could not (?:load|find))"
    r"[^\n]{0,180}(?:\.NET|assembl(?:y|ies)|hostfxr|coreclr)", re.IGNORECASE,
)


class PipelineError(RuntimeError):
    """A controlled failure whose message never contains a credential."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PipelineError(message)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def private_write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_file(path: Path, size: int, digest: str) -> None:
    require(path.is_file() and not path.is_symlink(), f"Missing regular asset: {path.name}")
    require(path.stat().st_size == size, f"Incorrect asset size: {path.name}")
    require(sha256_file(path) == digest, f"Incorrect SHA-256: {path.name}")


def base_manifest() -> dict:
    return {
        "version": BASE_VERSION, "platform": "macos-arm64", "application": "Orvala.app",
        "minimum_macos": "12.0", "status": "beta", "notarized": False,
        "size": BASE_SIZE, "sha256": BASE_SHA256,
        "parts": [
            {"url": f"{RELEASE_ROOT}/v{BASE_VERSION}/Orvala-Mac-arm64-{BASE_VERSION}.zip.part{index:02d}",
             "size": size, "sha256": digest}
            for index, (size, digest) in enumerate(PART_SPECS, 1)
        ],
    }


def safe_codesign_stderr(data: bytes) -> str:
    text = data.decode("utf-8", "replace")
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"-----BEGIN [^-\n]+-----.*?-----END [^-\n]+-----", "[REDACTED KEY BLOCK]", text,
                  flags=re.DOTALL)
    text = "".join(char for char in text if char in "\n\t" or ord(char) >= 32)
    return text[-8192:].strip()


def command(argv: list[str], label: str, *, timeout: int = 180,
            env: dict | None = None, check: bool = True,
            codesign_diagnostics: bool = False, cwd: Path | None = None) -> subprocess.CompletedProcess:
    # Never print argv: security import contains a password in an OS CLI argument.
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, env=env, check=False, cwd=cwd)
    except (OSError, subprocess.TimeoutExpired):
        raise PipelineError(f"{label} could not finish within {timeout} seconds.") from None
    if check and result.returncode:
        # Opt-in ONLY for codesign, whose arguments contain identity hashes/paths,
        # never a password or API key. security/notarytool output stays private.
        if codesign_diagnostics and argv[0] == "/usr/bin/codesign":
            diagnostic = safe_codesign_stderr(result.stderr)
            print(f"CODESIGN FAILURE: {label}\n{diagnostic or '(no codesign stderr)'}", file=sys.stderr, flush=True)
        raise PipelineError(f"{label} failed (exit {result.returncode}); no release was promoted.")
    return result


def download(url: str, target: Path, size: int, digest: str) -> None:
    require(url.startswith(RELEASE_ROOT + "/") or url == DEVELOPER_ID_CA_URL,
            "Unexpected public download origin.")
    command(["/usr/bin/curl", "--fail", "--silent", "--show-error", "--location",
             "--proto", "=https", "--tlsv1.2", "--retry", "3", "--max-time", "240",
             "--output", str(target), url], "Public asset download", timeout=260)
    verify_file(target, size, digest)


def assert_safe_name(name: str) -> None:
    parts = PurePosixPath(name).parts
    require(bool(parts) and not name.startswith("/") and "\\" not in name
            and all(part not in (".", "..", "__MACOSX") and not part.startswith("._") for part in parts)
            and not any(char in name for char in ("\x00", "\r", "\n", "\t")),
            "Unsafe archive member name.")


def extract_bootstrap(archive: Path, root: Path) -> Path:
    # Only a tiny, hash-pinned distribution bootstrap is extracted by Python.
    # The 4GB game uses the shipping JXA/tar streaming path instead.
    with ZipFile(archive) as source:
        names = set()
        for entry in source.infolist():
            assert_safe_name(entry.filename)
            require(entry.filename not in names, "Duplicate bootstrap member.")
            names.add(entry.filename)
            require(PurePosixPath(entry.filename).parts[0] == "Orvala.app", "Unexpected bootstrap root.")
            kind = stat.S_IFMT(entry.external_attr >> 16)
            require(kind in (0, stat.S_IFREG, stat.S_IFDIR), "Bootstrap contains a special file.")
            destination = root.joinpath(*PurePosixPath(entry.filename).parts)
            if entry.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with source.open(entry) as src, destination.open("xb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
            mode = (entry.external_attr >> 16) & 0o777
            if mode:
                destination.chmod(mode)
    app = root / "Orvala.app"
    validator = app / "Contents/Resources/validate.js"
    require(validator.is_file(), "Approved bootstrap is missing its installer validator.")
    return app


def trust(app: Path, *, prefix: str, evidence: dict) -> None:
    commands = (
        ("codesign", ["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)]),
        ("stapler", ["/usr/bin/xcrun", "stapler", "validate", str(app)]),
        ("gatekeeper", ["/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", str(app)]),
    )
    results = {}
    for label, args in commands:
        result = command(args, f"{prefix} {label}")
        # Outputs of trust checks contain bundle/certificate metadata, no secrets.
        results[label] = (result.stdout + result.stderr).decode("utf-8", "replace").strip()
    require("Notarized Developer ID" in results["gatekeeper"], f"{prefix} is not a notarized Developer ID app.")
    evidence[prefix] = results


def jxa(validator: Path, *args: str) -> str:
    return command(["/usr/bin/osascript", "-l", "JavaScript", str(validator), *map(str, args)],
                   "Approved installer validator", timeout=180).stdout.decode("utf-8").strip()


def stream_extract(parts: list[Path], destination: Path) -> None:
    # tar may finish at the central directory, before EOF. A drain after tar keeps
    # the validated producer from getting SIGPIPE, just like the shipping updater.
    consumer = subprocess.Popen(
        ["/bin/sh", "-c", '/usr/bin/tar -xpf - --no-same-owner -C "$1"; result=$?; /bin/cat >/dev/null; exit "$result"',
         "orvala-stream", str(destination)], stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        assert consumer.stdin is not None
        for part in parts:
            with part.open("rb") as source:
                shutil.copyfileobj(source, consumer.stdin, 4 * 1024 * 1024)
            consumer.stdin.flush()
            part.unlink()  # Only a verified, consumed part under our private work directory.
        consumer.stdin.close()
        result = consumer.wait(timeout=180)
        require(result == 0, "Native streaming extraction failed.")
    except (OSError, subprocess.TimeoutExpired):
        consumer.kill()
        consumer.wait()
        raise PipelineError("Native streaming extraction did not complete.") from None
    finally:
        if consumer.poll() is None:
            consumer.kill()
            consumer.wait()
        if consumer.stderr:
            consumer.stderr.close()
    require(all(not path.is_symlink() for path in destination.rglob("*")), "Extracted package contains a symlink.")


def unpack_game(work: Path, validator: Path, evidence: dict) -> Path:
    stage = work / "base"
    stage.mkdir()
    manifest = base_manifest()
    write_json(stage / "manifest.json", manifest)
    jxa(validator, "manifest", stage / "manifest.json", "")
    download_needed = int(jxa(validator, "download", stage, ",".join("0" for _ in PART_SPECS)))
    require(shutil.disk_usage(work).free >= download_needed, "Runner has insufficient space for verified base download.")
    parts = [stage / f"part-{index}" for index in range(1, len(PART_SPECS) + 1)]
    jobs = [(item["url"], path, item["size"], item["sha256"]) for path, item in zip(parts, manifest["parts"])]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(download, *args) for args in jobs]
        for future in futures:
            future.result()
    archive_digest = hashlib.sha256()
    for part in parts:
        with part.open("rb") as source:
            for chunk in iter(lambda: source.read(4 * 1024 * 1024), b""):
                archive_digest.update(chunk)
    require(archive_digest.hexdigest() == BASE_SHA256, "Virtual base ZIP SHA-256 differs from the frozen release.")
    archive_table = jxa(validator, "parts", stage)
    expanded, files, extract_needed = map(int, archive_table.splitlines()[0].split("\t"))
    require(shutil.disk_usage(work).free >= extract_needed, "Runner has insufficient space for streaming extraction.")
    table = stage / "archive.tsv"
    table.write_text(archive_table + "\n", encoding="utf-8")
    extracted = work / "game"
    extracted.mkdir()
    stream_extract(parts, extracted)
    jxa(validator, "permissions", table, extracted)
    jxa(validator, "extracted", table, extracted)
    app = extracted / "Orvala.app"
    verify_file(app / "Contents/Resources/Orvala.pck", PCK_SIZE, PCK_SHA256)
    evidence["frozen_base"] = {"version": BASE_VERSION, "sha256": BASE_SHA256,
                               "parts_verified": len(parts), "expanded_bytes": expanded, "files": files,
                               "pck_sha256": PCK_SHA256, "pck_bytes": PCK_SIZE,
                               "shipping_jxa_and_native_tar": True, "permissions_restored_and_verified": True}
    return app


def convert_api_json(raw: str) -> tuple[str, str, bytes]:
    # Match UnifiedApiKey in the official apple-platform-rs source; never dump raw.
    try:
        value = json.loads(raw)
        issuer, key_id, encoded = value["issuer_id"], value["key_id"], value["private_key"]
        require(isinstance(issuer, str) and str(uuid.UUID(issuer)) == issuer.lower(), "Invalid Apple API issuer ID.")
        require(isinstance(key_id, str) and re.fullmatch(r"[A-Z0-9]{10}", key_id) is not None,
                "Invalid Apple API key ID.")
        require(isinstance(encoded, str), "Invalid Apple API key representation.")
        der = base64.b64decode(encoded, validate=True)
        require(64 <= len(der) <= 4096 and der.startswith(b"\x30"), "Invalid Apple API DER key.")
    except (KeyError, TypeError, ValueError):
        raise PipelineError("Apple API JSON does not match the documented rcodesign schema.") from None
    encoded_pem = base64.b64encode(der).decode("ascii")
    pem = "-----BEGIN PRIVATE KEY-----\n" + "\n".join(
        encoded_pem[index:index + 64] for index in range(0, len(encoded_pem), 64)
    ) + "\n-----END PRIVATE KEY-----\n"
    return issuer, key_id, pem.encode("ascii")


def managed_dll_hashes(app: Path) -> dict[str, str]:
    return {path.relative_to(app).as_posix(): sha256_file(path) for path in sorted(app.rglob("*.dll"))}


def is_macho(path: Path) -> bool:
    with path.open("rb") as source:
        return source.read(4) in MACHO_MAGICS


def user_keychain_search_list() -> list[str]:
    result = command(["/usr/bin/security", "list-keychains", "-d", "user"], "Read existing user keychain search list")
    try:
        paths = shlex.split(result.stdout.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise PipelineError("Could not parse the existing user keychain search list.") from None
    require(all(Path(path).is_absolute() and "\n" not in path and "\x00" not in path for path in paths),
            "Unexpected user keychain search list entry.")
    return paths


def merged_keychain_list(original: list[str], current: list[str], temporary: str,
                         *, include_temporary: bool) -> list[str]:
    # Keep every pre-existing keychain, plus unrelated additions made since the
    # snapshot. Scope our only change to this job's own temporary keychain.
    paths = [path for path in [*original, *current] if path != temporary]
    if include_temporary:
        paths.append(temporary)
    return list(dict.fromkeys(paths))


def remember_user_keychain_search_list(work: Path) -> None:
    private_write(work / "keychain-search-list.json", json.dumps(user_keychain_search_list()).encode("utf-8"))


def register_temp_keychain(work: Path, keychain: Path) -> None:
    original = json.loads((work / "keychain-search-list.json").read_text(encoding="utf-8"))
    paths = merged_keychain_list(original, user_keychain_search_list(), str(keychain), include_temporary=True)
    command(["/usr/bin/security", "list-keychains", "-d", "user", "-s", *paths],
            "Register temporary keychain without replacing existing keychains")
    registered = user_keychain_search_list()
    require(all(path in registered for path in paths), "Temporary keychain registration was incomplete.")


def restore_user_keychain_search_list(work: Path) -> None:
    snapshot = work / "keychain-search-list.json"
    if not snapshot.exists():
        return
    original = json.loads(snapshot.read_text(encoding="utf-8"))
    require(isinstance(original, list) and all(isinstance(path, str) for path in original),
            "Saved keychain search list is invalid.")
    keychain = str(work / "signing.keychain-db")
    paths = merged_keychain_list(original, user_keychain_search_list(), keychain, include_temporary=False)
    command(["/usr/bin/security", "list-keychains", "-d", "user", "-s", *paths],
            "Restore user keychain search list before deleting temporary identity")
    current = user_keychain_search_list()
    require(keychain not in current and all(path in current for path in paths),
            "User keychain search list was not restored.")
    snapshot.unlink()


def import_identity(work: Path, credentials: dict) -> tuple[Path, str]:
    try:
        p12 = base64.b64decode(credentials[SECRET_NAMES[0]], validate=True)
    except (ValueError, TypeError):
        raise PipelineError("Invalid base64 PKCS12 input.") from None
    require(256 <= len(p12) <= 1024 * 1024, "Unexpected PKCS12 size.")
    p12_path = work / "identity.p12"
    private_write(p12_path, p12)
    keychain = work / "signing.keychain-db"
    password = secrets.token_urlsafe(36)
    remember_user_keychain_search_list(work)
    command(["/usr/bin/security", "create-keychain", "-p", password, str(keychain)], "Temporary keychain creation")
    command(["/usr/bin/security", "set-keychain-settings", "-lut", "1200", str(keychain)], "Temporary keychain settings")
    command(["/usr/bin/security", "unlock-keychain", "-p", password, str(keychain)], "Temporary keychain unlock")
    # GitHub's official macOS signing setup registers the keychain for codesign's
    # chain/key resolution. Preserve all original keychains instead of replacing.
    register_temp_keychain(work, keychain)
    # The approved PKCS12 is leaf-only. Supply its public intermediate explicitly;
    # use the ordinary Apple system root, without adding any custom trust setting.
    intermediate = work / "DeveloperIDG2CA.cer"
    download(DEVELOPER_ID_CA_URL, intermediate, DEVELOPER_ID_CA_SIZE, DEVELOPER_ID_CA_SHA256)
    command(["/usr/bin/security", "import", str(intermediate), "-k", str(keychain)],
            "Import pinned public Developer ID G2 intermediate")
    command(["/usr/bin/security", "import", str(p12_path), "-k", str(keychain), "-P",
             credentials[SECRET_NAMES[1]], "-T", "/usr/bin/codesign", "-T", "/usr/bin/security"], "Signing identity import")
    command(["/usr/bin/security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:",
             "-s", "-k", password, str(keychain)], "Temporary private-key access")
    p12_path.unlink()
    identities = command(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning", str(keychain)],
                         "Find Developer ID identity").stdout.decode("utf-8", "replace")
    matches = re.findall(r'\b([A-Fa-f0-9]{40}) "(Developer ID Application:[^"\n]+)"', identities)
    matches = [(digest, name) for digest, name in matches if name.endswith(f"({TEAM_ID})")]
    require(len(matches) == 1, "Exactly one matching Developer ID Application identity is required.")
    return keychain, matches[0][0]


def verify_signed_chain(description: str) -> list[str]:
    require(f"TeamIdentifier={TEAM_ID}" in description and "runtime" in description,
            "Signed bundle has an unexpected team or no hardened runtime.")
    authorities = re.findall(r"^Authority=(.+)$", description, flags=re.MULTILINE)
    require(len(authorities) >= 3 and authorities[0].startswith("Developer ID Application:")
            and authorities[1] == "Developer ID Certification Authority"
            and authorities[-1] == "Apple Root CA",
            "Signed bundle does not contain the expected Developer ID to Apple root chain.")
    return authorities


def sign_game(app: Path, work: Path, keychain: Path, identity: str, evidence: dict) -> None:
    info_path = app / "Contents/Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    require(info.get("CFBundleIdentifier") == "br.com.playable.orvala" and info.get("CFBundleExecutable") == "Orvala",
            "Unexpected game bundle identifier or executable.")
    info.update(CFBundleShortVersionString=VERSION, CFBundleVersion=VERSION, LSMinimumSystemVersion=MINIMUM_MACOS)
    info_path.write_bytes(plistlib.dumps(info))
    before_dlls = managed_dll_hashes(app)
    require(bool(before_dlls), "Frozen .NET managed assemblies are missing.")
    entitlements = work / "jit-entitlements.plist"
    entitlements.write_bytes(plistlib.dumps(JIT_ENTITLEMENTS))
    native = [path for path in app.rglob("*") if path.is_file() and not path.is_symlink() and is_macho(path)]
    main = app / "Contents/MacOS/Orvala"
    require(main in native, "Game executable is not a native Mach-O binary.")
    for path in sorted(native, key=lambda item: (-len(item.parts), str(item))):
        args = ["/usr/bin/codesign", "--force", "--sign", identity, "--keychain", str(keychain),
                "--options", "runtime", "--timestamp"]
        # Every executable may host .NET; shared libraries need no host entitlements.
        if path == main or path.name == "createdump":
            args += ["--entitlements", str(entitlements)]
        command(args + [str(path)], f"Native code signature ({path.relative_to(app).as_posix()})",
                timeout=90, codesign_diagnostics=True)
    command(["/usr/bin/codesign", "--force", "--sign", identity, "--keychain", str(keychain),
             "--options", "runtime", "--timestamp", "--entitlements", str(entitlements), str(app)],
            "Main application signature (Orvala.app)", timeout=180, codesign_diagnostics=True)
    command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], "Complete signature verification")
    description = command(["/usr/bin/codesign", "--display", "--verbose=4", str(app)],
                          "Signed application identity").stderr.decode("utf-8", "replace")
    authorities = verify_signed_chain(description)
    # G2 lives in the intermediate's OU, NOT its CN. Verify the actual embedded
    # certificate bytes rather than inventing a suffix in codesign's Authority.
    certificates = work / "signed-certificate-chain"
    certificates.mkdir()
    command(["/usr/bin/codesign", "--display", "--extract-certificates", str(app)],
            "Extract signed public certificate chain", cwd=certificates)
    verify_file(certificates / "codesign1", DEVELOPER_ID_CA_SIZE, DEVELOPER_ID_CA_SHA256)
    actual_entitlements = command(["/usr/bin/codesign", "--display", "--entitlements", ":-", str(app)],
                                  "Signed JIT entitlements").stdout
    require(plistlib.loads(actual_entitlements) == JIT_ENTITLEMENTS, "Signed JIT entitlements do not match the approved four.")
    require(managed_dll_hashes(app) == before_dlls, "Managed game/runtime assemblies changed during signing.")
    verify_file(app / "Contents/Resources/Orvala.pck", PCK_SIZE, PCK_SHA256)
    evidence["signing"] = {"team_id": TEAM_ID, "native_files_signed": len(native), "hardened_runtime": True,
                           "jit_entitlements": JIT_ENTITLEMENTS, "managed_assemblies_unchanged": len(before_dlls),
                           "pck_unchanged": True, "minimum_macos": MINIMUM_MACOS,
                           "certificate_chain": authorities,
                           "public_intermediate_sha256": DEVELOPER_ID_CA_SHA256,
                           "embedded_signed_intermediate_sha256_verified": True}


class MultipartWriter(io.RawIOBase):
    """Write a nonseekable ZIP directly to sized release parts, hashing each byte."""
    def __init__(self, directory: Path, name: str, limit: int = PART_LIMIT):
        super().__init__()
        require(limit > 0, "Part limit must be positive.")
        self.directory, self.name, self.limit = directory, name, limit
        self.position = 0
        self.digest = hashlib.sha256()
        self.parts: list[dict] = []
        self.stream = None
        self.part_digest = None
        self.part_size = 0

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def tell(self) -> int:
        return self.position

    def _finish_part(self) -> None:
        if self.stream is not None:
            self.stream.close()
            self.parts.append({"name": Path(self.stream.name).name, "size": self.part_size,
                               "sha256": self.part_digest.hexdigest()})
            self.stream = None

    def write(self, data) -> int:
        require(not self.closed, "Multipart stream is already closed.")
        data = memoryview(data)
        total = len(data)
        self.digest.update(data)
        while data:
            if self.stream is None:
                name = f"{self.name}.part{len(self.parts) + 1:02d}"
                self.stream = (self.directory / name).open("xb")
                self.part_size, self.part_digest = 0, hashlib.sha256()
            count = min(len(data), self.limit - self.part_size)
            chunk = data[:count]
            self.stream.write(chunk)
            self.part_digest.update(chunk)
            self.part_size += count
            self.position += count
            data = data[count:]
            if self.part_size == self.limit:
                self._finish_part()
        return total

    def close(self) -> None:
        if not self.closed:
            self._finish_part()
        super().close()


def write_app_zip(app: Path, target) -> None:
    # ZIP_STORED keeps the 4GB PCK at a predictable, low-memory IO rate. Unix modes
    # are explicit; no symlinks, AppleDouble, Finder metadata or secret files enter.
    with ZipFile(target, "w", compression=ZIP_STORED, allowZip64=True) as archive:
        for path in [app, *sorted(app.rglob("*"))]:
            require(not path.is_symlink(), "A symlink cannot be packaged.")
            require(path.is_file() or path.is_dir(), "A special file cannot be packaged.")
            relative = path.relative_to(app.parent).as_posix()
            assert_safe_name(relative)
            name = relative + ("/" if path.is_dir() else "")
            entry = ZipInfo(name, (2026, 11, 25, 0, 0, 0))
            entry.create_system = 3
            entry.compress_type = ZIP_STORED
            mode = path.stat().st_mode
            entry.external_attr = (stat.S_IFMT(mode) | stat.S_IMODE(mode) & 0o777) << 16
            if path.is_dir():
                entry.external_attr |= 0x10
                archive.writestr(entry, b"")
            else:
                entry.file_size = path.stat().st_size
                with path.open("rb") as src, archive.open(entry, "w", force_zip64=True) as dst:
                    shutil.copyfileobj(src, dst, 4 * 1024 * 1024)


def notarize(app: Path, work: Path, api_raw: str, evidence: dict, progress_path: Path) -> None:
    issuer, key_id, pem = convert_api_json(api_raw)
    api_file = work / "notary-key.p8"
    private_write(api_file, pem)
    size = sum(path.stat().st_size for path in app.rglob("*") if path.is_file())
    required = size + ZIP_METADATA_BUDGET + RESERVE
    free = shutil.disk_usage(work).free
    require(free > required, "Runner has insufficient space for the temporary notarization ZIP.")
    evidence["disk_budget"] = {"app_regular_file_bytes": size, "zip_metadata_budget": ZIP_METADATA_BUDGET,
                               "reserve_bytes": RESERVE, "free_before_notary_zip": free,
                               "required_extra_before_zip": required,
                               "conservative_app_and_zip_peak_bytes": size * 2 + ZIP_METADATA_BUDGET + RESERVE,
                               "base_parts_deleted_during_stream": True}
    archive = work / "notary-game.zip"
    print("Packaging native signed app for Apple notarization.", flush=True)
    write_app_zip(app, archive)
    submitted_sha = sha256_file(archive)
    auth = ["--key", str(api_file), "--key-id", key_id, "--issuer", issuer]
    print("Uploading notarization ZIP to Apple (separate upload timeout: 600s).", flush=True)
    upload_started = time.monotonic()
    result = command(["/usr/bin/xcrun", "notarytool", "submit", str(archive), *auth,
                      "--output-format", "json"],
                     "Apple notarization upload", timeout=600, check=False)
    try:
        response = json.loads(result.stdout)
        submission_id = response.get("id")
        require(isinstance(submission_id, str) and str(uuid.UUID(submission_id)) == submission_id.lower(),
                "Apple notarization did not return a submission ID.")
    except (ValueError, TypeError, AttributeError):
        raise PipelineError("Apple notarization did not return a valid JSON result.") from None
    evidence["notarization"] = {"status": "Submitted" if result.returncode == 0 else "UploadUnconfirmed",
                                "submission_id": submission_id, "submitted_zip_sha256": submitted_sha,
                                "submitted_zip_size": archive.stat().st_size,
                                "upload_elapsed_seconds": round(time.monotonic() - upload_started, 3)}
    # Save a durable, credential-free ID BEFORE waiting. A wait interruption must
    # never force a duplicate 4GB submission merely to recover its identifier.
    write_json(progress_path, evidence)
    print(f"Apple submission ID: {submission_id}; ZIP SHA-256: {submitted_sha}", flush=True)
    require(result.returncode == 0, "Apple upload was not confirmed; preserved submission ID requires inspection.")
    print("Waiting on the existing Apple submission (up to 20 minutes).", flush=True)
    wait_started = time.monotonic()
    result = command(["/usr/bin/xcrun", "notarytool", "wait", submission_id, *auth,
                      "--timeout", "20m", "--output-format", "json"],
                     "Apple notarization wait", timeout=1250, check=False)
    try:
        response = json.loads(result.stdout)
        status = response.get("status")
        require(response.get("id", submission_id).lower() == submission_id.lower(),
                "Apple wait returned a different submission ID.")
    except (ValueError, TypeError, AttributeError):
        raise PipelineError("Apple wait did not return a valid JSON result; the saved submission ID remains available.") from None
    evidence["notarization"].update(status=status, wait_elapsed_seconds=round(time.monotonic() - wait_started, 3))
    write_json(progress_path, evidence)
    require(result.returncode == 0 and status == "Accepted", "Apple has not accepted this app; publication is blocked.")
    print(f"Apple Accepted: {submission_id}. Stapling and checking native trust.", flush=True)
    archive.unlink()  # Release the 4GB duplicate before packaging final release parts.
    evidence["disk_budget"]["notary_zip_deleted_before_release_packaging"] = not archive.exists()
    api_file.unlink()
    command(["/usr/bin/xcrun", "stapler", "staple", str(app)], "Staple accepted Apple ticket", timeout=180)
    trust(app, prefix="game_trust", evidence=evidence)


def remove_signing_material(work: Path, evidence: dict) -> None:
    restore_user_keychain_search_list(work)
    keychain = work / "signing.keychain-db"
    if keychain.exists():
        command(["/usr/bin/security", "delete-keychain", str(keychain)], "Remove signing keychain before game execution")
    require(not any(work.glob("signing.keychain*")), "Signing keychain still exists; game execution is blocked.")
    require(not (work / "identity.p12").exists() and not (work / "notary-key.p8").exists(),
            "Signing material still exists; game execution is blocked.")
    require(not any(name in os.environ for name in (*SECRET_NAMES, "GH_TOKEN", "GITHUB_TOKEN")),
            "Signing or release credentials remain in the process environment.")
    evidence["signing_material_removed_before_game_execution"] = True
    evidence["user_keychain_search_list_restored_before_game_execution"] = True


def smoke_passed(exit_code: int, log: str) -> bool:
    return exit_code == 0 and BOOT_MARKER in log and BOOT_FAILURE_PATTERN.search(log) is None


def native_library_smoke(app: Path, work: Path, evidence: dict) -> None:
    require(evidence.get("signing_material_removed_before_game_execution") is True,
            "Game smoke requires signing material cleanup first.")
    qa = work / "qa"
    qa.mkdir()
    temporary = qa / "tmp"
    temporary.mkdir()
    log_file = qa / "boot.log"
    # The hosted CI account is disposable. Keep its HOME unchanged, supply only
    # ordinary OS runtime variables, and place temporary files/logs under our work.
    # No Apple secret, GH token or Actions runtime token is inherited by the game.
    allowed = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "__CF_USER_TEXT_ENCODING")
    env = {name: os.environ[name] for name in allowed if name in os.environ}
    env.update(TMPDIR=str(temporary), CI="true")
    executable = app / "Contents/MacOS/Orvala"
    version_result = command([str(executable), "--version"], "Frozen Godot mono version", timeout=20, env=env, check=False)
    version_text = version_result.stdout.decode("utf-8", "replace").strip()
    evidence["native_game_executed"] = True
    evidence["engine_version_probe"] = {"exit_code": version_result.returncode, "version": version_text}
    require(version_result.returncode == 0 and re.fullmatch(r"4\.7\.2\.stable\.mono(?:\.[A-Za-z0-9_]+)*", version_text) is not None,
            "Final app does not report the frozen Godot 4.7.2 stable mono version.")
    args = [str(executable), "--headless", "--max-fps", "60", "--quit-after", "600",
            "--log-file", str(log_file), "--", "--library-entry-smoke"]
    started = time.monotonic()
    result = command(args, "Native .NET library and deck selector smoke", timeout=90, env=env, check=False)
    log_bytes = result.stdout + result.stderr
    if log_file.is_file():
        log_bytes += b"\n" + log_file.read_bytes()
    log_text = log_bytes.decode("utf-8", "replace")
    passed = smoke_passed(result.returncode, log_text)
    evidence["native_smoke"] = {"passed": passed, "test": "headless .NET library entry and starter deck selector",
                                "exit_code": result.returncode, "marker_seen": BOOT_MARKER in log_text,
                                "engine_script_or_dotnet_error_seen": BOOT_FAILURE_PATTERN.search(log_text) is not None,
                                "timeout_seconds": 90, "elapsed_seconds": round(time.monotonic() - started, 3),
                                "combined_log_sha256": hashlib.sha256(log_bytes).hexdigest(), "combined_log_bytes": len(log_bytes),
                                "credential_free_child_environment": True, "disposable_hosted_ci_profile": True,
                                "visual_tested": False, "login_tested": False, "multiplayer_tested": False}
    evidence["native_game_executed"] = True
    evidence["visual_tested"] = False
    require(passed, "Native .NET library/selector smoke requires exit 0, its exact marker, and no engine/script/assembly errors.")


def verify_final_roundtrip(app: Path, output: Path, work: Path, validator: Path,
                           manifest: dict, parts: list[dict], evidence: dict) -> Path:
    # Hard links preserve the release assets while stream_extract unlinks only
    # the consumed temporary part-N names. No second final ZIP is materialized.
    check = work / "final-validation"
    check.mkdir()
    write_json(check / "manifest.json", manifest)
    for index, part in enumerate(parts, 1):
        source = output / part["name"]
        verify_file(source, part["size"], part["sha256"])
        os.link(source, check / f"part-{index}")
    jxa(validator, "manifest", check / "manifest.json", "")
    table_text = jxa(validator, "parts", check)
    expanded, files, _ = map(int, table_text.splitlines()[0].split("\t"))
    table = check / "archive.tsv"
    table.write_text(table_text + "\n", encoding="utf-8")
    original_root = work / "game"
    require(app == original_root / "Orvala.app" and original_root.resolve().parent == work.resolve(),
            "Unexpected temporary original app path; refusing to remove it.")
    shutil.rmtree(original_root)  # Only the generated app, never installed games or user saves.
    require(not original_root.exists(), "Original temporary app was not removed.")
    # Because final release hardlinks retain consumed bytes, extraction cannot
    # count on freeing those parts. Reserve the WHOLE expanded app, not JXA's
    # incremental updater budget; this keeps the peak around two app copies.
    required = expanded + ZIP_METADATA_BUDGET + RESERVE
    free = shutil.disk_usage(work).free
    require(free > required, "Runner has insufficient space for final package round-trip extraction.")
    extracted = work / "final-extracted"
    extracted.mkdir()
    stream_extract([check / f"part-{index}" for index in range(1, len(parts) + 1)], extracted)
    jxa(validator, "permissions", table, extracted)
    jxa(validator, "extracted", table, extracted)
    verified_app = extracted / "Orvala.app"
    verify_file(verified_app / "Contents/Resources/Orvala.pck", PCK_SIZE, PCK_SHA256)
    trust(verified_app, prefix="final_roundtrip_trust", evidence=evidence)
    evidence["final_roundtrip"] = {"passed": True, "files": files, "expanded_bytes": expanded,
                                    "parts_reextracted": len(parts), "release_parts_preserved": True,
                                    "shipping_jxa_permissions_and_extracted": True,
                                    "original_temporary_app_removed": True, "pck_sha256": PCK_SHA256,
                                    "free_before_extraction": free, "required_extra_bytes": required}
    evidence["disk_budget"]["final_roundtrip_uses_retained_part_budget"] = True
    shutil.rmtree(check)
    return verified_app


def gh_json(args: list[str], token: str, *, allow_missing: bool = False) -> object | None:
    env = dict(os.environ, GH_TOKEN=token, GH_PROMPT_DISABLED="1")
    result = command(["gh", *args], "Own repository release API", env=env, check=False, timeout=300)
    if result.returncode:
        if allow_missing and b"HTTP 404" in result.stderr:
            return None
        raise PipelineError("Own repository release API failed; existing assets were preserved.")
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise PipelineError("Own repository release API returned invalid JSON.") from None


def ensure_release(token: str) -> dict:
    endpoint = f"repos/{REPOSITORY}/releases"
    existing = gh_json(["api", f"{endpoint}/tags/v{VERSION}"], token, allow_missing=True)
    if existing is None:
        existing = gh_json([
            "api", "--method", "POST", endpoint, "-f", f"tag_name=v{VERSION}",
            "-f", f"name=Orvala Mac {VERSION} — validação", "-f", "make_latest=false", "-F", "prerelease=true",
            "-f", "body=Mac Apple Silicon, macOS 13+. Pacote assinado e notarizado. Canal em validação; sem promoção do portal."
        ], token)
    require(isinstance(existing, dict) and existing.get("tag_name") == f"v{VERSION}"
            and existing.get("prerelease") is True and existing.get("draft") is False,
            "Existing version is not a public pre-release; refusing to change its state.")
    # Keep a pre-existing prerelease out of latest, too. This does not edit assets.
    gh_json(["api", "--method", "PATCH", f"{endpoint}/{existing['id']}", "-f", "make_latest=false",
             "-F", "prerelease=true"], token)
    return existing


def release_assets(endpoint: str, token: str) -> dict[str, dict]:
    pages = gh_json(["api", "--paginate", "--slurp", endpoint], token)
    require(isinstance(pages, list) and all(isinstance(page, list) for page in pages),
            "Unexpected release assets response.")
    items = [item for page in pages for item in page]
    require(all(isinstance(item, dict) and isinstance(item.get("name"), str) for item in items),
            "Unexpected release asset metadata.")
    require(len({item["name"] for item in items}) == len(items), "Duplicate remote asset names; refusing ambiguous publication.")
    return {item["name"]: item for item in items}


def asset_matches(asset: dict, expected: dict) -> bool:
    return (asset.get("name") == expected["name"] and asset.get("state") == "uploaded"
            and asset.get("size") == expected["size"] and asset.get("digest") == "sha256:" + expected["sha256"])


def is_current_release_part(name: str) -> bool:
    return re.fullmatch(re.escape(f"Orvala-Mac-arm64-{VERSION}.zip.part") + r"[0-9]{2}", name) is not None


def own_new_empty_starter(asset: dict, expected: dict, baseline_ids: set[int],
                          attempt_started: float) -> bool:
    if (not is_current_release_part(expected["name"])
            or asset.get("name") != expected["name"] or asset.get("state") != "starter"
            or asset.get("size") != 0 or asset.get("digest") not in (None, "")
            or type(asset.get("id")) is not int or asset["id"] in baseline_ids
            or not isinstance(asset.get("uploader"), dict)
            or asset["uploader"].get("login") != "github-actions[bot]"):
        return False
    try:
        created = datetime.fromisoformat(asset["created_at"].replace("Z", "+00:00")).timestamp()
    except (KeyError, TypeError, ValueError):
        return False
    # GitHub dates have second precision. A very narrow tolerance accommodates
    # truncation, never a leftover from a preceding run or preflight snapshot.
    return attempt_started - 2 <= created <= time.time() + 2


def verified_asset_record(asset: dict) -> dict:
    return {key: asset[key] for key in ("id", "name", "size", "digest")}


def upload_release_asset(expected: dict, token: str, endpoint: str,
                         baseline_ids: set[int], *, attempts: int = 3) -> dict:
    path = expected["path"]
    name = expected["name"]
    env = dict(os.environ, GH_TOKEN=token, GH_PROMPT_DISABLED="1")
    removed_starters = []
    for attempt in range(1, attempts + 1):
        before = release_assets(endpoint, token).get(name)
        if before:
            require(asset_matches(before, expected), f"Existing asset differs or has no verifiable digest: {name}; refusing to overwrite.")
            return {**verified_asset_record(before), "attempts": attempt - 1, "removed_own_empty_starters": removed_starters}
        started = time.time()
        print(f"Uploading {name}: attempt {attempt}/{attempts}.", flush=True)
        cli_failed = False
        try:
            upload_result = command(["gh", "release", "upload", f"v{VERSION}", str(path), "--repo", REPOSITORY],
                                    f"Upload own pre-release asset {name}", env=env, timeout=300, check=False)
            cli_failed = upload_result.returncode != 0
        except PipelineError:
            # An HTTP/CLI timeout is ambiguous: the server may already have the
            # complete bytes. Reconcile exact remote metadata BEFORE any retry.
            cli_failed = True
        after = release_assets(endpoint, token).get(name)
        if after and asset_matches(after, expected):
            print(f"Verified {name}: asset ID {after['id']} (remote size and SHA-256 match).", flush=True)
            return {**verified_asset_record(after), "attempts": attempt,
                    "removed_own_empty_starters": removed_starters}
        if after:
            require(cli_failed and own_new_empty_starter(after, expected, baseline_ids, started),
                    f"Remote asset differs or upload state is ambiguous: {name}; refusing to overwrite or delete.")
            # Only the empty starter newly created by THIS attempted part upload
            # can be removed. Bootstrap, existing IDs and uploaded bytes cannot.
            asset_id = after["id"]
            fresh = gh_json(["api", f"repos/{REPOSITORY}/releases/assets/{asset_id}"], token)
            if isinstance(fresh, dict) and asset_matches(fresh, expected):
                return {**verified_asset_record(fresh), "attempts": attempt,
                        "removed_own_empty_starters": removed_starters}
            require(isinstance(fresh, dict) and own_new_empty_starter(fresh, expected, baseline_ids, started)
                    and fresh["id"] == asset_id,
                    f"Asset state changed before retry: {name}; refusing deletion.")
            command(["gh", "api", "--method", "DELETE", f"repos/{REPOSITORY}/releases/assets/{asset_id}"],
                    f"Remove only this attempt's empty starter for {name}", env=env, timeout=60)
            require(release_assets(endpoint, token).get(name) is None,
                    f"Empty starter removal could not be confirmed: {name}.")
            removed_starters.append(asset_id)
            print(f"Removed this attempt's empty starter {asset_id} for {name}; no uploaded asset was replaced.", flush=True)
        if attempt < attempts:
            print(f"Retrying {name} after remote reconciliation ({attempt * 3}s backoff).", flush=True)
            time.sleep(attempt * 3)
    raise PipelineError(f"Upload unresolved after {attempts} reconciled attempts: {name}; manifest was not published.")


def publish_files(files: list[Path], token: str, evidence: dict, progress_path: Path) -> None:
    require(os.environ.get("GITHUB_REPOSITORY", "").lower() == REPOSITORY.lower(),
            "Publishing is restricted to the own release repository.")
    release = ensure_release(token)
    endpoint = f"repos/{REPOSITORY}/releases/{release['id']}/assets"
    existing = release_assets(endpoint, token)
    baseline_ids = {item["id"] for item in existing.values()}
    # Preflight every existing name before uploading ANY new asset. Never --clobber.
    pending, reused, expected_files = [], [], []
    for path in files:
        expected = {"path": path, "name": path.name, "sha256": sha256_file(path), "size": path.stat().st_size}
        expected_files.append(expected)
        asset = existing.get(path.name)
        if asset:
            require(asset_matches(asset, expected),
                    f"Existing asset differs or has no verifiable digest: {path.name}; refusing to overwrite.")
            reused.append(path.name)
        else:
            pending.append(expected)
    parts = [item for item in expected_files if is_current_release_part(item["name"])]
    require(len(parts) == len(PART_SPECS), "All seven final release parts must be present before publication.")
    auxiliary_names = (BOOTSTRAP_NAME, EVIDENCE_NAME, "macos-arm64.json")
    require({item["name"] for item in expected_files} == {item["name"] for item in parts} | set(auxiliary_names),
            "Unexpected release publication file set.")
    uploaded_records, failures = [], []
    evidence["publication_progress"] = {"verified_new_part_assets": [], "all_seven_remote_parts_verified": False,
                                        "manifest_published": False}
    write_json(progress_path, evidence)
    pending_parts = [item for item in pending if item in parts]
    print(f"Publishing {len(pending_parts)} pending parts with at most 3 concurrent uploads.", flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(upload_release_asset, item, token, endpoint, baseline_ids): item["name"] for item in pending_parts}
        for future in concurrent.futures.as_completed(futures):
            try:
                uploaded_records.append(future.result())
            except PipelineError as error:
                failures.append(str(error))
            evidence["publication_progress"]["verified_new_part_assets"] = sorted(uploaded_records, key=lambda item: item["name"])
            write_json(progress_path, evidence)
    require(not failures, failures[0] if failures else "Part upload failed.")
    remote = release_assets(endpoint, token)
    require(all(asset_matches(remote.get(item["name"], {}), item) for item in parts),
            "All seven remote part digests must match before evidence or manifest upload.")
    evidence["publication_progress"]["all_seven_remote_parts_verified"] = True
    evidence["publication_progress"]["all_part_assets"] = [verified_asset_record(remote[item["name"]]) for item in parts]
    write_json(progress_path, evidence)
    print("All seven remote part sizes and SHA-256 digests verified. Publishing small evidence and manifest last.", flush=True)
    # Small assets are sequential, strictly after all seven remote parts verify.
    # The exact bootstrap is always reused when present and never overwritten.
    for name in auxiliary_names:
        expected = next(item for item in expected_files if item["name"] == name)
        if name not in reused:
            uploaded_records.append(upload_release_asset(expected, token, endpoint, baseline_ids))
        if name == "macos-arm64.json":
            evidence["publication_progress"]["manifest_published"] = True
            write_json(progress_path, evidence)
    verified = release_assets(endpoint, token)
    for expected in expected_files:
        require(asset_matches(verified.get(expected["name"], {}), expected),
                f"Published asset digest could not be verified: {expected['name']}.")
    evidence["publication"] = {"repository": REPOSITORY, "tag": f"v{VERSION}", "prerelease": True,
                               "make_latest": False, "reused_assets": reused,
                               "uploaded_assets": [item["name"] for item in pending], "remote_asset_digests_verified": True,
                               "uploaded_asset_records": sorted(uploaded_records, key=lambda item: item["name"]),
                               "max_concurrent_part_uploads": 3, "max_upload_attempts": 3,
                               "portal_promoted": False}


def cleanup(work: Path) -> None:
    # Deletion is restricted to an exclusive directory marked by this program.
    require(work.name.startswith("orvala-macos-104-"), "Unexpected private workspace name; refusing cleanup.")
    if not work.exists():
        return
    require(not work.is_symlink() and (work / ".orvala-cloud-owned").read_text() == VERSION,
            "Private workspace ownership cannot be verified; refusing cleanup.")
    keychain = work / "signing.keychain-db"
    restore_error = None
    if sys.platform == "darwin":
        try:
            restore_user_keychain_search_list(work)
        except Exception:
            restore_error = PipelineError("User keychain search-list restoration failed during cleanup.")
        if keychain.exists():
            try:
                command(["/usr/bin/security", "delete-keychain", str(keychain)], "Temporary keychain cleanup", check=False)
            except PipelineError:
                # Still erase the owned private directory, including the encrypted
                # keychain file and any P12/P8 left by an earlier failed import.
                restore_error = restore_error or PipelineError("Temporary keychain removal command failed during cleanup.")
    shutil.rmtree(work)
    if restore_error:
        raise restore_error


def plan() -> dict:
    return {
        "mode": "offline plan; no network, credentials or external changes", "repository": REPOSITORY,
        "runner": "standard public macos-15 / Apple Silicon", "timeout_minutes": 40,
        "target_version": VERSION, "minimum_macos": MINIMUM_MACOS,
        "base": base_manifest(),
        "bootstrap_launcher_version": BOOTSTRAP_VERSION,
        "bootstrap": {"launcher_version": BOOTSTRAP_VERSION, "url": BOOTSTRAP_URL,
                      "size": BOOTSTRAP_SIZE, "sha256": BOOTSTRAP_SHA256,
                      "approved_signed_notarized_bytes_reused": True},
        "public_intermediate": {"url": DEVELOPER_ID_CA_URL, "size": DEVELOPER_ID_CA_SIZE,
                                "sha256": DEVELOPER_ID_CA_SHA256},
        "pck": {"size": PCK_SIZE, "sha256": PCK_SHA256}, "temporary_secret_names": list(SECRET_NAMES),
        "steps": ["Verify public bootstrap hash and native Apple trust checks",
                  "Download seven frozen public base parts; verify individual and virtual ZIP hashes",
                  "Run approved bootstrap JXA, native tar streaming, restore and verify Unix permissions",
                  "Keep PCK and managed assemblies frozen; update bundle version/minimum OS only",
                  "Import leaf Developer ID and pinned official G2 intermediate into an isolated temporary keychain; sign all Mach-O and main bundle",
                  "Upload to Apple separately (600s), persist submission ID, then wait on that ID (20m); require Accepted, staple and verify trust",
                  "Delete temporary notary ZIP; create Unix-mode ZIP directly into <=700MB hashed parts",
                  "Delete original temporary app; reextract final parts via hardlinks, restore permissions and reverify Apple trust",
                  "Delete signing keychain/material; run credential-free native .NET library and deck selector smoke (90s)",
                  f"Optionally publish own v{VERSION} pre-release with 3 parallel reconciled part uploads; evidence/manifest last after all 7 remote hashes match",
                  "Remove temporary keychain and all secret material even on failure"],
        "publication_requires": f"--run --publish --confirm-version {VERSION}, authorized temporary secrets, own repo GITHUB_TOKEN",
        "external_mutations": ["Apple notarization submission with --run", "own pre-release assets only with --publish"],
        "does_not_verify": ["Rendered or interactive gameplay", "M5 hardware gameplay", "online login or multiplayer"],
        "portal_promoted": False, "private_game_sources_published": False,
        "disk_budget": {"base_download_required": BASE_SIZE + PART_LIMIT + 134_217_728,
                        "payload_peak_formula": "2 * expanded_app_bytes + 64MiB ZIP metadata + 512MiB reserve",
                        "base_parts_deleted_as_consumed": True, "notary_zip_deleted_before_final_parts": True},
    }


class OfflineTests(unittest.TestCase):
    def test_rcodesign_der_to_pem_and_invalid_schema(self):
        der = b"\x30" + bytes(range(1, 100))
        issuer, key, pem = convert_api_json(json.dumps({"issuer_id": "743b00ee-ebbb-407b-ba7b-951fd6ad00d7",
                                                       "key_id": "FAKEKEY123", "private_key": base64.b64encode(der).decode()}))
        self.assertEqual(key, "FAKEKEY123")
        self.assertEqual(base64.b64decode(b"".join(pem.splitlines()[1:-1])), der)
        self.assertEqual(issuer, "743b00ee-ebbb-407b-ba7b-951fd6ad00d7")
        for raw in ('{}', '{"issuer_id":"bad"}', '{"private_key":"redacted"}'):
            with self.assertRaises(PipelineError):
                convert_api_json(raw)

    def test_multipart_zip_preserves_payload_modes_and_whole_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "Orvala.app"
            (app / "Contents/MacOS").mkdir(parents=True)
            executable = app / "Contents/MacOS/Orvala"
            executable.write_bytes(bytes(range(256)) * 8)
            executable.chmod(0o755)
            output = root / "parts"
            output.mkdir()
            with MultipartWriter(output, "fixture.zip", limit=173) as target:
                write_app_zip(app, target)
            wire = b"".join((output / item["name"]).read_bytes() for item in target.parts)
            self.assertEqual(hashlib.sha256(wire).hexdigest(), target.digest.hexdigest())
            self.assertEqual(len(wire), target.position)
            self.assertGreater(len(target.parts), 3)
            self.assertTrue(all(0 < item["size"] <= 173 for item in target.parts))
            for item in target.parts:
                verify_file(output / item["name"], item["size"], item["sha256"])
            with ZipFile(io.BytesIO(wire)) as archive:
                self.assertIsNone(archive.testzip())
                self.assertEqual(archive.read("Orvala.app/Contents/MacOS/Orvala"), executable.read_bytes())
                self.assertEqual((archive.getinfo("Orvala.app/Contents/MacOS/Orvala").external_attr >> 16) & 0o777,
                                 executable.stat().st_mode & 0o777)

    def test_reject_archive_traversal_appledouble_and_symlink(self):
        for name in ("../evil", "/evil", "Orvala.app/../evil", "Orvala.app/._file", "__MACOSX/file", "bad\\path"):
            with self.assertRaises(PipelineError):
                assert_safe_name(name)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / "bad.zip"
            with ZipFile(archive_path, "w") as archive:
                entry = ZipInfo("Orvala.app/link")
                entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(entry, "outside")
            with self.assertRaises(PipelineError):
                extract_bootstrap(archive_path, root / "extracted")

    def test_base_manifest_pins_all_parts(self):
        manifest = base_manifest()
        self.assertEqual(sum(part["size"] for part in manifest["parts"]), BASE_SIZE)
        self.assertEqual(len(manifest["parts"]), 7)
        self.assertEqual(len({part["url"] for part in manifest["parts"]}), 7)
        self.assertTrue(all(re.fullmatch("[a-f0-9]{64}", part["sha256"]) for part in manifest["parts"]))

    def test_signing_requires_complete_g2_chain_team_and_hardened_runtime(self):
        description = ("CodeDirectory v=20500 flags=0x10000(runtime)\n"
                       "Authority=Developer ID Application: Fixture (WN9MP7LBRW)\n"
                       "Authority=Developer ID Certification Authority\n"
                       "Authority=Apple Root CA\nTeamIdentifier=WN9MP7LBRW\n")
        self.assertEqual(len(verify_signed_chain(description)), 3)
        for broken in (description.replace("Developer ID Certification Authority", "Unrelated Certification Authority"),
                       description.replace("Apple Root CA", "Other Root"),
                       description.replace("TeamIdentifier=WN9MP7LBRW", "TeamIdentifier=OTHERTEAM1"),
                       description.replace("(runtime)", "(adhoc)")):
            with self.assertRaises(PipelineError):
                verify_signed_chain(broken)

    def test_native_smoke_requires_its_marker_and_successful_exit(self):
        self.assertTrue(smoke_passed(0, "Godot .NET started\n" + BOOT_MARKER))
        self.assertFalse(smoke_passed(1, BOOT_MARKER))
        self.assertFalse(smoke_passed(0, "Godot started, but C# library smoke was not reached"))
        for problem in ("ERROR: fixture failure", "SCRIPT ERROR: fixture failure", "SCRIPTERROR: fixture failure",
                        "Unable to find the .NET assemblies directory.", "Failed to load hostfxr.", "Unhandled exception"):
            self.assertFalse(smoke_passed(0, BOOT_MARKER + "\n" + problem))

    def test_temporary_keychain_registration_and_restore_preserve_other_keychains(self):
        original = ["/Users/runner/Library/Keychains/login.keychain-db", "/Library/Keychains/Existing.keychain-db"]
        temporary = "/private/tmp/orvala-macos-104-test/signing.keychain-db"
        new_other = "/Users/runner/Library/Keychains/Other.keychain-db"
        registered = merged_keychain_list(original, original, temporary, include_temporary=True)
        self.assertEqual(registered, [*original, temporary])
        restored = merged_keychain_list(original, [*registered, new_other], temporary, include_temporary=False)
        self.assertEqual(restored, [*original, new_other])

    def test_codesign_diagnostic_sanitization_excludes_control_and_key_blocks(self):
        diagnostic = safe_codesign_stderr(b"\x1b[31mContents/MacOS/Orvala: errSecInternalComponent\x1b[0m\n"
                                          b"-----BEGIN PRIVATE KEY-----\nfixture-secret\n-----END PRIVATE KEY-----\x00")
        self.assertIn("errSecInternalComponent", diagnostic)
        self.assertNotIn("fixture-secret", diagnostic)
        self.assertNotIn("\x1b", diagnostic)
        self.assertNotIn("\x00", diagnostic)

    @staticmethod
    def upload_fixture():
        name = f"Orvala-Mac-arm64-{VERSION}.zip.part01"
        expected = {"path": Path(name), "name": name, "size": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
        asset = {"id": 101, "name": name, "state": "uploaded", "size": 3, "digest": "sha256:" + expected["sha256"]}
        return expected, asset

    def test_upload_timeout_reconciles_already_accepted_remote_without_retry_or_delete(self):
        expected, asset = self.upload_fixture()
        with mock.patch(__name__ + ".release_assets", side_effect=[{}, {expected["name"]: asset}]), \
             mock.patch(__name__ + ".command", side_effect=PipelineError("fixture timeout")) as cli, \
             mock.patch(__name__ + ".time.sleep") as pause, mock.patch("builtins.print"):
            result = upload_release_asset(expected, "fixture-token", "fixture-endpoint", {1})
        self.assertEqual(result["id"], 101)
        self.assertEqual(cli.call_count, 1)
        pause.assert_not_called()

    def test_upload_transient_failure_retries_only_after_remote_absence_is_confirmed(self):
        expected, asset = self.upload_fixture()
        failed = subprocess.CompletedProcess([], 1, b"", b"fixture upstream failure")
        success = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch(__name__ + ".release_assets", side_effect=[{}, {}, {}, {expected["name"]: asset}]), \
             mock.patch(__name__ + ".command", side_effect=[failed, success]) as cli, \
             mock.patch(__name__ + ".time.sleep") as pause, mock.patch("builtins.print"):
            result = upload_release_asset(expected, "fixture-token", "fixture-endpoint", {1})
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(cli.call_count, 2)
        pause.assert_called_once_with(3)

    def test_upload_different_remote_digest_never_retries_deletes_or_overwrites(self):
        expected, asset = self.upload_fixture()
        asset["digest"] = "sha256:" + "f" * 64
        with mock.patch(__name__ + ".release_assets", side_effect=[{}, {expected["name"]: asset}]), \
             mock.patch(__name__ + ".command", return_value=subprocess.CompletedProcess([], 1, b"", b"")) as cli, \
             mock.patch(__name__ + ".time.sleep") as pause, mock.patch("builtins.print"):
            with self.assertRaises(PipelineError):
                upload_release_asset(expected, "fixture-token", "fixture-endpoint", {1})
        self.assertEqual(cli.call_count, 1)
        pause.assert_not_called()

    def test_only_this_attempts_new_empty_part_starter_can_be_removed_for_retry(self):
        expected, asset = self.upload_fixture()
        starter = {"id": 102, "name": expected["name"], "state": "starter", "size": 0, "digest": None,
                   "uploader": {"login": "github-actions[bot]"},
                   "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        self.assertFalse(own_new_empty_starter(starter, expected, {102}, time.time()))
        self.assertFalse(own_new_empty_starter({**starter, "name": BOOTSTRAP_NAME},
                                              {**expected, "name": BOOTSTRAP_NAME}, set(), time.time()))
        old_name = "Orvala-Mac-arm64-1.0.4.zip.part01"
        self.assertFalse(own_new_empty_starter({**starter, "name": old_name},
                                              {**expected, "name": old_name}, set(), time.time()))
        self.assertFalse(own_new_empty_starter({**starter, "created_at": "2020-01-01T00:00:00Z"}, expected, set(), time.time()))
        self.assertFalse(own_new_empty_starter({**starter, "uploader": {"login": "other"}}, expected, set(), time.time()))
        with mock.patch(__name__ + ".release_assets", side_effect=[{}, {expected["name"]: starter}, {}, {}, {expected["name"]: asset}]), \
             mock.patch(__name__ + ".gh_json", return_value=starter), \
             mock.patch(__name__ + ".command", side_effect=[subprocess.CompletedProcess([], 1, b"", b""),
                                                            subprocess.CompletedProcess([], 0, b"", b""),
                                                            subprocess.CompletedProcess([], 0, b"", b"")]) as cli, \
             mock.patch(__name__ + ".time.sleep"), mock.patch("builtins.print"):
            result = upload_release_asset(expected, "fixture-token", "fixture-endpoint", {1})
        self.assertEqual(result["removed_own_empty_starters"], [102])
        delete_calls = [call.args[0] for call in cli.call_args_list if "DELETE" in call.args[0]]
        self.assertEqual(len(delete_calls), 1)
        self.assertTrue(delete_calls[0][-1].endswith("/assets/102"))

    def test_cli_success_with_ambiguous_starter_metadata_is_never_deleted(self):
        expected, _ = self.upload_fixture()
        starter = {"id": 102, "name": expected["name"], "state": "starter", "size": 0, "digest": None,
                   "uploader": {"login": "github-actions[bot]"},
                   "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        with mock.patch(__name__ + ".release_assets", side_effect=[{}, {expected["name"]: starter}]), \
             mock.patch(__name__ + ".command", return_value=subprocess.CompletedProcess([], 0, b"", b"")) as cli, \
             mock.patch("builtins.print"):
            with self.assertRaises(PipelineError):
                upload_release_asset(expected, "fixture-token", "fixture-endpoint", {1})
        self.assertEqual(cli.call_count, 1)

    def test_wait_timeout_keeps_uploaded_submission_id_durable_before_waiting(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            app = work / "Orvala.app"
            app.mkdir()
            (app / "fixture").write_bytes(b"fixture")
            progress = work / "progress.json"
            api = json.dumps({"issuer_id": "743b00ee-ebbb-407b-ba7b-951fd6ad00d7", "key_id": "FAKEKEY123",
                              "private_key": base64.b64encode(b"\x30" + bytes(range(1, 100))).decode()})
            submission_id = "00000000-0000-4000-8000-000000000001"
            def fake_command(args, label, **kwargs):
                if "submit" in args:
                    self.assertNotIn("--wait", args)
                    self.assertEqual(kwargs["timeout"], 600)
                    return subprocess.CompletedProcess(args, 0, json.dumps({"id": submission_id}).encode(), b"")
                self.assertIn("wait", args)
                self.assertEqual(kwargs["timeout"], 1250)
                self.assertEqual(json.loads(progress.read_text())["notarization"]["submission_id"], submission_id)
                raise PipelineError("fixture wait timeout")
            def fake_zip(app_path, target):
                target.write_bytes(b"fixture-public-zip")
            with mock.patch(__name__ + ".command", side_effect=fake_command), \
                 mock.patch(__name__ + ".write_app_zip", side_effect=fake_zip), \
                 mock.patch(__name__ + ".shutil.disk_usage", return_value=type("Disk", (), {"free": 2**40})()), \
                 mock.patch("builtins.print"):
                with self.assertRaises(PipelineError):
                    notarize(app, work, api, {}, progress)
            saved = json.loads(progress.read_text())
            self.assertEqual(saved["notarization"]["status"], "Submitted")
            self.assertEqual(saved["notarization"]["submission_id"], submission_id)
            self.assertNotIn("private_key", progress.read_text())
            self.assertNotIn("FAKEKEY123", progress.read_text())

    def test_partial_part_upload_failure_blocks_all_small_publication_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            names = [f"Orvala-Mac-arm64-{VERSION}.zip.part{index:02d}" for index in range(1, 8)]
            names += [BOOTSTRAP_NAME, EVIDENCE_NAME, "macos-arm64.json"]
            files = []
            for name in names:
                path = root / name
                path.write_bytes(name.encode())
                files.append(path)
            attempted = []
            def fake_upload(expected, *args, **kwargs):
                attempted.append(expected["name"])
                if expected["name"].endswith("part03"):
                    raise PipelineError("fixture part03 upload failed")
                return {"id": 100 + len(attempted), "name": expected["name"], "size": expected["size"],
                        "digest": "sha256:" + expected["sha256"]}
            with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": REPOSITORY}), \
                 mock.patch(__name__ + ".ensure_release", return_value={"id": 42}), \
                 mock.patch(__name__ + ".release_assets", return_value={}), \
                 mock.patch(__name__ + ".upload_release_asset", side_effect=fake_upload), mock.patch("builtins.print"):
                with self.assertRaises(PipelineError):
                    publish_files(files, "fixture-token", {}, root / "progress.json")
            self.assertEqual(len(attempted), 7)
            self.assertTrue(all(".zip.part" in name for name in attempted))
            progress = json.loads((root / "progress.json").read_text())
            self.assertFalse(progress["publication_progress"]["manifest_published"])


def run(args) -> None:
    require(sys.platform == "darwin" and platform.machine() == "arm64", "--run requires a native Apple Silicon macOS runner.")
    require(args.confirm_version == VERSION, f"--run requires --confirm-version {VERSION}.")
    require(os.environ.get("GITHUB_REPOSITORY", "").lower() == REPOSITORY.lower(), "Run only inside the own release repository.")
    # Remove credentials from the inherited environment before launching any child.
    credentials = {name: os.environ.pop(name, "") for name in SECRET_NAMES}
    gh_token, github_token = os.environ.pop("GH_TOKEN", ""), os.environ.pop("GITHUB_TOKEN", "")
    token = gh_token or github_token
    del gh_token, github_token
    require(all(credentials.values()), "All three temporary Apple signing secrets are required.")
    require(not args.publish or bool(token), "Publication requires the built-in own repository GITHUB_TOKEN.")
    work, output = args.work_dir.resolve(), args.output_dir.resolve()
    require(work.name.startswith("orvala-macos-104-") and not work.exists(), "Use a new exclusive orvala-macos-104-* workspace.")
    require(work != output and work not in output.parents and output not in work.parents,
            "Private work and public output directories must be separate.")
    require(not output.exists(), "Use a new output directory; existing release files are preserved.")
    work.mkdir(mode=0o700, parents=True)
    private_write(work / ".orvala-cloud-owned", VERSION.encode())
    output.mkdir(parents=True)
    evidence = {"version": VERSION, "bootstrap_launcher_version": BOOTSTRAP_VERSION,
                "repository": REPOSITORY, "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "native_game_executed": False, "private_game_sources_published": False, "portal_promoted": False,
                "status": "in_progress"}
    try:
        print("Downloading the approved, hash-pinned public Mac bootstrap.", flush=True)
        bootstrap_zip = work / BOOTSTRAP_NAME
        download(BOOTSTRAP_URL, bootstrap_zip, BOOTSTRAP_SIZE, BOOTSTRAP_SHA256)
        bootstrap = extract_bootstrap(bootstrap_zip, work / "bootstrap")
        trust(bootstrap, prefix="bootstrap_trust", evidence=evidence)
        evidence["bootstrap"] = {"launcher_version": BOOTSTRAP_VERSION, "source_url": BOOTSTRAP_URL,
                                  "sha256": BOOTSTRAP_SHA256, "size": BOOTSTRAP_SIZE,
                                  "approved_signed_notarized_bytes_reused": True}
        validator = bootstrap / "Contents/Resources/validate.js"
        print("Verifying and streaming the seven public frozen game parts.", flush=True)
        app = unpack_game(work, validator, evidence)
        keychain, identity = import_identity(work, credentials)
        print("Signing frozen native code with Developer ID in a temporary keychain.", flush=True)
        sign_game(app, work, keychain, identity, evidence)
        notarize(app, work, credentials[SECRET_NAMES[2]], evidence, output / "run-result.json")
        credentials.clear()
        verify_file(app / "Contents/Resources/Orvala.pck", PCK_SIZE, PCK_SHA256)
        print("Packing the accepted, stapled app directly into release parts.", flush=True)
        final_required = (sum(path.stat().st_size for path in app.rglob("*") if path.is_file())
                          + ZIP_METADATA_BUDGET + RESERVE)
        require(shutil.disk_usage(work).free > final_required,
                "Runner has insufficient space for final release parts; no manifest was announced.")
        with MultipartWriter(output, f"Orvala-Mac-arm64-{VERSION}.zip") as target:
            write_app_zip(app, target)
        require(len(target.parts) <= 32, "Final release has too many parts.")
        manifest = {"version": VERSION, "platform": "macos-arm64", "application": "Orvala.app",
                    "minimum_macos": MINIMUM_MACOS, "status": "stable", "notarized": True,
                    "size": target.position, "sha256": target.digest.hexdigest(),
                    "parts": [{"url": f"{RELEASE_ROOT}/v{VERSION}/{item['name']}", "size": item["size"],
                               "sha256": item["sha256"]} for item in target.parts]}
        manifest_path = output / "macos-arm64.json"
        write_json(manifest_path, manifest)
        verified_app = verify_final_roundtrip(app, output, work, validator, manifest, target.parts, evidence)
        print("Final release parts reextracted, permissions restored, Apple trust verified.", flush=True)
        remove_signing_material(work, evidence)
        require(not credentials, "Credential memory must be cleared before executing the game.")
        print("Signing material removed. Starting credential-free native .NET library smoke.", flush=True)
        native_library_smoke(verified_app, work, evidence)
        print("Native .NET library, starter deck selector and return smoke PASS.", flush=True)
        evidence["final_package"] = {"sha256": manifest["sha256"], "size": manifest["size"],
                                     "parts": target.parts, "final_reextraction_and_trust": True,
                                     "notarized_flag_requires_accepted_and_trust": True,
                                     "native_library_smoke_required_before_publication": True}
        bootstrap_asset = output / BOOTSTRAP_NAME
        shutil.copyfile(bootstrap_zip, bootstrap_asset)
        evidence["status"] = "accepted_signed_stapled_and_validated"
        evidence_path = output / EVIDENCE_NAME
        write_json(evidence_path, evidence)
        if args.publish:
            files = [output / part["name"] for part in target.parts]
            # Evidence is already safe to publish; publication details stay local
            # after upload, avoiding a changing same-name asset on retries.
            publish_files([*files, bootstrap_asset, evidence_path, manifest_path], token, evidence, output / "run-result.json")
            evidence["status"] = "published_prerelease_without_portal_promotion"
        else:
            evidence["publication"] = {"performed": False}
        write_json(output / "run-result.json", evidence)
        print("PASS: signed, Accepted, stapled, final package reextracted/trusted, native .NET library smoke passed. Visual gameplay was not tested.", flush=True)
    except Exception as error:
        evidence["status"] = "failed_no_portal_promotion"
        evidence["failure"] = str(error) if isinstance(error, PipelineError) else "Unexpected pipeline failure (details withheld)."
        write_json(output / "run-result.json", evidence)
        raise
    finally:
        credentials.clear()
        cleanup(work)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="Print the pinned offline plan (default); no external actions.")
    mode.add_argument("--self-test", action="store_true", help="Run small offline fixtures; no network or credentials.")
    mode.add_argument("--run", action="store_true", help="Explicitly download, sign and submit to Apple on native macOS.")
    mode.add_argument("--cleanup", action="store_true", help="Remove only a marked private workspace and its temporary keychain.")
    parser.add_argument("--publish", action="store_true", help=f"With --run, publish own v{VERSION} pre-release using GITHUB_TOKEN.")
    parser.add_argument("--confirm-version", default="", help="Required explicit target version for --run.")
    parser.add_argument("--work-dir", type=Path, default=Path(tempfile.gettempdir()) / "orvala-macos-104-local")
    parser.add_argument("--output-dir", type=Path, default=Path.cwd() / "orvala-macos-104-output")
    args = parser.parse_args(argv)
    try:
        require(not args.publish or args.run, "--publish requires --run.")
        if args.self_test:
            result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(OfflineTests))
            return 0 if result.wasSuccessful() else 1
        if args.cleanup:
            cleanup(args.work_dir.resolve())
        elif args.run:
            run(args)
        else:
            print(json.dumps(plan(), indent=2, ensure_ascii=False))
        return 0
    except PipelineError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    except Exception:
        # Do not dump a traceback: secrets can occur in third-party CLI exceptions.
        print("ERROR: Unexpected pipeline failure; inspect the credential-free run-result.json. No portal was promoted.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
