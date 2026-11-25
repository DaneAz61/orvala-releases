#!/usr/bin/env python3
"""Credential-free client QA of the own, already-published Mac 1.0.5 package.

This contains distribution/test orchestration only, never game source or assets.
The default plan and --self-test are offline. --run downloads only the own public
hash-pinned release; it never signs, notarizes, logs in or changes the portal.
--publish-evidence is a separate process with the own built-in GitHub token and
can only add unique QA assets to the existing v1.0.5 pre-release after PASS.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import platform
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zlib
from pathlib import Path
from unittest import mock

import cloud_release as cloud


VERSION = "1.0.5"
REPOSITORY = "DaneAz61/orvala-releases"
MANIFEST_URL = f"https://github.com/{REPOSITORY}/releases/download/v{VERSION}/macos-arm64.json"
BOOTSTRAP_VERSION = "1.0.4"
BOOTSTRAP_NAME = f"Instalar-Orvala-Mac-{BOOTSTRAP_VERSION}.zip"
BOOTSTRAP_URL = f"https://github.com/{REPOSITORY}/releases/download/v{BOOTSTRAP_VERSION}/{BOOTSTRAP_NAME}"
BOOTSTRAP_SIZE = 1_364_034
BOOTSTRAP_SHA256 = "01e958b0a74e5d19c5ccef0e4f5e204d2dfe985b8d7101ddada487daa418d038"
PCK_SIZE = 4_192_008_472
PCK_SHA256 = "69a41ae720bc2d989d48c5f2b15c4950f83c513dec0bf3f5b84988285e5bb3e5"
MENU_MARKER = "ORVALA MENUS SMOKE OK: início, acesso ao mundo, coleção, seletor, retratos e miniatura original animada."
MARKER_FILE = ".orvala-native-client-owned"
MAX_MANIFEST = 64 * 1024
MAX_LOG = 8 * 1024 * 1024
MAX_SAFE_LOG = 2 * 1024 * 1024
MAX_IMAGE = 24 * 1024 * 1024
MENU_IMAGES = ("inicio", "mundo", "personagens", "miniatura", "biblioteca", "duelo")
VALIDATED_STATUSES = ("passed", "menus_passed_startup_capture_unavailable")
RUNTIME_ENVIRONMENT = (
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "__CF_USER_TEXT_ENCODING",
)
GUI_UNAVAILABLE = re.compile(
    r"(?:failed|unable|cannot|could not).{0,100}(?:OpenGL|rendering device|display server|WindowServer|graphics context)|"
    r"(?:OpenGL|display server|WindowServer).{0,100}(?:unavailable|not available|failed|not supported)",
    re.IGNORECASE,
)


def require(condition: bool, message: str) -> None:
    cloud.require(condition, message)


def valid_sha256(value: str) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value) is not None,
            "Supply the independently approved manifest SHA-256.")
    return value.lower()


def validate_imported_constants() -> None:
    require(cloud.VERSION == VERSION and cloud.BASE_VERSION == "1.0.3" and cloud.REPOSITORY == REPOSITORY
            and cloud.BOOTSTRAP_VERSION == BOOTSTRAP_VERSION
            and cloud.BOOTSTRAP_NAME == BOOTSTRAP_NAME and cloud.BOOTSTRAP_URL == BOOTSTRAP_URL
            and cloud.BOOTSTRAP_SIZE == BOOTSTRAP_SIZE and cloud.BOOTSTRAP_SHA256 == BOOTSTRAP_SHA256
            and cloud.PCK_SIZE == PCK_SIZE and cloud.PCK_SHA256 == PCK_SHA256,
            "Imported helpers must match game 1.0.5, frozen 1.0.3 payload and the exact approved 1.0.4 bootstrap origin.")


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Manifest has duplicate JSON keys.")
        result[key] = value
    return result


def parse_manifest(data: bytes, expected_hash: str) -> dict:
    require(0 < len(data) <= MAX_MANIFEST, "Published manifest exceeds its small size limit.")
    require(hashlib.sha256(data).hexdigest() == valid_sha256(expected_hash), "Published manifest SHA-256 differs.")
    try:
        manifest = json.loads(data.decode("utf-8-sig"), object_pairs_hook=no_duplicate_keys,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")))
    except (ValueError, UnicodeError):
        raise cloud.PipelineError("Published manifest is not valid, bounded JSON.") from None
    require(isinstance(manifest, dict) and manifest.get("version") == VERSION
            and manifest.get("platform") == "macos-arm64" and manifest.get("application") == "Orvala.app"
            and manifest.get("minimum_macos") == "13.0" and manifest.get("notarized") is True
            and manifest.get("status") == "stable", "Published manifest is not the approved notarized Mac 1.0.5 release.")
    require(type(manifest.get("size")) is int and cloud.PCK_SIZE < manifest["size"] <= 8 * 1024**3,
            "Unexpected final game package size.")
    valid_sha256(manifest.get("sha256"))
    parts = manifest.get("parts")
    require(isinstance(parts, list) and 1 <= len(parts) <= 32, "Unexpected final release part count.")
    total = 0
    for index, part in enumerate(parts, 1):
        require(isinstance(part, dict), "Malformed final release part.")
        name = f"Orvala-Mac-arm64-{VERSION}.zip.part{index:02d}"
        require(part.get("url") == f"{cloud.RELEASE_ROOT}/v{VERSION}/{name}", "A final release part points outside the own exact version.")
        require(type(part.get("size")) is int and 0 < part["size"] <= cloud.PART_LIMIT,
                "Unexpected final part size.")
        valid_sha256(part.get("sha256"))
        total += part["size"]
    require(total == manifest["size"], "Final part sizes do not match the manifest.")
    return manifest


def child_environment(temporary: Path, source: dict | None = None) -> dict:
    original = os.environ if source is None else source
    result = {name: original[name] for name in RUNTIME_ENVIRONMENT if name in original}
    # HOME is inherited unchanged. This process is restricted to a disposable
    # hosted runner; no personal profile, Apple material or Actions token enters.
    result.update(TMPDIR=str(temporary), CI="true")
    return result


def safe_text(value: str, work: Path | None = None) -> str:
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)
    value = re.sub(r"-----BEGIN [^-\n]+-----.*?-----END [^-\n]+-----", "[REDACTED KEY BLOCK]", value, flags=re.DOTALL)
    value = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})\b", "[REDACTED TOKEN]", value)
    value = re.sub(r"(?i)(authorization\s*:\s*(?:bearer|token)\s+)[^\s]+", r"\1[REDACTED]", value)
    value = "".join(character for character in value if character in "\n\t" or ord(character) >= 32)
    if work is not None:
        value = value.replace(str(work), "$QA_WORK")
    return value


def bounded_log(path: Path) -> bytes:
    if not path.exists():
        return b""
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_LOG,
            "Client log exceeded its regular-file size limit.")
    return path.read_bytes()


def png_dimensions(path: Path) -> tuple[int, int]:
    require(path.is_file() and not path.is_symlink() and 32 <= path.stat().st_size <= MAX_IMAGE,
            "QA image is not a bounded regular PNG.")
    data = path.read_bytes()
    require(data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR", "QA image is not a PNG.")
    width, height = struct.unpack(">II", data[16:24])
    require(64 <= width <= 8192 and 64 <= height <= 8192, "Unexpected QA image dimensions.")
    offset, chunks, has_pixels, complete = 8, 0, False, False
    while offset + 12 <= len(data):
        length = struct.unpack_from(">I", data, offset)[0]
        kind = data[offset + 4:offset + 8]
        end = offset + 12 + length
        require(end <= len(data) and chunks < 4096, "Truncated or excessive PNG chunks.")
        expected_crc = struct.unpack_from(">I", data, end - 4)[0]
        require(zlib.crc32(data[offset + 4:end - 4]) & 0xffffffff == expected_crc, "QA PNG chunk integrity failed.")
        require(chunks != 0 or (kind == b"IHDR" and length == 13), "Malformed PNG image header.")
        has_pixels |= kind == b"IDAT" and length > 0
        offset, chunks = end, chunks + 1
        if kind == b"IEND":
            require(length == 0 and offset == len(data), "PNG contains data after its terminal chunk.")
            complete = True
            break
    require(complete and has_pixels, "QA PNG has no complete pixel stream.")
    return width, height


def capture_game_window(process: subprocess.Popen, destination: Path, env: dict, stop: threading.Event) -> dict:
    result = {"attempted": False, "captured": False, "scope": "disposable CI desktop during normal home startup",
              "delay_after_process_seconds": 3.0, "privacy_settings_changed": False,
              "capture_requires_human_visual_review": True}
    try:
        if stop.wait(3.0) or process.poll() is not None:
            result["unavailable_reason"] = "The game exited before the three-second desktop capture; no game image is claimed."
            return result
        server = cloud.command(["/usr/bin/pgrep", "-x", "WindowServer"], "Disposable CI WindowServer presence",
                               timeout=5, env=env, check=False)
        result["windowserver_detected"] = server.returncode == 0
        if server.returncode != 0 or process.poll() is not None:
            result["unavailable_reason"] = "The disposable runner did not expose a WindowServer while the game was alive."
            return result
        result.update(attempted=True, process_alive_at_capture=True)
        shot = cloud.command(["/usr/sbin/screencapture", "-x", str(destination)],
                             "Disposable CI desktop screenshot", timeout=15, env=env, check=False)
        if shot.returncode == 0 and destination.is_file():
            result.update(captured=True, pixels=list(png_dimensions(destination)))
        else:
            result["unavailable_reason"] = "The runner did not permit desktop capture; no permission was requested or changed."
    except (OSError, cloud.PipelineError):
        result["unavailable_reason"] = "The runner's native window/capture service was unavailable."
    return result


def run_client(app: Path, work: Path, public: Path, name: str, arguments: list[str],
               marker: str | None, *, capture: bool = False) -> dict:
    temporary = work / "runtime-tmp"
    temporary.mkdir(exist_ok=True)
    env = child_environment(temporary)
    require(not any("TOKEN" in key or key.startswith("APPLE_") for key in env), "Credential-free client environment invariant failed.")
    raw = work / f"{name}-stdio.raw"
    engine_log = work / f"{name}-engine.raw"
    started = time.monotonic()
    executable = app / "Contents/MacOS/Orvala"
    argv = [str(executable), *arguments, "--log-file", str(engine_log)]
    # Engine options precede the '--' separator, including the injected log path.
    if "--" in arguments:
        index = arguments.index("--")
        argv = [str(executable), *arguments[:index], "--log-file", str(engine_log), *arguments[index:]]
    timed_out = False
    capture_result = {"attempted": False, "captured": False}
    with raw.open("xb") as output:
        process = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT, env=env, cwd=work)
        stop = threading.Event()
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1) if capture else None
        future = pool.submit(capture_game_window, process, public / "startup-window.png", env, stop) if pool else None
        try:
            try:
                exit_code = process.wait(timeout=90)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                process.wait(timeout=10)
                exit_code = process.returncode
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            stop.set()
            if future is not None:
                capture_result = future.result(timeout=20)
            if pool:
                pool.shutdown(wait=True)
    log_bytes = bounded_log(raw) + b"\n" + bounded_log(engine_log)
    text = log_bytes.decode("utf-8", "replace")
    failed = cloud.BOOT_FAILURE_PATTERN.search(text) is not None
    passed = not timed_out and exit_code == 0 and not failed and (marker is None or marker in text)
    sanitized = safe_text(text, work).encode("utf-8")[-MAX_SAFE_LOG:]
    (public / f"{name}.log").write_bytes(sanitized)
    result = {"passed": passed, "exit_code": exit_code, "timed_out": timed_out,
              "elapsed_seconds": round(time.monotonic() - started, 3), "timeout_seconds": 90,
              "exact_marker_seen": marker in text if marker else None, "engine_or_runtime_error_seen": failed,
              "credential_free_child_environment": True, "combined_log_sha256": hashlib.sha256(log_bytes).hexdigest(),
              "log": f"{name}.log", "gui_service_unavailable": bool(GUI_UNAVAILABLE.search(text)),
              "desktop_capture": capture_result}
    return result


def unpack_published(manifest: dict, work: Path, validator: Path, evidence: dict) -> Path:
    stage = work / "download"
    stage.mkdir()
    cloud.write_json(stage / "manifest.json", manifest)
    cloud.jxa(validator, "manifest", stage / "manifest.json", "")
    needed = int(cloud.jxa(validator, "download", stage, ",".join("0" for _ in manifest["parts"])))
    require(shutil.disk_usage(work).free > needed, "Runner has insufficient space for the final published package.")
    parts = [stage / f"part-{index}" for index in range(1, len(manifest["parts"]) + 1)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(cloud.download, item["url"], path, item["size"], item["sha256"])
                   for path, item in zip(parts, manifest["parts"])]
        for future in futures:
            future.result()
    digest = hashlib.sha256()
    for part in parts:
        with part.open("rb") as stream:
            for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                digest.update(block)
    require(digest.hexdigest() == manifest["sha256"], "Final published virtual ZIP SHA-256 differs.")
    table_text = cloud.jxa(validator, "parts", stage)
    expanded, files, required = map(int, table_text.splitlines()[0].split("\t"))
    require(shutil.disk_usage(work).free > required, "Runner has insufficient streaming extraction space.")
    table = stage / "archive.tsv"
    table.write_text(table_text + "\n", encoding="utf-8")
    extracted = work / "extracted"
    extracted.mkdir()
    cloud.stream_extract(parts, extracted)
    cloud.jxa(validator, "permissions", table, extracted)
    cloud.jxa(validator, "extracted", table, extracted)
    app = extracted / "Orvala.app"
    cloud.verify_file(app / "Contents/Resources/Orvala.pck", cloud.PCK_SIZE, PCK_SHA256)
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    require(info.get("CFBundleIdentifier") == "br.com.playable.orvala" and info.get("CFBundleExecutable") == "Orvala"
            and info.get("CFBundleShortVersionString") == VERSION and info.get("CFBundleVersion") == VERSION
            and info.get("LSMinimumSystemVersion") == "13.0",
            "Final game metadata differs from the approved Mac 1.0.5 package.")
    cloud.trust(app, prefix="published_game_trust", evidence=evidence)
    description = cloud.command(["/usr/bin/codesign", "--display", "--verbose=4", str(app)],
                                "Published game signing identity").stderr.decode("utf-8", "replace")
    evidence["published_game_authorities"] = cloud.verify_signed_chain(description)
    evidence["final_package"] = {"parts": len(parts), "sha256": manifest["sha256"], "bytes": manifest["size"],
                                 "expanded_bytes": expanded, "files": files, "pck_sha256": PCK_SHA256,
                                 "shipping_jxa_and_native_tar": True, "permissions_restored_and_verified": True,
                                 "duplicate_complete_zip_created": False, "consumed_parts_removed": not any(path.exists() for path in parts)}
    return app


def read_owned_work(work: Path, manifest_sha: str, run_id: str, attempt: str) -> dict:
    require(work.is_dir() and not work.is_symlink() and work.name.startswith("orvala-mac-native-client-"),
            "Use only the marked client-QA workspace.")
    marker = work / MARKER_FILE
    require(marker.is_file() and not marker.is_symlink(), "Client-QA ownership marker is missing.")
    value = json.loads(marker.read_text(encoding="utf-8"))
    require(value == {"version": VERSION, "manifest_sha256": manifest_sha, "run_id": run_id, "attempt": attempt},
            "Client-QA workspace does not belong to this exact run and manifest.")
    return value


def artifact_paths(work: Path, evidence: dict) -> list[Path]:
    public = work / "public"
    require(public.is_dir() and not public.is_symlink(), "QA public evidence directory is missing.")
    names = {"evidence.json", "headless.log", "menus.log", "startup.log", "startup-window.png",
             *(f"menu-{name}.png" for name in MENU_IMAGES)}
    paths = [public / name for name in sorted(names) if (public / name).exists()]
    required = {"evidence.json", "headless.log", "menus.log", "startup.log",
                *(f"menu-{name}.png" for name in MENU_IMAGES)}
    if evidence.get("startup_window_verified") is True:
        required.add("startup-window.png")
    require(required.issubset({path.name for path in paths}), "Completed QA logs or six native frame captures are missing.")
    if evidence.get("startup_window_verified") is not True:
        paths = [path for path in paths if path.name != "startup-window.png"]
    for path in paths:
        require(path.is_file() and not path.is_symlink() and path.resolve().parent == public.resolve(), "QA asset escaped its exact evidence folder.")
        if path.suffix == ".png":
            png_dimensions(path)
        else:
            limit = 512 * 1024 if path.suffix == ".json" else MAX_SAFE_LOG
            require(path.stat().st_size <= limit, "QA text asset exceeds its public size limit.")
            text = path.read_text(encoding="utf-8")
            require(text == safe_text(text), "QA text asset contains unsanitized control or credential content.")
    require(evidence.get("status") in VALIDATED_STATUSES and evidence.get("headless", {}).get("passed") is True
            and evidence.get("menus", {}).get("passed") is True and evidence.get("startup", {}).get("passed") is True
            and evidence.get("menu_images_verified") == len(MENU_IMAGES)
            and evidence.get("native_menu_rendered") is True
            and evidence.get("credential_free_game_environment") is True,
            "QA assets can only be uploaded after all required native client checks pass.")
    require((evidence.get("status") == "passed") == (evidence.get("startup_window_verified") is True),
            "QA status must explicitly distinguish an unavailable normal desktop capture.")
    return paths


def upload_qa(work: Path, manifest_sha: str, run_id: str, attempt: str) -> None:
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "QA asset upload is restricted to the own release repository.")
    require(not any(os.environ.get(name) for name in cloud.SECRET_NAMES), "Apple credentials must never enter client QA.")
    read_owned_work(work, manifest_sha, run_id, attempt)
    evidence = json.loads((work / "public/evidence.json").read_text(encoding="utf-8"))
    require(evidence.get("manifest_sha256") == manifest_sha and evidence.get("run_id") == run_id
            and evidence.get("attempt") == attempt, "QA evidence belongs to another run or manifest.")
    files = artifact_paths(work, evidence)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    require(bool(token), "Use only the own built-in GitHub token in the separate evidence upload step.")
    release = cloud.gh_json(["api", f"repos/{REPOSITORY}/releases/tags/v{VERSION}"], token)
    require(isinstance(release, dict) and release.get("tag_name") == f"v{VERSION}"
            and release.get("prerelease") is True and release.get("draft") is False,
            "QA evidence requires the existing public v1.0.5 pre-release; no release will be created or changed.")
    endpoint = f"repos/{REPOSITORY}/releases/{release['id']}/assets"
    pages = cloud.gh_json(["api", "--paginate", "--slurp", endpoint], token)
    require(isinstance(pages, list) and all(isinstance(page, list) for page in pages), "Unexpected own release asset inventory.")
    existing = {item["name"] for page in pages for item in page}
    prefix = f"Orvala-Mac-{VERSION}-native-QA-{run_id}-{attempt}-"
    names = {path: prefix + path.name for path in files}
    require(not (existing & set(names.values())), "A QA asset name already exists; no overwrite is permitted.")
    upload = work / "qa-upload"
    require(not upload.exists(), "QA upload preparation already exists; preserve existing evidence.")
    upload.mkdir()
    for source, name in names.items():
        shutil.copyfile(source, upload / name)
    env = dict(os.environ, GH_TOKEN=token, GH_PROMPT_DISABLED="1")
    cloud.command(["gh", "release", "upload", f"v{VERSION}", "--repo", REPOSITORY,
                   *(str(upload / name) for name in names.values())], "Upload unique own QA assets", env=env, timeout=180)
    pages = cloud.gh_json(["api", "--paginate", "--slurp", endpoint], token)
    actual = {item["name"]: item for page in pages for item in page}
    for source, name in names.items():
        require(name in actual and actual[name].get("size") == source.stat().st_size
                and actual[name].get("digest") == "sha256:" + cloud.sha256_file(source), "Uploaded QA asset integrity was not confirmed.")
    print(f"PASS: {len(files)} unique QA assets verified on the existing own v1.0.5 pre-release; no game asset or release state was changed.")


def plan(manifest_sha: str) -> dict:
    return {"version": VERSION, "manifest_url": MANIFEST_URL, "manifest_sha256": manifest_sha,
            "bootstrap": {"version": BOOTSTRAP_VERSION, "name": BOOTSTRAP_NAME, "url": BOOTSTRAP_URL,
                          "size": BOOTSTRAP_SIZE, "sha256": BOOTSTRAP_SHA256},
            "bootstrap_sha256": BOOTSTRAP_SHA256, "frozen_pck_sha256": PCK_SHA256,
            "run_contacts": ["own public release downloads", "Apple public trust/ticket checks"],
            "game_network_login": False, "apple_credentials_required": False, "private_sources_required": False,
            "game_modes": ["headless library entry", "graphical menu smoke with audio Dummy", "short normal home screen"],
            "limits": {"engine_timeout_seconds": 90, "window_capture_delay_seconds": 3},
            "publication": "Separate explicit --publish-evidence; unique run IDs; existing own pre-release QA assets only",
            "not_tested": ["real audio output", "multiplayer", "full duel", "M5 hardware", "user Mac profile"]}


def run(args, manifest_sha: str, run_id: str, attempt: str) -> int:
    require(platform.system() == "Darwin" and platform.machine() == "arm64", "Native client QA requires an ARM64 Mac.")
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("ORVALA_HOSTED_QA") == "github-hosted",
            "Native client QA is restricted to the own public repository's disposable hosted runner.")
    require(not any(os.environ.get(name) for name in (*cloud.SECRET_NAMES, "GH_TOKEN", "GITHUB_TOKEN")),
            "Client QA must start without Apple credentials or a release token.")
    validate_imported_constants()
    work = args.work_dir.resolve()
    require(work.name.startswith("orvala-mac-native-client-") and not work.exists(), "Use a new exclusive client-QA workspace.")
    work.mkdir(parents=True, mode=0o700)
    cloud.private_write(work / MARKER_FILE, json.dumps({"version": VERSION, "manifest_sha256": manifest_sha,
                                                     "run_id": run_id, "attempt": attempt}).encode())
    public = work / "public"
    public.mkdir()
    evidence = {**plan(manifest_sha), "run_id": run_id, "attempt": attempt,
                "platform": {"system": platform.system(), "macos": platform.mac_ver()[0], "architecture": platform.machine(),
                             "runner_image": os.environ.get("ORVALA_QA_RUNNER_IMAGE", "unknown")},
                "status": "in_progress", "credential_free_game_environment": True,
                "visual_menu_verified": False, "native_menu_rendered": False, "startup_window_verified": False,
                "real_audio_verified": False, "full_gameplay_verified": False,
                "login_verified": False, "multiplayer_verified": False, "m5_hardware_verified": False,
                "personal_user_profile_used": False, "private_game_sources_published": False}
    try:
        manifest_file = work / "published-manifest.json"
        cloud.command(["/usr/bin/curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https",
                       "--tlsv1.2", "--max-filesize", str(MAX_MANIFEST), "--max-time", "30", "--output", str(manifest_file),
                       MANIFEST_URL], "Own published Mac manifest", timeout=40)
        manifest = parse_manifest(manifest_file.read_bytes(), manifest_sha)
        bootstrap_zip = work / cloud.BOOTSTRAP_NAME
        cloud.download(cloud.BOOTSTRAP_URL, bootstrap_zip, cloud.BOOTSTRAP_SIZE, BOOTSTRAP_SHA256)
        bootstrap = cloud.extract_bootstrap(bootstrap_zip, work / "bootstrap")
        cloud.trust(bootstrap, prefix="bootstrap_trust", evidence=evidence)
        app = unpack_published(manifest, work, bootstrap / "Contents/Resources/validate.js", evidence)
        temporary = work / "runtime-tmp"
        temporary.mkdir()
        env = child_environment(temporary)
        version = cloud.command([str(app / "Contents/MacOS/Orvala"), "--version"], "Published Godot mono version",
                                timeout=20, env=env, check=False)
        version_text = version.stdout.decode("utf-8", "replace").strip()
        require(version.returncode == 0 and re.fullmatch(r"4\.7\.2\.stable\.mono(?:\.[A-Za-z0-9_]+)*", version_text) is not None,
                "The published app does not report Godot 4.7.2 stable mono.")
        evidence["engine_version"] = version_text
        evidence["headless"] = run_client(app, work, public, "headless",
            ["--headless", "--max-fps", "60", "--quit-after", "600", "--", "--library-entry-smoke"], cloud.BOOT_MARKER)
        require(evidence["headless"]["passed"], "Published native .NET library entry smoke failed.")
        images = work / "menu-images"
        images.mkdir()
        evidence["menus"] = run_client(app, work, public, "menus",
            ["--resolution", "1280x800", "--audio-driver", "Dummy", "--max-fps", "60", "--quit-after", "600", "--",
             "--orvala-menu-smoke", f"--orvala-menu-shots={images}"], MENU_MARKER)
        verified_images = 0
        evidence["menu_frames"] = []
        for name in MENU_IMAGES:
            image = images / f"{name}.png"
            if image.exists():
                dimensions = png_dimensions(image)
                shutil.copyfile(image, public / f"menu-{name}.png")
                evidence["menu_frames"].append({"file": f"menu-{name}.png", "pixels": list(dimensions),
                                                "sha256": cloud.sha256_file(image), "bytes": image.stat().st_size})
                verified_images += 1
        evidence["menu_images_verified"] = verified_images
        if not evidence["menus"]["passed"]:
            evidence["status"] = "gui_unavailable" if evidence["menus"]["gui_service_unavailable"] else "failed_graphical_menu"
            return 2
        require(verified_images == len(MENU_IMAGES), "Graphical menu smoke did not produce all six real frame captures.")
        # The smoke quits as soon as it passes. Run the unchanged normal home
        # screen separately to capture its own live window after three seconds.
        # This is the disposable CI account, not a player's Mac or save folder.
        evidence["startup"] = run_client(app, work, public, "startup",
            ["--resolution", "1280x800", "--audio-driver", "Dummy", "--max-fps", "60", "--quit-after", "600"],
            None, capture=True)
        require(evidence["startup"]["passed"], "Published normal graphical home startup failed.")
        evidence["visual_menu_verified"] = True
        evidence["native_menu_rendered"] = True
        evidence["startup_window_verified"] = evidence["startup"]["desktop_capture"].get("captured") is True
        evidence["status"] = "passed" if evidence["startup_window_verified"] else "menus_passed_startup_capture_unavailable"
        return 0
    except (cloud.PipelineError, OSError, ValueError) as error:
        evidence["status"] = "failed"
        evidence["failure"] = safe_text(str(error), work) if isinstance(error, cloud.PipelineError) else "A controlled local QA operation failed."
        raise cloud.PipelineError(evidence["failure"]) from None
    finally:
        # Raw engine logs stay in the disposable private workspace. Only this
        # bounded, sanitized evidence directory is eligible for publication.
        sanitized = json.loads(safe_text(json.dumps(evidence, ensure_ascii=False), work))
        cloud.write_json(public / "evidence.json", sanitized)


class OfflineTests(unittest.TestCase):
    def manifest(self):
        value = cloud.base_manifest()
        value.update(version=VERSION, minimum_macos="13.0", status="stable", notarized=True)
        for index, item in enumerate(value["parts"], 1):
            item["url"] = f"{cloud.RELEASE_ROOT}/v{VERSION}/Orvala-Mac-arm64-{VERSION}.zip.part{index:02d}"
        return value

    def encode(self, value):
        data = json.dumps(value).encode()
        return data, hashlib.sha256(data).hexdigest()

    def test_manifest_is_pinned_to_own_exact_final_version(self):
        data, digest = self.encode(self.manifest())
        self.assertEqual(parse_manifest(data, digest)["version"], VERSION)
        with self.assertRaises(cloud.PipelineError):
            parse_manifest(data, "0" * 64)
        value = self.manifest()
        value["parts"][0]["url"] = value["parts"][0]["url"].replace(REPOSITORY, "other/repo")
        with self.assertRaises(cloud.PipelineError):
            parse_manifest(*self.encode(value))

    def test_manifest_rejects_beta_wrong_minimum_and_boolean_size(self):
        for changes in ({"notarized": False}, {"version": "1.0.3"}, {"version": "1.0.4"},
                        {"minimum_macos": "12.0"}, {"size": True}):
            value = self.manifest()
            value.update(changes)
            with self.subTest(changes=changes), self.assertRaises(cloud.PipelineError):
                parse_manifest(*self.encode(value))

    def test_previous_game_parts_cannot_mix_with_final_manifest(self):
        value = self.manifest()
        value["parts"][0]["url"] = f"{cloud.RELEASE_ROOT}/v1.0.4/Orvala-Mac-arm64-1.0.4.zip.part01"
        with self.assertRaises(cloud.PipelineError):
            parse_manifest(*self.encode(value))

    def test_imported_constants_pin_old_bootstrap_and_new_game_separately(self):
        approved = dict(VERSION=VERSION, BASE_VERSION="1.0.3", REPOSITORY=REPOSITORY,
                        BOOTSTRAP_VERSION=BOOTSTRAP_VERSION, BOOTSTRAP_NAME=BOOTSTRAP_NAME, BOOTSTRAP_URL=BOOTSTRAP_URL,
                        BOOTSTRAP_SIZE=BOOTSTRAP_SIZE, BOOTSTRAP_SHA256=BOOTSTRAP_SHA256,
                        PCK_SIZE=PCK_SIZE, PCK_SHA256=PCK_SHA256)
        with mock.patch.multiple(cloud, **approved):
            validate_imported_constants()
            for name, wrong in (("VERSION", "1.0.4"), ("BASE_VERSION", "1.0.4"),
                                ("BOOTSTRAP_URL", BOOTSTRAP_URL.replace("/v1.0.4/", "/v1.0.5/")),
                                ("BOOTSTRAP_VERSION", "1.0.5"), ("BOOTSTRAP_NAME", "Instalar-Orvala-Mac-1.0.5.zip"),
                                ("BOOTSTRAP_SIZE", BOOTSTRAP_SIZE + 1), ("PCK_SHA256", "0" * 64)):
                with self.subTest(name=name), mock.patch.object(cloud, name, wrong), self.assertRaises(cloud.PipelineError):
                    validate_imported_constants()
        self.assertEqual(plan("a" * 64)["bootstrap"]["version"], "1.0.4")

    def test_duplicate_json_keys_are_rejected(self):
        data = b'{"version":"1.0.5","version":"1.0.4"}'
        with self.assertRaises(cloud.PipelineError):
            parse_manifest(data, hashlib.sha256(data).hexdigest())

    def test_game_environment_excludes_all_credential_names(self):
        source = {"HOME": "/Users/runner", "PATH": "/usr/bin", "USER": "runner", "GH_TOKEN": "forbidden",
                  "GITHUB_TOKEN": "forbidden", "ACTIONS_RUNTIME_TOKEN": "forbidden", "APPLE_NOTARY_API_JSON": "forbidden",
                  "APPLE_SIGNING_P12_PASSWORD": "forbidden", "SOME_UNRELATED_SECRET": "forbidden"}
        actual = child_environment(Path("/tmp/qa"), source)
        self.assertEqual(actual["HOME"], source["HOME"])
        self.assertEqual(set(actual), {"HOME", "PATH", "USER", "TMPDIR", "CI"})

    def test_logs_redact_tokens_and_private_key_blocks(self):
        raw = "ok\nAuthorization: Bearer hidden\nghp_" + "a" * 36 + "\n-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"
        result = safe_text(raw)
        self.assertNotIn("hidden", result)
        self.assertNotIn("secret", result)
        self.assertNotIn("ghp_", result)
        self.assertNotIn("BEGIN PRIVATE", result)

    def test_safe_json_and_logs_preserve_trailing_newline_and_are_idempotent(self):
        for text in ('{"status": "passed"}\n', "normal game output\n", "line one\nline two\n"):
            self.assertEqual(safe_text(text), text)
            self.assertEqual(safe_text(safe_text(text)), text)

    def evidence_fixture(self, work):
        public = work / "public"
        public.mkdir()
        evidence = {"status": "menus_passed_startup_capture_unavailable", "headless": {"passed": True},
                    "menus": {"passed": True}, "startup": {"passed": True}, "menu_images_verified": 6,
                    "native_menu_rendered": True, "startup_window_verified": False,
                    "credential_free_game_environment": True}
        cloud.write_json(public / "evidence.json", evidence)
        for name in ("headless", "menus", "startup"):
            (public / f"{name}.log").write_text("validated test log\n", encoding="utf-8")
        def chunk(kind, data):
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
        image = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 64, 64, 8, 2, 0, 0, 0))
                 + chunk(b"IDAT", zlib.compress((b"\0" + b"\x80\x40\x20" * 64) * 64)) + chunk(b"IEND", b""))
        for name in MENU_IMAGES:
            (public / f"menu-{name}.png").write_bytes(image)
        return evidence

    def test_six_frames_required_and_only_whitelisted_assets_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            evidence = self.evidence_fixture(work)
            (work / "public/private-key.p8").write_text("must never be selected", encoding="utf-8")
            paths = artifact_paths(work, evidence)
            self.assertEqual(len(paths), 10)
            self.assertNotIn("private-key.p8", [path.name for path in paths])
            (work / "public/menu-inicio.png").unlink()
            with self.assertRaises(cloud.PipelineError):
                artifact_paths(work, evidence)

    def test_unavailable_desktop_is_explicit_and_full_pass_requires_seventh_image(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            evidence = self.evidence_fixture(work)
            self.assertNotIn("startup-window.png", [path.name for path in artifact_paths(work, evidence)])
            evidence["status"] = "passed"
            with self.assertRaises(cloud.PipelineError):
                artifact_paths(work, evidence)
            evidence["startup_window_verified"] = True
            with self.assertRaises(cloud.PipelineError):
                artifact_paths(work, evidence)

    def test_no_markers_or_no_native_frames_cannot_be_published(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            evidence = self.evidence_fixture(work)
            evidence["menus"]["passed"] = False
            with self.assertRaises(cloud.PipelineError):
                artifact_paths(work, evidence)

    def test_native_client_uses_only_allowlisted_environment_and_engine_flags_precede_separator(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            public = work / "public"
            public.mkdir()
            captured = {}

            class FakeProcess:
                returncode = 0
                pid = 12345

                def wait(self, timeout=None):
                    return 0

                def poll(self):
                    return 0

            def fake_spawn(argv, **kwargs):
                captured.update(argv=argv, env=kwargs["env"])
                kwargs["stdout"].write(cloud.BOOT_MARKER.encode())
                return FakeProcess()

            with mock.patch.object(subprocess, "Popen", side_effect=fake_spawn), \
                 mock.patch.dict(os.environ, {"GH_TOKEN": "forbidden", "ACTIONS_RUNTIME_TOKEN": "forbidden"}):
                result = run_client(work / "Orvala.app", work, public, "headless",
                                    ["--headless", "--", "--library-entry-smoke"], cloud.BOOT_MARKER)
            self.assertTrue(result["passed"])
            self.assertLess(captured["argv"].index("--log-file"), captured["argv"].index("--"))
            self.assertNotIn("GH_TOKEN", captured["env"])
            self.assertNotIn("ACTIONS_RUNTIME_TOKEN", captured["env"])

    def test_no_passing_status_without_exact_markers(self):
        self.assertFalse(cloud.smoke_passed(0, "Godot started"))
        self.assertFalse(cloud.smoke_passed(0, cloud.BOOT_MARKER + "\nERROR: failure"))
        self.assertTrue(cloud.smoke_passed(0, cloud.BOOT_MARKER))

    def test_owned_work_rejects_wrong_run(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / "orvala-mac-native-client-fixture"
            work.mkdir()
            cloud.write_json(work / MARKER_FILE, {"version": VERSION, "manifest_sha256": "a" * 64, "run_id": "123", "attempt": "1"})
            self.assertEqual(read_owned_work(work, "a" * 64, "123", "1")["run_id"], "123")
            with self.assertRaises(cloud.PipelineError):
                read_owned_work(work, "a" * 64, "999", "1")

    def test_publishing_refuses_wrong_repository_before_reading_token(self):
        with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": "other/repo"}, clear=True):
            with self.assertRaises(cloud.PipelineError):
                upload_qa(Path("missing"), "a" * 64, "123", "1")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--self-test", action="store_true", help="Small offline fixtures; never network or credentials.")
    mode.add_argument("--run", action="store_true", help="Download and test the exact already-published own package on disposable Mac CI.")
    mode.add_argument("--publish-evidence", action="store_true", help="Only upload bounded QA assets after an earlier PASS; never run the game with a token.")
    mode.add_argument("--report", action="store_true", help="Print safe completed local evidence only.")
    parser.add_argument("--manifest-sha256", default="", help="Required independently approved SHA-256 of the own v1.0.5 manifest.")
    parser.add_argument("--work-dir", type=Path, default=Path(tempfile.gettempdir()) / "orvala-mac-native-client-local")
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", ""))
    parser.add_argument("--attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT", "1"))
    args = parser.parse_args(argv)
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(OfflineTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    try:
        manifest_sha = valid_sha256(args.manifest_sha256)
        if not (args.run or args.publish_evidence or args.report):
            print(json.dumps(plan(manifest_sha), indent=2, ensure_ascii=False))
            return 0
        require(re.fullmatch(r"[0-9]{1,20}", args.run_id) is not None and re.fullmatch(r"[1-9][0-9]?", args.attempt) is not None,
                "Use the actual bounded GitHub run ID and attempt.")
        work = args.work_dir.resolve()
        if args.publish_evidence:
            upload_qa(work, manifest_sha, args.run_id, args.attempt)
            return 0
        if args.report:
            read_owned_work(work, manifest_sha, args.run_id, args.attempt)
            path = work / "public/evidence.json"
            require(path.is_file() and not path.is_symlink() and path.stat().st_size < 512 * 1024, "Completed QA evidence is unavailable.")
            value = json.loads(path.read_text(encoding="utf-8"))
            print(json.dumps(value, indent=2, ensure_ascii=False))
            return 0
        result = run(args, manifest_sha, args.run_id, args.attempt)
        print("Native .NET, six rendered menus and normal home startup passed. Read status/startup_window_verified for desktop capture availability; real audio, full duels and M5 hardware were not tested."
              if result == 0 else "NOT APPROVED: graphical runner checks were unavailable or failed; see explicit QA evidence.")
        return result
    except (cloud.PipelineError, OSError, ValueError):
        print("FAILED: published Mac client QA did not meet its pinned safety/integrity/native checks. Read the bounded local evidence; no package or portal was changed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
