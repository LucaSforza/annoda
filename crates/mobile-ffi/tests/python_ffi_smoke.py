#!/usr/bin/env python3
"""Exercise UniFFI's generated ctypes binding against a built shared library."""

from __future__ import annotations

import argparse
import importlib
import os
import pathlib
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zlib


def png(seed: int) -> bytes:
    def chunk(kind: bytes, payload: bytes) -> bytes:
        body = kind + payload
        return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    width, height = 8, 8
    rows = b"".join(
        b"\0" + b"".join(bytes((seed + x, 90 + y, 150)) for x in range(width))
        for y in range(height)
    )
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows))
        + chunk(b"IEND", b"")
    )


def read_fixture_line(process: subprocess.Popen[bytes], timeout: float = 90.0) -> str:
    buffer = getattr(process, "_annoda_stdout_buffer", bytearray())
    process._annoda_stdout_buffer = buffer
    stderr = getattr(process, "_annoda_stderr_buffer", bytearray())
    process._annoda_stderr_buffer = stderr
    deadline = time.monotonic() + timeout
    while b"\n" not in buffer:
        remaining = deadline - time.monotonic()
        ready, _, _ = select.select(
            [process.stdout, process.stderr], [], [], min(0.5, max(0, remaining))
        )
        if not ready:
            if time.monotonic() >= deadline:
                raise TimeoutError("network fixture did not respond")
            if process.poll() is not None:
                raise RuntimeError(
                    f"network fixture exited with {process.returncode}: "
                    f"{stderr.decode('utf-8', errors='replace')}"
                )
            continue
        for stream in ready:
            data = os.read(stream.fileno(), 4096)
            if stream is process.stdout:
                if not data:
                    raise RuntimeError(
                        "network fixture closed stdout: "
                        f"{stderr.decode('utf-8', errors='replace')}"
                    )
                buffer.extend(data)
            elif data:
                stderr.extend(data)
    line, _, rest = buffer.partition(b"\n")
    process._annoda_stdout_buffer = bytearray(rest)
    return line.decode("utf-8")


def issue_credential(process: subprocess.Popen[bytes], identity, name: str, age: int) -> bytes:
    request = " ".join(
        (
            "ISSUE",
            identity.signing_public_key.hex(),
            identity.encryption_public_key.hex(),
            name.encode("utf-8").hex(),
            str(age),
        )
    )
    process.stdin.write((request + "\n").encode("ascii"))
    process.stdin.flush()
    response = read_fixture_line(process)
    if not response.startswith("CREDENTIAL "):
        raise RuntimeError(f"synthetic issuer rejected request: {response}")
    return bytes.fromhex(response.removeprefix("CREDENTIAL "))


def run_public_network_workflow(ffi, repository: pathlib.Path, root: pathlib.Path) -> None:
    fixture_root = root / "network-fixture"
    process = subprocess.Popen(
        [
            "cargo",
            "run",
            "--offline",
            "-p",
            "annoda-mobile-ffi",
            "--example",
            "app_ffi_network_fixture",
            "--",
            str(fixture_root),
        ],
        cwd=repository,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    try:
        metadata = {}
        while metadata.get("ready") != "1":
            line = read_fixture_line(process)
            key, separator, value = line.partition("=")
            if separator:
                metadata[key] = value
        budget = ffi.FfiSyncBudget(
            max_duration_ms=20_000,
            max_download_bytes=8 * 1024 * 1024,
            max_upload_bytes=8 * 1024 * 1024,
            max_peers=2,
            max_mailbox_items=32,
            max_concurrent_requests=4,
            retries=1,
            request_timeout_ms=3_000,
        )
        peers = [
            ffi.FfiSyncPeer(peer_id=metadata[f"peer_{letter}"], address=metadata[f"address_{letter}"])
            for letter in ("a", "b")
        ]

        def config(name: str):
            return ffi.FfiApplicationConfig(
                data_directory=str(root / f"{name}-account"),
                transport_data_directory=str(root / f"{name}-transport"),
                trusted_issuer_keys=[bytes.fromhex(metadata["issuer_key"])],
                revoked_serials=[],
                peers=peers,
                sync_budget=budget,
                allow_development_safety_fixture=True,
            )

        applications = []
        alice = ffi.create_application(config("alice"), "python ABI Alice passphrase")
        applications.append(alice)
        bob = ffi.create_application(config("bob"), "python ABI Bob passphrase")
        applications.append(bob)
        alice_identity = alice.identity_summary()
        bob_identity = bob.identity_summary()
        alice_id, bob_id = alice_identity.profile_id, bob_identity.profile_id
        alice.import_credential(issue_credential(process, alice_identity, "Alice", 28))
        bob.import_credential(issue_credential(process, bob_identity, "Bob", 30))
        alice.publish_profile([png(10), png(40), png(80)])
        bob.publish_profile([png(20), png(60), png(100)])
        alice_profile = alice.published_profile()
        assert alice_profile is not None
        assert alice_profile.profile_id == alice_id and len(alice_profile.photos) == 3

        def sync(app):
            result = app.start_sync_session().wait_result(25_000)
            assert result is not None, "bounded sync session completed without a report"
            return result

        query = ffi.FfiDiscoveryQuery(
            minimum_age=18, maximum_age=99, page_size=20, cursor=None, coarse_region=None
        )
        found = bob.discover(query)
        alice_candidate = next(item for item in found.items if item.profile_id == alice_id)
        photo = bob.fetch_photo(alice_id, alice_candidate.photos[0].hash)
        assert photo.width == 8 and photo.height == 8
        assert photo.media_type == "image/jpeg" and photo.bytes.startswith(b"\xff\xd8")

        bob.like(alice_id)
        sync(alice)
        assert any(item.sender == bob_id for item in alice.received_likes(20, None).items)
        alice.like(bob_id)
        sync(bob)
        alice_match = next(item for item in alice.matches(20, None).items if item.peer == bob_id)
        bob_match = next(item for item in bob.matches(20, None).items if item.peer == alice_id)
        assert alice_match.match_id == bob_match.match_id

        telegram = ffi.FfiContactHandle(
            service=ffi.FfiContactService.TELEGRAM,
            other_service=None,
            value="@bob-python-fixture",
        )
        bob.disclose_contacts(bob_match.match_id, [telegram])
        sync(alice)
        assert alice.received_contacts(alice_match.match_id) == [telegram]
        instagram = ffi.FfiContactHandle(
            service=ffi.FfiContactService.INSTAGRAM,
            other_service=None,
            value="@alice-python-fixture",
        )
        alice.disclose_contacts(alice_match.match_id, [instagram])
        sync(bob)
        assert bob.received_contacts(bob_match.match_id) == [instagram]
        try:
            alice.operations_page(1, ffi.FfiPageCursor(value=b"\xff"))
        except ffi.FfiError.InvalidInput:
            pass
        else:
            raise AssertionError("malformed operation cursor was accepted")
        first_operations = alice.operations_page(1, None)
        assert len(first_operations.items) == 1 and first_operations.next_cursor is not None
        second_operations = alice.operations_page(1, first_operations.next_cursor)
        assert len(second_operations.items) == 1
        assert second_operations.items[0].operation_id != first_operations.items[0].operation_id
        alice.close()
        reopened_alice = ffi.open_application(config("alice"), "python ABI Alice passphrase")
        applications.append(reopened_alice)
        assert reopened_alice.identity_summary() == alice_identity
        restored_profile = reopened_alice.published_profile()
        assert restored_profile is not None
        assert restored_profile.profile_id == alice_id and len(restored_profile.photos) == 3
        assert any(item.match_id == alice_match.match_id for item in reopened_alice.matches(20, None).items)
        reopened_alice.block(bob_id)
        assert all(item.profile_id != bob_id for item in reopened_alice.discover(query).items)
        reopened_alice.close()
    finally:
        for application in locals().get("applications", []):
            application.close()
        if process.poll() is None:
            process.stdin.write(b"QUIT\n")
            process.stdin.flush()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("library", type=pathlib.Path)
    parser.add_argument("fixture_directory", type=pathlib.Path, nargs="?")
    parser.add_argument("--skip-network", action="store_true", help="skip the two-volunteer application workflow")
    args = parser.parse_args()

    binding = pathlib.Path(__file__).parents[1] / "generated/python/annoda_mobile_ffi.py"
    if not args.library.is_file():
        parser.error(f"shared library does not exist: {args.library}")
    if not binding.is_file():
        parser.error(f"generated UniFFI binding does not exist: {binding}")
    repository = pathlib.Path(__file__).parents[3]
    fixture_temp = None
    fixture_directory = args.fixture_directory
    if fixture_directory is None:
        fixture_temp = tempfile.TemporaryDirectory(prefix="annoda-ffi-fixture-")
        fixture_directory = pathlib.Path(fixture_temp.name)
        subprocess.run(
            [
                "cargo",
                "run",
                "--offline",
                "-p",
                "annoda-mobile-ffi",
                "--example",
                "ffi_test_fixture",
                "--",
                str(fixture_directory),
            ],
            cwd=repository,
            check=True,
        )
    public_fixture = fixture_directory / "public-fixture.txt"
    fixture_account_directory = fixture_directory / "account"
    if not public_fixture.is_file() or not fixture_account_directory.is_dir():
        parser.error("test fixture directory must contain public-fixture.txt and account/")
    fixture = dict(
        line.split("=", maxsplit=1)
        for line in public_fixture.read_text(encoding="ascii").splitlines()
    )

    with tempfile.TemporaryDirectory(prefix="annoda-ffi-") as temporary:
        directory = pathlib.Path(temporary)
        account_directory = directory / "account"
        shutil.copy2(binding, directory / binding.name)
        shutil.copy2(args.library, directory / "libannoda_mobile_ffi.so")
        sys.path.insert(0, temporary)
        try:
            ffi = importlib.import_module("annoda_mobile_ffi")
            assert ffi.api_version() == "0.1.0"
            model = ffi.LocalPreferenceModel(2, 1)
            initial = model.score(1, [0.3, 0.4]).probability
            model.record_feedback(1, [0.3, 0.4], True)
            learned = model.score(1, [0.3, 0.4]).probability
            assert initial == 0.5 and learned > initial
            model.reset()
            assert model.score(1, [0.3, 0.4]).probability == 0.5

            try:
                ffi.LocalPreferenceModel(0, 1)
            except ffi.FfiError.InvalidInput:
                pass
            else:
                raise AssertionError("invalid constructor input did not cross the ABI as typed error")

            try:
                model.score(1, [0.3])
            except ffi.FfiError.IncompatibleModel:
                pass
            else:
                raise AssertionError("dimension mismatch did not cross the ABI as typed error")

            account = ffi.create_account(str(account_directory), "test-only portable passphrase")
            profile_id = account.profile_id()
            account.set_notification_preferences(
                ffi.FfiNotificationPreferences(likes_enabled=False, matches_enabled=True)
            )
            assert account.pending_notifications(16) == []
            account.lock()

            try:
                ffi.open_account(str(account_directory), "incorrect passphrase")
            except ffi.FfiError.AuthenticationFailed:
                pass
            else:
                raise AssertionError("wrong account passphrase was not a typed ABI error")

            restored = ffi.open_account(str(account_directory), "test-only portable passphrase")
            assert restored.profile_id() == profile_id
            assert restored.notification_preferences() == ffi.FfiNotificationPreferences(
                likes_enabled=False, matches_enabled=True
            )
            restored.lock()

            fixture_account = ffi.open_account(
                str(fixture_account_directory), "test-only portable passphrase"
            )
            request = ffi.FfiSyncRequest(
                credential=bytes.fromhex(fixture["credential"]),
                trusted_issuer_keys=[bytes.fromhex(fixture["issuer_key"])],
                revoked_serials=[],
                peers=[],
                budget=ffi.FfiSyncBudget(
                    max_duration_ms=10_000,
                    max_download_bytes=1024,
                    max_upload_bytes=1024,
                    max_peers=1,
                    max_mailbox_items=4,
                    max_concurrent_requests=1,
                    retries=0,
                    request_timeout_ms=1000,
                ),
                contribution_policy=ffi.FfiPeerContributionPolicy(
                    enabled=False,
                    wifi_only=True,
                    charging_only=False,
                    max_storage_bytes=0,
                    max_transfer_bytes=0,
                    max_duration_ms=0,
                ),
                host_conditions=ffi.FfiHostConditions(
                    wifi_available=False,
                    charging=False,
                ),
                authorized_replicas=[],
            )
            session = fixture_account.start_sync_session(request)
            session.cancel()
            report = session.wait_result(5000)
            assert report is not None
            assert report.status == ffi.FfiSyncStatus.DEFERRED
            assert report.deferred_reasons == [ffi.FfiSyncDeferredReason.NO_PEERS]
            assert report.contacted_peers == []
            assert report.new_events == []
            pending = fixture_account.pending_notifications(16)
            assert len(pending) == 1
            assert pending[0].kind == ffi.FfiNotificationKind.NEW_LIKE
            assert len(pending[0].event_id) == 32
            assert fixture_account.acknowledge_notification(pending[0].event_id) is True
            assert fixture_account.acknowledge_notification(pending[0].event_id) is False
            assert fixture_account.pending_notifications(16) == []
            fixture_account.lock()
            restored.lock()

            application_config = ffi.FfiApplicationConfig(
                data_directory=str(fixture_account_directory),
                transport_data_directory=str(directory / "transport"),
                trusted_issuer_keys=[bytes.fromhex(fixture["issuer_key"])],
                revoked_serials=[],
                peers=[],
                sync_budget=ffi.FfiSyncBudget(
                    max_duration_ms=10_000,
                    max_download_bytes=1024,
                    max_upload_bytes=1024,
                    max_peers=1,
                    max_mailbox_items=4,
                    max_concurrent_requests=1,
                    retries=0,
                    request_timeout_ms=1000,
                ),
                allow_development_safety_fixture=False,
            )
            application = ffi.open_application(
                application_config, "test-only portable passphrase"
            )
            assert application.cancel_current_operation() is False
            application_identity = application.identity_summary()
            assert len(application_identity.profile_id) == 32
            application.import_credential(bytes.fromhex(fixture["credential"]))
            assert application.credential() == bytes.fromhex(fixture["credential"])
            incoming = application.received_likes(16, None)
            assert len(incoming.items) == 1
            assert incoming.items[0].first_name == "Synthetic Peer"
            assert incoming.items[0].state == ffi.FfiMatchState.INCOMING
            assert application.matches(16, None).items == []
            application.close()

            reopened_application = ffi.open_application(
                application_config, "test-only portable passphrase"
            )
            assert reopened_application.identity_summary() == application_identity
            assert reopened_application.credential() == bytes.fromhex(fixture["credential"])
            assert len(reopened_application.received_likes(16, None).items) == 1
            reopened_application.close()
            if not args.skip_network:
                run_public_network_workflow(ffi, repository, directory)
        finally:
            sys.path.remove(temporary)
            sys.modules.pop("annoda_mobile_ffi", None)

    print("UniFFI Python ABI smoke test passed")
    if fixture_temp is not None:
        fixture_temp.cleanup()


if __name__ == "__main__":
    main()
