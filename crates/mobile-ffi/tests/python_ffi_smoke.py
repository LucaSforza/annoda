#!/usr/bin/env python3
"""Exercise UniFFI's generated ctypes binding against a built shared library."""

from __future__ import annotations

import argparse
import importlib
import pathlib
import shutil
import subprocess
import sys
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("library", type=pathlib.Path)
    parser.add_argument("fixture_directory", type=pathlib.Path, nargs="?")
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
        finally:
            sys.path.remove(temporary)
            sys.modules.pop("annoda_mobile_ffi", None)

    print("UniFFI Python ABI smoke test passed")
    if fixture_temp is not None:
        fixture_temp.cleanup()


if __name__ == "__main__":
    main()
