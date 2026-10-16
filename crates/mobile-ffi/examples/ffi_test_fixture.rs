//! Creates a disposable encrypted account and public synthetic credential for ABI smoke tests.
//! This fixture is test-only and must never be used as an account or issuer in production.

use std::{env, fs, path::PathBuf, time::SystemTime};

use annoda_core::{
    AccountKeyStore, PortableAccountVault,
    identity::DevelopmentIssuer,
    matching::MatchRecord,
    storage::{MailboxCursor, PeerStorage},
};

const TEST_PASSPHRASE: &[u8] = b"test-only portable passphrase";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let destination = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: ffi_test_fixture <private temporary directory>")?;
    fs::create_dir_all(&destination)?;
    let account_dir = destination.join("account");
    let account = PortableAccountVault::new(&account_dir).create(TEST_PASSPHRASE)?;
    let issuer = DevelopmentIssuer::new()?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let credential = issuer.issue_synthetic(
        account.identity(),
        "Synthetic Fixture",
        24,
        now.saturating_sub(1),
        now.saturating_add(3600),
    )?;
    let bob = annoda_core::DeviceKeyPair::generate()?;
    let bob_credential = issuer.issue_synthetic(
        &bob,
        "Synthetic Peer",
        26,
        now.saturating_sub(1),
        now.saturating_add(3600),
    )?;
    let trust = issuer.trusted_issuers();
    let mut bob_record = MatchRecord::new(bob_credential.profile_id(), credential.profile_id())?;
    let like = bob_record.create_like_envelope(
        &bob,
        &bob_credential,
        &credential,
        [0x51; 16],
        now,
        now.saturating_add(1800),
        &trust,
    )?;
    let mut state = PeerStorage::open_default(account_dir.join("client-state.sqlite3"))?;
    state.receive_like_checkpointed(
        &like,
        &bob_credential,
        account.identity(),
        &credential,
        &trust,
        now,
        "fixture-peer",
        MailboxCursor {
            expires_at: like.expires_at,
            parcel_id: like.id,
        },
    )?;
    let fixture = format!(
        "credential={}\nissuer_key={}\n",
        hex(&postcard::to_allocvec(&credential)?),
        hex(&issuer.public_key())
    );
    fs::write(destination.join("public-fixture.txt"), fixture)?;
    account.lock();
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
