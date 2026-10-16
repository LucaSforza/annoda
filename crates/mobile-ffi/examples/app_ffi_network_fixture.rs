//! Test-only real-network fixture for the public UniFFI application API.
//!
//! It starts two independent volunteer nodes and accepts public-key-only synthetic
//! issuance requests on stdin. It never writes or prints account private keys.

use std::{
    env, fs,
    io::{self, BufRead, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use annoda_core::identity::{DevelopmentIssuer, IdentityIssuer, IssuanceRequest};
use annoda_network::{NodeConfig, PeerNode};

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: app_ffi_network_fixture <private temporary directory>")?;
    fs::create_dir_all(&root)?;
    let issuer = DevelopmentIssuer::new()?;

    let first_config = NodeConfig {
        data_dir: root.join("volunteer-a"),
        listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".parse()?],
        ..NodeConfig::default()
    };
    let first = PeerNode::start(first_config, issuer.trusted_issuers()).await?;
    let first_address = first
        .wait_for_listeners()
        .await?
        .into_iter()
        .next()
        .ok_or("no listener")?;

    let second_config = NodeConfig {
        data_dir: root.join("volunteer-b"),
        listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".parse()?],
        bootstrap_peers: vec![annoda_network::BootstrapPeer {
            peer_id: first.peer_id(),
            address: first_address.clone(),
        }],
        ..NodeConfig::default()
    };
    let second = PeerNode::start(second_config, issuer.trusted_issuers()).await?;
    let second_address = second
        .wait_for_listeners()
        .await?
        .into_iter()
        .next()
        .ok_or("no listener")?;

    println!("issuer_key={}", hex(&issuer.public_key()));
    println!("peer_a={}", first.peer_id());
    println!("address_a={first_address}");
    println!("peer_b={}", second.peer_id());
    println!("address_b={second_address}");
    println!("ready=1");
    io::stdout().flush()?;

    for line in io::stdin().lock().lines() {
        let line = line?;
        if line == "QUIT" {
            break;
        }
        let response = issue_line(&issuer, &line);
        println!("{response}");
        io::stdout().flush()?;
    }

    second.shutdown().await;
    first.shutdown().await;
    Ok(())
}

fn issue_line(issuer: &DevelopmentIssuer, line: &str) -> String {
    let mut fields = line.split_whitespace();
    let (Some("ISSUE"), Some(signing), Some(encryption), Some(first_name_hex), Some(age), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return "ERROR invalid request".to_owned();
    };
    let Ok(signing) = decode_hex(signing).and_then(|bytes| bytes.try_into().map_err(|_| ())) else {
        return "ERROR invalid signing key".to_owned();
    };
    let Ok(encryption_key) = decode_hex(encryption) else {
        return "ERROR invalid encryption key".to_owned();
    };
    if encryption_key.len() != 32 {
        return "ERROR invalid encryption key".to_owned();
    }
    let Ok(first_name) =
        decode_hex(first_name_hex).and_then(|bytes| String::from_utf8(bytes).map_err(|_| ()))
    else {
        return "ERROR invalid name".to_owned();
    };
    let Ok(age_at_issue) = age.parse::<u8>() else {
        return "ERROR invalid age".to_owned();
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return "ERROR unavailable clock".to_owned();
    };
    let issued_at = now.as_secs();
    match issuer.issue(IssuanceRequest {
        signing_key: signing,
        encryption_key,
        first_name,
        age_at_issue,
        issued_at,
        expires_at: issued_at.saturating_add(24 * 60 * 60),
    }) {
        Ok(credential) => match postcard::to_allocvec(&credential) {
            Ok(bytes) => format!("CREDENTIAL {}", hex(&bytes)),
            Err(_) => "ERROR credential encoding failed".to_owned(),
        },
        Err(_) => "ERROR issuance rejected".to_owned(),
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2) || value.len() > 16 * 1024 {
        return Err(());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).ok_or(())?;
            let low = (pair[1] as char).to_digit(16).ok_or(())?;
            Ok(((high << 4) | low) as u8)
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
