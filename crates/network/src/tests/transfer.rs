use super::*;
use futures::io::{AsyncReadExt, AsyncWriteExt, Cursor};

#[tokio::test]
async fn meters_only_completed_io_and_stops_at_shared_limits() {
    let meter = TransferMeter::new(3, 2);
    let mut source = MeteredIo::new(Cursor::new(vec![1, 2, 3, 4]), Some(meter.clone()));
    let mut bytes = [0; 8];
    assert_eq!(source.read(&mut bytes).await.unwrap(), 3);
    assert_eq!(meter.downloaded(), 3);
    assert_eq!(
        source.read(&mut bytes).await.unwrap_err().kind(),
        io::ErrorKind::Other
    );

    let mut sink = MeteredIo::new(Cursor::new(Vec::new()), Some(meter.clone()));
    assert_eq!(sink.write(b"abcd").await.unwrap(), 2);
    assert_eq!(meter.uploaded(), 2);
    assert_eq!(
        sink.write(b"x").await.unwrap_err().kind(),
        io::ErrorKind::Other
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_connections_share_one_hard_transfer_ceiling() {
    let meter = TransferMeter::new(0, 4096);
    let mut workers = Vec::new();
    for _ in 0..16 {
        let meter = meter.clone();
        workers.push(tokio::spawn(async move {
            let mut io = MeteredIo::new(Cursor::new(Vec::new()), Some(meter));
            let mut written = 0;
            loop {
                match io.write(&[7; 128]).await {
                    Ok(count) => written += count,
                    Err(error) if error.kind() == io::ErrorKind::Other => break,
                    Err(error) => panic!("unexpected metered write error: {error}"),
                }
            }
            written
        }));
    }
    let mut total = 0;
    for worker in workers {
        total += worker.await.unwrap();
    }
    assert_eq!(total, 4096);
    assert_eq!(meter.uploaded(), 4096);
}

#[tokio::test]
async fn contribution_phase_caps_combined_reads_and_writes() {
    let meter = TransferMeter::new(100, 100);
    meter.start_phase_limit(5);
    let mut sink = MeteredIo::new(Cursor::new(Vec::new()), Some(meter.clone()));
    assert_eq!(sink.write(b"abcd").await.unwrap(), 4);
    let mut source = MeteredIo::new(Cursor::new(vec![1, 2, 3]), Some(meter.clone()));
    let mut bytes = [0; 3];
    assert_eq!(source.read(&mut bytes).await.unwrap(), 1);
    assert_eq!(meter.uploaded() + meter.downloaded(), 5);
}
