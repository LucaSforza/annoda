use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
};

use futures::io::{AsyncRead, AsyncWrite};

#[derive(Debug)]
struct MeterState {
    download_limit: u64,
    upload_limit: u64,
    downloaded: u64,
    uploaded: u64,
    phase_limit: u64,
    phase_used: u64,
}

pub(crate) struct TransferMeter(Mutex<MeterState>);

impl TransferMeter {
    pub(crate) fn new(download_limit: u64, upload_limit: u64) -> Arc<Self> {
        Arc::new(Self(Mutex::new(MeterState {
            download_limit,
            upload_limit,
            downloaded: 0,
            uploaded: 0,
            phase_limit: u64::MAX,
            phase_used: 0,
        })))
    }

    fn state(&self) -> MutexGuard<'_, MeterState> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn downloaded(&self) -> u64 {
        self.state().downloaded
    }

    pub(crate) fn uploaded(&self) -> u64 {
        self.state().uploaded
    }

    pub(crate) fn set_upload_limit(&self, limit: u64) {
        self.state().upload_limit = limit;
    }

    pub(crate) fn start_phase_limit(&self, limit: u64) {
        let mut state = self.state();
        state.phase_used = 0;
        state.phase_limit = limit;
    }

    pub(crate) fn end_phase_limit(&self) {
        self.state().phase_limit = u64::MAX;
    }

    fn exhausted() -> io::Error {
        io::Error::other("sync transfer budget exhausted")
    }
}

pub(crate) struct MeteredIo<T> {
    inner: T,
    meter: Option<Arc<TransferMeter>>,
}

impl<T> MeteredIo<T> {
    pub(crate) fn new(inner: T, meter: Option<Arc<TransferMeter>>) -> Self {
        Self { inner, meter }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for MeteredIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let Some(meter) = self.meter.clone() else {
            return Pin::new(&mut self.inner).poll_read(context, buffer);
        };
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Keep the state lock for this synchronous poll so phase changes cannot
        // reclassify an in-progress reservation between reserve and completion.
        let mut state = meter.state();
        let available = state
            .download_limit
            .saturating_sub(state.downloaded)
            .min(state.phase_limit.saturating_sub(state.phase_used));
        if available == 0 {
            return Poll::Ready(Err(TransferMeter::exhausted()));
        }
        let allowed = buffer.len().min(available.min(usize::MAX as u64) as usize);
        match Pin::new(&mut self.inner).poll_read(context, &mut buffer[..allowed]) {
            Poll::Ready(Ok(read)) => {
                let read = read.min(allowed);
                state.downloaded += read as u64;
                state.phase_used += read as u64;
                Poll::Ready(Ok(read))
            }
            other => other,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for MeteredIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Some(meter) = self.meter.clone() else {
            return Pin::new(&mut self.inner).poll_write(context, buffer);
        };
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut state = meter.state();
        let available = state
            .upload_limit
            .saturating_sub(state.uploaded)
            .min(state.phase_limit.saturating_sub(state.phase_used));
        if available == 0 {
            return Poll::Ready(Err(TransferMeter::exhausted()));
        }
        let allowed = buffer.len().min(available.min(usize::MAX as u64) as usize);
        match Pin::new(&mut self.inner).poll_write(context, &buffer[..allowed]) {
            Poll::Ready(Ok(written)) => {
                let written = written.min(allowed);
                state.uploaded += written as u64;
                state.phase_used += written as u64;
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(context)
    }
}

#[cfg(test)]
#[path = "tests/transfer.rs"]
mod tests;
