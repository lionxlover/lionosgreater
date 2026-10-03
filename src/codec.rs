#![forbid(unsafe_code)]
//! JSON-lines frame reader/writer over the UI socket.
//!
//! Bounds: a frame (line) larger than [`MAX_LINE_BYTES`] aborts the
//! connection; frames must be valid UTF-8. After a line has been handed to
//! the caller, its bytes are owned by a `Zeroizing<String>` wrapper at the
//! call site, so password material in `AnswerPrompt` lines is wiped on drop
//! (spec §3).

use crate::error::{Error, Result};
use crate::proto::MAX_LINE_BYTES;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

/// Reads newline-delimited UTF-8 frames from an async stream.
pub struct FrameReader<R> {
    inner: Pin<Box<R>>,
    buf: Vec<u8>,
    eof: bool,
}

impl<R: AsyncRead> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        FrameReader {
            inner: Box::pin(inner),
            buf: Vec::with_capacity(512),
            eof: false,
        }
    }

    /// Next frame as a zeroizing string, or `None` on clean EOF.
    pub async fn next_frame(&mut self) -> Result<Option<Zeroizing<String>>> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                // Split off the line (excluding the LF), CR tolerated.
                let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
                line.pop(); // LF
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if line.is_empty() || line.iter().all(|b| b.is_ascii_whitespace()) {
                    continue; // ignore blank lines
                }
                match String::from_utf8(line) {
                    Ok(s) => return Ok(Some(Zeroizing::new(s))),
                    Err(e) => {
                        // `e` may contain the offending bytes; drop the bytes
                        // explicitly, keep only offsets for the error.
                        let mut bad = e.into_bytes();
                        zeroize_vec(&mut bad);
                        return Err(Error::Protocol("frame is not valid UTF-8".into()));
                    }
                }
            }
            if self.eof {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                // trailing garbage without newline
                let mut bad = std::mem::take(&mut self.buf);
                zeroize_vec(&mut bad);
                return Err(Error::Protocol("trailing partial frame at EOF".into()));
            }
            if self.buf.len() >= MAX_LINE_BYTES {
                // Connection will be dropped after this error; wipe the buffer.
                let mut bad = std::mem::take(&mut self.buf);
                zeroize_vec(&mut bad);
                return Err(Error::Protocol(format!(
                    "frame exceeds {} bytes; connection dropped",
                    MAX_LINE_BYTES
                )));
            }
            let mut chunk = [0u8; 2048];
            let n = self.inner.as_mut().read(&mut chunk).await?;
            if n == 0 {
                self.eof = true;
            } else {
                self.buf.extend_from_slice(&chunk[..n]);
            }
        }
    }
}

/// Writes single frames. Writer side never emits secret material.
pub struct FrameWriter<W> {
    inner: Pin<Box<W>>,
}

impl<W: AsyncWrite> FrameWriter<W> {
    pub fn new(inner: W) -> Self {
        FrameWriter {
            inner: Box::pin(inner),
        }
    }

    pub async fn write_frame(&mut self, line: &str) -> Result<()> {
        self.inner.as_mut().write_all(line.as_bytes()).await?;
        self.inner.as_mut().write_all(b"\n").await?;
        Ok(self.inner.as_mut().flush().await?)
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        Ok(self.inner.as_mut().shutdown().await?)
    }
}

fn zeroize_vec(v: &mut Vec<u8>) {
    use zeroize::Zeroize;
    v.zeroize();
    v.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn splits_lines_and_ignores_blanks() {
        let (mut w, r) = tokio::io::duplex(64);
        w.write_all(b"  \n{\"a\":1}\n{\"a\":2}\n").await.unwrap();
        drop(w);
        let mut fr = FrameReader::new(r);
        let a = fr.next_frame().await.unwrap().unwrap();
        assert_eq!(&*a, r#"{"a":1}"#);
        let b = fr.next_frame().await.unwrap().unwrap();
        assert_eq!(&*b, r#"{"a":2}"#);
        assert!(fr.next_frame().await.unwrap().is_none());
    }

    #[test]
    fn oversized_frame_errors() {
        rt().block_on(async {
            let (mut w, r) = tokio::io::duplex(1024);
            // Write from a task so the duplex (1 KiB capacity) doesn't
            // deadlock against the not-yet-started reader.
            let writer = tokio::spawn(async move {
                let big = vec![b'a'; MAX_LINE_BYTES + 10];
                w.write_all(&big).await.unwrap();
            });
            let mut fr = FrameReader::new(r);
            assert!(fr.next_frame().await.is_err());
            let _ = writer.await;
        });
    }

    #[test]
    fn invalid_utf8_errors() {
        rt().block_on(async {
            let (mut w, r) = tokio::io::duplex(64);
            w.write_all(b"\xff\xfe bad \n").await.unwrap();
            let mut fr = FrameReader::new(r);
            assert!(fr.next_frame().await.is_err());
        });
    }
}
