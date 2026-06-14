//! A minimal HTTP/1.1 responder — enough to make `curl` happy and to benchmark throughput.
//!
//! One task per connection: read until the end of the request headers (`\r\n\r\n`), then serve
//! a response and close. `GET /` returns a small HTML page; `GET /bench` (optionally
//! `/bench/<MiB>`) streams a large body to measure sustained throughput. We scan for the
//! header terminator across reads (curl may split the request across segments) and respond
//! exactly once.

use tcp_core::TcpStream;

const MAX_REQUEST: usize = 64 * 1024;
const BENCH_DEFAULT_MIB: usize = 16;
const CHUNK: usize = 64 * 1024;

pub async fn serve(stream: TcpStream) {
    let mut request = Vec::new();
    let mut buf = [0u8; 2048];

    loop {
        match stream.read(&mut buf).await {
            Ok(0) => return, // peer closed before sending a full request
            Ok(n) => {
                request.extend_from_slice(&buf[..n]);
                if headers_complete(&request) || request.len() > MAX_REQUEST {
                    break;
                }
            }
            Err(_) => return, // connection reset
        }
    }

    let path = request_path(&request);
    if path == b"/bench" || path.starts_with(b"/bench/") {
        serve_bench(&stream, bench_size(path)).await;
    } else {
        serve_index(&stream).await;
    }
    stream.close();
}

async fn serve_index(stream: &TcpStream) {
    let body = b"<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>ferrumnet</title></head>\n<body>\n<h1>Hello from a userspace TCP/IP stack written in Rust.</h1>\n<p>This page was served by a from-scratch TCP implementation &mdash; no kernel sockets, no smoltcp, no tokio, zero dependencies. <code>curl</code> believes it is talking to the kernel; it is talking to userspace code.</p>\n<p>Try <code>/bench</code> for a throughput test.</p>\n</body></html>\n";
    let header = format!(
        "HTTP/1.1 200 OK\r\nServer: ferrumnet\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if stream.write_all(header.as_bytes()).await.is_err() {
        return;
    }
    let _ = stream.write_all(body).await;
}

/// Stream `mib` mebibytes of payload, exercising the send path (cwnd growth, windowing,
/// segmentation, ACK clocking) end to end through the 64 KiB tx ring.
async fn serve_bench(stream: &TcpStream, mib: usize) {
    let total = mib * 1024 * 1024;
    let header = format!(
        "HTTP/1.1 200 OK\r\nServer: ferrumnet\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        total
    );
    if stream.write_all(header.as_bytes()).await.is_err() {
        return;
    }
    let chunk = vec![b'x'; CHUNK];
    let mut sent = 0;
    while sent < total {
        let n = (total - sent).min(CHUNK);
        if stream.write_all(&chunk[..n]).await.is_err() {
            return;
        }
        sent += n;
    }
}

/// Extract the request-target from the first line: `GET <path> HTTP/1.1`.
fn request_path(req: &[u8]) -> &[u8] {
    let line_end = req.windows(2).position(|w| w == b"\r\n").unwrap_or(req.len());
    let line = &req[..line_end];
    let mut parts = line.split(|&b| b == b' ');
    parts.next(); // method
    parts.next().unwrap_or(b"/")
}

/// Parse an optional size from `/bench/<MiB>`, clamped to a sane range.
fn bench_size(path: &[u8]) -> usize {
    let suffix = path.strip_prefix(b"/bench/").unwrap_or(b"");
    std::str::from_utf8(suffix)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(BENCH_DEFAULT_MIB)
        .clamp(1, 256)
}

/// True once the buffer contains the CRLF CRLF that ends the request headers.
fn headers_complete(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n")
}
