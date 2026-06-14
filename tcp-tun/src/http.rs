//! A minimal HTTP/1.1 responder — just enough to make `curl` happy.
//!
//! One task per connection: read until the end of the request headers (`\r\n\r\n`), send a
//! single fixed `200 OK`, and close. We scan for the terminator across reads (curl may split
//! the request across segments, `device-icmp/T13`) and respond exactly once.

use tcp_core::TcpStream;

const MAX_REQUEST: usize = 64 * 1024;

pub async fn serve(stream: TcpStream) {
    let mut request = Vec::new();
    let mut buf = [0u8; 2048];

    // Read until we have the full request-line + headers, or the peer closes / over-sends.
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

    let body = b"<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>userspace-tcp</title></head>\n<body>\n<h1>Hello from a userspace TCP/IP stack written in Rust.</h1>\n<p>This page was served by a from-scratch TCP implementation &mdash; no kernel sockets, no smoltcp, no tokio, zero dependencies. <code>curl</code> believes it is talking to the kernel; it is talking to userspace code.</p>\n</body></html>\n";

    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Server: rustphd-userspace-tcp\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );

    if stream.write_all(header.as_bytes()).await.is_err() {
        return;
    }
    let _ = stream.write_all(body).await;
    stream.close();
}

/// True once the buffer contains the CRLF CRLF that ends the request headers.
fn headers_complete(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n")
}
