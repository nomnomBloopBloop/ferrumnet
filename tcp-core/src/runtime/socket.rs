//! `TcpListener` / `TcpStream` and their `accept` / `read` / `write` futures.
//!
//! Each holds an `Rc` to the shared reactor state. A future, when it cannot make progress,
//! stores its `Waker` in the reactor's per-connection registry **before** returning `Pending`
//! (within the same `RefCell` borrow as the buffer check) — closing the lost-wakeup race.

use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use crate::iface::Endpoint;
use crate::state::State;

use super::reactor::ReactorState;

/// A listening socket bound to the runtime's local endpoint.
///
/// Invariant: drive it from a **single** accept loop. The reactor keeps one `accept_waker`
/// slot, so two concurrently-pending `accept()` futures on clones would clobber each other.
#[derive(Clone)]
pub struct TcpListener {
    state: Rc<RefCell<ReactorState>>,
}

impl TcpListener {
    pub(crate) fn new(state: Rc<RefCell<ReactorState>>) -> Self {
        TcpListener { state }
    }

    /// Accept the next established connection.
    pub fn accept(&self) -> Accept {
        Accept {
            state: self.state.clone(),
        }
    }
}

pub struct Accept {
    state: Rc<RefCell<ReactorState>>,
}

impl Future for Accept {
    type Output = TcpStream;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<TcpStream> {
        let mut s = self.state.borrow_mut();
        // Skip any queued connection that was reset/closed before we got to it.
        while let Some(remote) = s.accept_queue.pop_front() {
            let usable = s
                .stack
                .connection_mut(&remote)
                .is_some_and(|t| t.is_synchronized() || t.rx_available() > 0);
            if usable {
                return Poll::Ready(TcpStream {
                    state: self.state.clone(),
                    remote,
                });
            }
        }
        s.accept_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// An established connection.
pub struct TcpStream {
    state: Rc<RefCell<ReactorState>>,
    remote: Endpoint,
}

impl TcpStream {
    pub fn peer(&self) -> Endpoint {
        self.remote
    }

    /// Read up to `buf.len()` bytes. Resolves to `Ok(0)` at end of stream (peer FIN).
    pub fn read<'a>(&'a self, buf: &'a mut [u8]) -> Read<'a> {
        Read { stream: self, buf }
    }

    /// Write up to `buf.len()` bytes (POSIX semantics — may be short). Use [`TcpStream::write_all`]
    /// to send everything.
    pub fn write<'a>(&'a self, buf: &'a [u8]) -> Write<'a> {
        Write { stream: self, buf }
    }

    /// Write the entire buffer, awaiting send-buffer space as needed.
    pub async fn write_all(&self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let n = self.write(data).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "connection closed"));
            }
            data = &data[n..];
        }
        Ok(())
    }

    /// Begin an orderly close (send FIN after queued data).
    pub fn close(&self) {
        if let Some(tcb) = self.state.borrow_mut().stack.connection_mut(&self.remote) {
            tcb.close();
        }
    }
}

pub struct Read<'a> {
    stream: &'a TcpStream,
    buf: &'a mut [u8],
}

impl Future for Read<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.buf.is_empty() {
            return Poll::Ready(Ok(0)); // honour the zero-length read contract
        }
        let remote = me.stream.remote;
        let mut s = me.stream.state.borrow_mut();
        match s.stack.connection_mut(&remote) {
            None => Poll::Ready(Ok(0)), // connection gone -> EOF
            Some(tcb) => {
                if tcb.rx_available() > 0 {
                    Poll::Ready(Ok(tcb.recv(me.buf))) // deliver buffered data first
                } else if tcb.is_reset() {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, "connection reset")))
                } else if tcb.recv_eof() || tcb.state == State::Closed {
                    Poll::Ready(Ok(0)) // orderly EOF (peer FIN)
                } else {
                    s.read_wakers.insert(remote, cx.waker().clone());
                    Poll::Pending
                }
            }
        }
    }
}

pub struct Write<'a> {
    stream: &'a TcpStream,
    buf: &'a [u8],
}

impl Future for Write<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let remote = self.stream.remote;
        let mut s = self.stream.state.borrow_mut();
        match s.stack.connection_mut(&remote) {
            None => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "connection reset"))),
            Some(tcb) => {
                if tcb.is_reset() {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, "connection reset")));
                }
                if !matches!(tcb.state, State::Established | State::CloseWait) {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "not connected")));
                }
                let n = tcb.send(self.buf);
                if n > 0 {
                    Poll::Ready(Ok(n))
                } else {
                    s.write_wakers.insert(remote, cx.waker().clone());
                    Poll::Pending
                }
            }
        }
    }
}
