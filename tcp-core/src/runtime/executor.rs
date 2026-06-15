//! A minimal single-threaded async executor.
//!
//! Tasks are `!Send` futures (they hold `Rc` handles to the reactor) polled only on the
//! reactor thread. Wakers, however, must be `Send + Sync` to satisfy [`std::task::Wake`], so
//! the wake path touches only an `Arc<Mutex<Vec<usize>>>` "woken" queue — never the reactor
//! state. Building the `Waker` through the safe `Wake` trait is what keeps the whole crate
//! `#![deny(unsafe_code)]`; no hand-rolled `RawWaker` vtable is needed.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::sync::{Arc, Mutex};
use std::task::{Context, Wake, Waker};

type BoxFuture = Pin<Box<dyn Future<Output = ()>>>;

/// Pushes a task id onto the shared woken queue when woken.
struct TaskWaker {
    id: usize,
    woken: Arc<Mutex<Vec<usize>>>,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.woken.lock().unwrap().push(self.id);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.lock().unwrap().push(self.id);
    }
}

struct ExecInner {
    tasks: HashMap<usize, BoxFuture>,
    next_id: usize,
}

/// A cloneable handle for spawning new tasks (e.g. an accept loop spawning per-connection
/// handlers).
///
/// The back-reference to the executor is a [`Weak`], **not** an `Rc`: a spawned task (e.g. the
/// accept loop) commonly captures a `Spawner` and is itself stored in the executor, so a strong
/// reference here would close an `Rc` cycle (executor → task → `Spawner` → executor) that leaks
/// the executor and every task when the runtime is dropped. With a `Weak`, dropping the runtime
/// releases the executor, which drops its tasks, which drop their `Spawner`s — no cycle.
#[derive(Clone)]
pub struct Spawner {
    inner: Weak<RefCell<ExecInner>>,
    woken: Arc<Mutex<Vec<usize>>>,
}

impl Spawner {
    /// Spawn a task onto the executor. A no-op if the executor has already been dropped (the
    /// `Weak` no longer upgrades) — spawning onto a torn-down runtime cannot schedule anything.
    pub fn spawn(&self, fut: impl Future<Output = ()> + 'static) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let id = {
            let mut inner = inner.borrow_mut();
            let id = inner.next_id;
            inner.next_id += 1;
            inner.tasks.insert(id, Box::pin(fut));
            id
        };
        self.woken.lock().unwrap().push(id); // schedule the first poll
    }
}

pub struct Executor {
    inner: Rc<RefCell<ExecInner>>,
    woken: Arc<Mutex<Vec<usize>>>,
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

impl Executor {
    pub fn new() -> Self {
        Executor {
            inner: Rc::new(RefCell::new(ExecInner {
                tasks: HashMap::new(),
                next_id: 0,
            })),
            woken: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn spawner(&self) -> Spawner {
        Spawner {
            inner: Rc::downgrade(&self.inner),
            woken: self.woken.clone(),
        }
    }

    pub fn task_count(&self) -> usize {
        self.inner.borrow().tasks.len()
    }

    /// Poll every woken task, repeating until the woken queue drains (a task may wake itself
    /// or spawn others). The reactor state is NOT borrowed here, so polled tasks are free to
    /// borrow it.
    pub fn run_ready(&self) {
        loop {
            let ids: Vec<usize> = {
                let mut woken = self.woken.lock().unwrap();
                std::mem::take(&mut *woken)
            };
            if ids.is_empty() {
                break;
            }
            for id in ids {
                // Take the future out so the task can re-borrow the executor (spawn) freely.
                let fut = self.inner.borrow_mut().tasks.remove(&id);
                let Some(mut fut) = fut else { continue };
                let waker: Waker = Arc::new(TaskWaker {
                    id,
                    woken: self.woken.clone(),
                })
                .into();
                let mut cx = Context::from_waker(&waker);
                if fut.as_mut().poll(&mut cx).is_pending() {
                    self.inner.borrow_mut().tasks.insert(id, fut);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    #[test]
    fn runs_a_ready_task_to_completion() {
        let exec = Executor::new();
        let done = Rc::new(RefCell::new(false));
        let d = done.clone();
        exec.spawner().spawn(async move {
            *d.borrow_mut() = true;
        });
        assert_eq!(exec.task_count(), 1);
        exec.run_ready();
        assert!(*done.borrow());
        assert_eq!(exec.task_count(), 0);
    }

    #[test]
    fn a_task_can_spawn_another() {
        let exec = Executor::new();
        let spawner = exec.spawner();
        let count = Rc::new(RefCell::new(0));
        let c = count.clone();
        let sp = spawner.clone();
        spawner.spawn(async move {
            let c2 = c.clone();
            sp.spawn(async move {
                *c2.borrow_mut() += 1;
            });
            *c.borrow_mut() += 1;
        });
        exec.run_ready(); // outer task runs, spawns inner; loop picks up the inner one
        assert_eq!(*count.borrow(), 2);
    }
}
