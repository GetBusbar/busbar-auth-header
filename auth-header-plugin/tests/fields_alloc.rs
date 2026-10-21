// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-REQUEST CALL ALLOCATES NOTHING OF THE PLUGIN'S OWN (THE DESIGN §11.2: "no allocation and
//! no blocking on the hot path"). A `fields` call is counted on its own thread, through the loader's
//! real call, in both credential modes over the same answer shape (`authorization: Bearer` + an
//! eleven-byte credential): the operator's own fields are staged by reference from the binding, and
//! the caller's are presented without a heap copy, so the caller's mode allocates no more than the
//! own mode does. What either mode still allocates is the SDK's (its zeroised staging of the
//! answer), the same in both.

#![allow(unsafe_code)] // the counting allocator: `GlobalAlloc` is an unsafe trait

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::mem::zeroed;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::auth::{
    slot, FieldSpan, FieldsIn, FieldsOut, OpenOutboundIn, OpenOutboundOut, RequestFacts, MODE_OWN,
    MODE_PASSTHROUGH,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Outcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, load_linked, out_head, Bind, Diagnostic, DispatchConfig, Dispatcher, Dropped,
    EnvelopeSink, Frame, LinkedRow, LoadedDoor, Metric, Plugin,
};

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<usize> = const { Cell::new(0) };
}

/// The system allocator, counting the allocations (and growths) made on a thread while it counts.
struct Counting;

fn count() {
    let _ = COUNTING.try_with(|on| {
        if on.get() {
            let _ = COUNT.try_with(|n| n.set(n.get() + 1));
        }
    });
}

// SAFETY: every call is forwarded to `System` unchanged; counting touches only const-initialised
// thread-locals, which never allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: forwarded as given.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded as given.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: forwarded as given.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();
        // SAFETY: forwarded as given.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// The allocations `f` makes on this thread.
fn allocations(f: impl FnOnce()) -> usize {
    COUNT.with(|n| n.set(0));
    COUNTING.with(|on| on.set(true));
    f();
    COUNTING.with(|on| on.set(false));
    COUNT.with(Cell::get)
}

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(b: &'static str) -> AbiStr {
    AbiStr::of(b)
}

fn blob(b: &'static str, fmt: u32, flags: u32) -> Blob {
    Blob::of(b.as_bytes()).with_fmt(fmt).with_flags(flags)
}

#[derive(Default)]
struct Sink(Mutex<usize>);

impl EnvelopeSink for Sink {
    fn metric(&self, _: Metric<'_>) {}
    fn diag(&self, _: Diagnostic<'_>) {
        *self.0.lock().unwrap() += 1;
    }
    fn dropped(&self, _: Dropped) {}
}

fn plugin(d: &Dispatcher) -> Plugin<Auth> {
    let bind = Bind {
        instance: Arc::from("alloc"),
        max_inflight_cap: 64,
        sink: Arc::new(Sink::default()),
        dispatcher: d.adopter(),
        conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
    };
    // SAFETY: `door` is this crate's own `auth_outbound_door!` entry: it answers the `'static`,
    // fully initialised door the SDK laid out.
    #[allow(unused_unsafe)]
    let loaded = unsafe { LoadedDoor::from_raw(busbar_auth_header::door) };
    let row = LinkedRow::of_loaded(loaded).expect("the door states its Statement");
    let p = load_linked::<Auth>(&row, bind).expect("the linked door loads");
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    o.input.generation = 1;
    assert_eq!(p.call(life::OPEN, &mut o).outcome, Outcome::Ready);
    p
}

fn open_bearer(p: &Plugin<Auth>, credential: &'static str) -> u64 {
    let mut f: Frame<OpenOutboundIn, OpenOutboundOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.style = s("bearer");
    f.input.credential = blob(credential, BLOB_OCTETS, BLOB_SECRET);
    f.input.settings = blob("{}", BLOB_JSON, 0);
    assert_eq!(p.call(slot::OPEN_OUTBOUND, &mut f).outcome, Outcome::Ready);
    f.out.handle
}

/// The host's buffers and frame for one `fields` call, built before counting starts.
struct Call {
    buf: Vec<u8>,
    spans: Vec<FieldSpan>,
    frame: Frame<FieldsIn, FieldsOut>,
}

impl Call {
    fn new(handle: u64, mode: u32, caller: Blob) -> Box<Self> {
        let mut c = Box::new(Call {
            buf: vec![0; 256],
            spans: vec![z(); 4],
            frame: Frame::new(z(), z()),
        });
        let f = &mut c.frame;
        f.input.head = in_head();
        f.out.head = out_head();
        f.input.handle = handle;
        f.input.mode = mode;
        f.input.request = RequestFacts {
            method: s("POST"),
            authority: s("api.example"),
            canonical_path: s("/v1/messages"),
            query: AbiStr::ABSENT,
            timestamp: 1_440_938_160,
        };
        f.input.caller_credential = caller;
        (f.input.field_buf, f.input.field_buf_cap) = (c.buf.as_mut_ptr(), c.buf.len());
        (f.input.fields, f.input.fields_cap) = (c.spans.as_mut_ptr(), c.spans.len() as u32);
        c
    }

    /// The answer's one field, as `name: value`.
    fn field(&self) -> String {
        assert_eq!(self.frame.out.fields_len, 1, "one field answered");
        let sp = self.spans[0];
        let at = |s: busbar_contract::abi::mechanism::call::Span| {
            String::from_utf8_lossy(&self.buf[s.offset as usize..(s.offset + s.len) as usize])
                .into_owned()
        };
        format!("{}: {}", at(sp.name), at(sp.value))
    }
}

/// `n` `fields` calls of `mode`, each counted; the answers read back.
fn counted(p: &Plugin<Auth>, handle: u64, mode: u32, caller: Blob, n: usize) -> (usize, String) {
    let mut total = 0;
    let mut field = String::new();
    for _ in 0..n {
        let mut call = Call::new(handle, mode, caller);
        total += allocations(|| {
            assert_eq!(
                p.call(slot::FIELDS, &mut call.frame).outcome,
                Outcome::Ready
            );
        });
        field = call.field();
    }
    (total, field)
}

#[test]
fn a_callers_credential_is_presented_with_no_allocation_beyond_the_own_modes() {
    let d = Dispatcher::new(DispatchConfig::default());
    let p = plugin(&d);
    let own = open_bearer(&p, "sk-test-123");
    let caller = blob("caller-tok1", BLOB_OCTETS, BLOB_SECRET);
    // Warm both paths once (lazily built host state is not the call's).
    let _ = counted(&p, own, MODE_OWN, z(), 1);
    let _ = counted(&p, own, MODE_PASSTHROUGH, caller, 1);

    let (own_allocs, own_field) = counted(&p, own, MODE_OWN, z(), 8);
    let (caller_allocs, caller_field) = counted(&p, own, MODE_PASSTHROUGH, caller, 8);
    assert_eq!(own_field, "authorization: Bearer sk-test-123");
    assert_eq!(caller_field, "authorization: Bearer caller-tok1");
    assert_eq!(
        caller_allocs, own_allocs,
        "presenting a caller's credential allocates per request beyond what the own mode does \
         (8 calls each)"
    );
}
