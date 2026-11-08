// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Compare allocations through the real loaded door in both credential modes. A caller's
//! borrowed credential must allocate no more than the own mode's sealed composition, which always
//! stages its field on the heap: an own count of zero means the counter saw nothing and fails the
//! test. The comparison is relative; it sets no absolute allocation bound.

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
    EnvelopeSink, Frame, LinkedRow, Metric, Plugin,
};

// Count only allocations made on the calling test thread while the fields call runs.
struct FieldsAllocator;
thread_local! {
    static ALLOCATIONS: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}
unsafe impl std::alloc::GlobalAlloc for FieldsAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| {
            if let Some(v) = n.get() {
                n.set(Some(v + 1));
            }
        });
        // SAFETY: forward the allocator's unchanged layout.
        unsafe { std::alloc::System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        // SAFETY: forward the pointer and original layout to the same allocator.
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOC: FieldsAllocator = FieldsAllocator;

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(b: &'static str) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn blob(b: &str, fmt: u32, flags: u32) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags,
    }
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
    let row = LinkedRow::of(busbar_auth_header::door).expect("the door states its Statement");
    let p = load_linked::<Auth>(&row, bind).expect("the linked door loads");
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    o.input.generation = 1;
    assert_eq!(p.call(life::OPEN, &mut o).outcome, Outcome::Ready);
    p
}

fn open_bearer(p: &Plugin<Auth>, credential: &str) -> u64 {
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
    fn new(handle: u64, mode: u32, caller: Blob, field_capacity: usize) -> Box<Self> {
        let mut c = Box::new(Call {
            buf: vec![0; field_capacity],
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
            query: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
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
fn counted(p: &Plugin<Auth>, handle: u64, mode: u32, caller: Blob, n: usize) -> (u64, String) {
    counted_with_capacity(p, handle, mode, caller, n, 256)
}

fn counted_with_capacity(
    p: &Plugin<Auth>,
    handle: u64,
    mode: u32,
    caller: Blob,
    n: usize,
    field_capacity: usize,
) -> (u64, String) {
    let mut total = 0;
    let mut field = String::new();
    for _ in 0..n {
        let mut call = Call::new(handle, mode, caller, field_capacity);
        ALLOCATIONS.with(|n| n.set(Some(0)));
        {
            assert_eq!(
                p.call(slot::FIELDS, &mut call.frame).outcome,
                Outcome::Ready
            );
        }
        total += ALLOCATIONS.with(|n| n.replace(None).unwrap());
        field = call.field();
    }
    (total, field)
}

/// The caller mode's count (8 calls) is at most the own mode's, and the own count is not zero: the
/// own mode stages its sealed field in a heap buffer on every call, so zero means nothing was
/// counted and the comparison would pass vacuously.
fn assert_no_allocation_beyond_own(caller_allocs: u64, own_allocs: u64) {
    assert!(
        own_allocs > 0,
        "the counting allocator saw no allocation in the own mode: nothing was counted"
    );
    assert!(
        caller_allocs <= own_allocs,
        "presenting a caller's credential allocates per request beyond what the own mode does \
         (8 calls each): caller={caller_allocs}, own={own_allocs}"
    );
}

#[test]
fn long_bearer_credentials_keep_the_wire_bytes_and_relative_allocation_contract() {
    let dispatcher = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let plugin = plugin(&dispatcher);
    let own_key = "o".repeat(2048);
    let caller_key = "c".repeat(2048);
    let handle = open_bearer(&plugin, &own_key);
    let caller = blob(&caller_key, BLOB_OCTETS, BLOB_SECRET);
    let own_expected = format!("authorization: Bearer {own_key}");
    let caller_expected = format!("authorization: Bearer {caller_key}");
    let capacity = own_expected.len().max(caller_expected.len());
    let _ = counted_with_capacity(&plugin, handle, MODE_OWN, z(), 1, capacity);
    let _ = counted_with_capacity(&plugin, handle, MODE_PASSTHROUGH, caller, 1, capacity);
    let (own_allocs, own_field) =
        counted_with_capacity(&plugin, handle, MODE_OWN, z(), 8, capacity);
    let (caller_allocs, caller_field) =
        counted_with_capacity(&plugin, handle, MODE_PASSTHROUGH, caller, 8, capacity);
    assert_eq!(own_field, own_expected);
    assert_eq!(caller_field, caller_expected);
    assert_no_allocation_beyond_own(caller_allocs, own_allocs);
}

#[test]
fn a_callers_credential_is_presented_with_no_allocation_beyond_the_own_modes() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let p = plugin(&d);
    let own = open_bearer(&p, "sk-test-123");
    let caller = blob("caller-tok1", BLOB_OCTETS, BLOB_SECRET);

    let _ = counted(&p, own, MODE_OWN, z(), 1);
    let _ = counted(&p, own, MODE_PASSTHROUGH, caller, 1);

    let (own_allocs, own_field) = counted(&p, own, MODE_OWN, z(), 8);
    let (caller_allocs, caller_field) = counted(&p, own, MODE_PASSTHROUGH, caller, 8);
    assert_eq!(own_field, "authorization: Bearer sk-test-123");
    assert_eq!(caller_field, "authorization: Bearer caller-tok1");
    assert_no_allocation_beyond_own(caller_allocs, own_allocs);
}
