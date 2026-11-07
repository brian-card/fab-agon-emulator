// Sampling profiler for NanoOs (scratch copy only, not for upstream).
//
// NANOOS_PROFILE=<path>: while <path>.on exists, count instructions, count
// arrivals at the addresses in NANOOS_PROFILE_CALLEES (comma-separated hex),
// and every 31 instructions record the IX frame chain as a folded stack.
// Frames in the 0xFFE000 overlay window carry a fingerprint of the loaded
// overlay.  When <path>.on goes away, write <path> (totals), <path>.stacks,
// and <path>.callees.
use std::collections::{HashMap, HashSet};
use std::io::Write;

pub struct Prof {
    pub path: Option<String>,
    pub on: bool,
    pub count: u64,
    pub tick: u32,
    pub samples: u64,
    pub stacks: HashMap<String, u64>,
    pub callees: HashMap<u32, u64>,
    pub callee_set: HashSet<u32>,
    pub crash: Option<String>,
    pub ring: Vec<(u32, u32)>,
    pub ring_i: usize,
    pub instr: u64,
    pub armed: bool,
    pub last_ovl: Option<Vec<String>>,
}

impl Prof {
    pub fn new() -> Prof {
        let path = std::env::var("NANOOS_PROFILE").ok();
        let mut callee_set = HashSet::new();
        if let Ok(list) = std::env::var("NANOOS_PROFILE_CALLEES") {
            for part in list.split(',') {
                if let Ok(a) = u32::from_str_radix(part.trim().trim_start_matches("0x"), 16) {
                    callee_set.insert(a);
                }
            }
        }
        let crash = std::env::var("NANOOS_CRASH").ok();
        let ring = if crash.is_some() { vec![(0, 0); 32768] } else { Vec::new() };
        Prof { path, on: false, count: 0, tick: 0, samples: 0,
               stacks: HashMap::new(), callees: HashMap::new(), callee_set,
               crash, ring, ring_i: 0, instr: 0, armed: false,
               last_ovl: if std::env::var("NANOOS_LASTOVL").is_ok() { Some(Vec::new()) } else { None } }
    }

    /// Called about once a millisecond: start or stop a window.
    pub fn poll(&mut self) -> bool {
        let Some(path) = self.path.clone() else { return false };
        let want = std::path::Path::new(&format!("{}.on", path)).exists();
        if want && !self.on {
            self.on = true;
            self.count = 0;
            self.tick = 0;
            self.samples = 0;
            self.stacks.clear();
            self.callees.clear();
        } else if !want && self.on {
            self.on = false;
            let mut f = std::fs::File::create(format!("{}.stacks", path)).unwrap();
            for (k, v) in &self.stacks {
                writeln!(f, "{} {}", k, v).unwrap();
            }
            let mut f = std::fs::File::create(format!("{}.callees", path)).unwrap();
            for (k, v) in &self.callees {
                writeln!(f, "{:06x} {}", k, v).unwrap();
            }
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "instructions {} samples {}", self.count, self.samples).unwrap();
            if let Some(v) = &self.last_ovl {
                let _ = std::fs::write(format!("{}.lastovl", path), v.join("\n"));
            }
            return true;
        }
        false
    }
}

impl Prof {
    /// Record an instruction for the reboot catcher; returns true when a
    /// running system has just jumped into the reset region.
    pub fn record(&mut self, pc: u32, sp: u32) -> bool {
        let n = self.ring.len();
        self.ring[self.ring_i] = (pc, sp);
        self.ring_i = (self.ring_i + 1) % n;
        self.instr += 1;
        if !self.armed {
            if self.instr > 50_000_000 && pc >= 0x100 {
                self.armed = true;
            }
            return false;
        }
        pc < 0x100
    }

    pub fn dump(&mut self, regs: String) {
        let path = self.crash.clone().unwrap();
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path).unwrap();
        writeln!(f, "=== reset after {} instructions; {}", self.instr, regs).unwrap();
        let n = self.ring.len();
        for k in 0..n {
            let (pc, sp) = self.ring[(self.ring_i + k) % n];
            writeln!(f, "{:06x} {:06x}", pc, sp).unwrap();
        }
        self.armed = false;
        self.instr = 0;
    }
}

thread_local! {
    pub static PROF: std::cell::RefCell<Prof> = std::cell::RefCell::new(Prof::new());
}
