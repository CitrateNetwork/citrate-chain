//! GHOSTDAG from headers (spec 06 §2 G3, G4, G6, G7), written from the spec
//! pseudocode and rusty-kaspa's `GhostdagManager`, not from the node's
//! `citrate_consensus::ghostdag`.
//!
//! Reachability is exact: every block's past is held as a bitset over a
//! topological index, so `a ∈ past(b)` is one bit test. That is quadratic in
//! memory and bounded by [`MAX_BLOCKS`].

use std::collections::{BTreeMap, HashMap, VecDeque};

use citrate_consensus::types::{Block, Hash};

/// One blue block weighs this much work (spec 06 G7).
pub const WORK_UNIT: u128 = 1_000_000;

/// The largest DAG the reference holds (reachability bitsets are N²/8 bytes:
/// 50,000 blocks is ~300 MB).
pub const MAX_BLOCKS: usize = 50_000;

/// The reference's GHOSTDAG record of one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub selected_parent: Option<Hash>,
    pub blue_score: u64,
    pub blue_work: u128,
    /// SP first, then the blue blocks of `Mergeset*` in coloring order.
    pub blues: Vec<Hash>,
    pub reds: Vec<Hash>,
    pub anticone_sizes: BTreeMap<Hash, u32>,
}

/// The fork-choice key `(blue_work, vrf_output, hash)` (spec 06 §1.1), with
/// the reference's OWN blue work.
pub type Key = (u128, [u8; 32], [u8; 32]);

/// The DAG as the reference sees it.
pub struct Dag<'a> {
    pub blocks: HashMap<Hash, &'a Block>,
    index: HashMap<Hash, usize>,
    order: Vec<Hash>,
    past: Vec<Vec<u64>>,
    pub records: HashMap<Hash, Record>,
}

fn parents(b: &Block) -> Vec<Hash> {
    let mut p = Vec::new();
    // A block above height 0 whose selected parent is the zero hash names the
    // genesis SENTINEL (a node whose store holds no genesis block, see
    // `crate::replay`), which the DAG then holds under the zero hash.
    if b.header.selected_parent_hash != Hash::default() || b.header.height > 0 {
        p.push(b.header.selected_parent_hash);
    }
    p.extend(b.header.merge_parent_hashes.iter().copied());
    p
}

impl<'a> Dag<'a> {
    /// Index `blocks` topologically and build reachability. Errors on a
    /// missing parent, a cycle, or more than [`MAX_BLOCKS`] blocks.
    pub fn new(blocks: &'a [Block]) -> Result<Self, String> {
        if blocks.len() > MAX_BLOCKS {
            return Err(format!(
                "{} blocks: the reference holds at most {MAX_BLOCKS}",
                blocks.len()
            ));
        }
        let map: HashMap<Hash, &Block> = blocks.iter().map(|b| (b.header.block_hash, b)).collect();
        // Kahn's algorithm over parent edges, ties by (height, hash) for a
        // deterministic order.
        let mut indeg: HashMap<Hash, usize> = HashMap::new();
        let mut children: HashMap<Hash, Vec<Hash>> = HashMap::new();
        for b in blocks {
            let ps = parents(b);
            for p in &ps {
                if !map.contains_key(p) {
                    return Err(format!(
                        "block {} names parent {p}, which is not in the DAG",
                        b.header.block_hash
                    ));
                }
                children.entry(*p).or_default().push(b.header.block_hash);
            }
            indeg.insert(b.header.block_hash, ps.len());
        }
        let mut ready: std::collections::BTreeSet<(u64, [u8; 32])> = blocks
            .iter()
            .filter(|b| indeg.get(&b.header.block_hash) == Some(&0))
            .map(|b| (b.header.height, *b.header.block_hash.as_bytes()))
            .collect();
        let mut order = Vec::with_capacity(blocks.len());
        while let Some(first) = ready.iter().next().copied() {
            ready.remove(&first);
            let h = Hash::new(first.1);
            order.push(h);
            for c in children.get(&h).cloned().unwrap_or_default() {
                let d = indeg.get_mut(&c).ok_or("indegree")?;
                *d -= 1;
                if *d == 0 {
                    let cb = map.get(&c).ok_or("child")?;
                    ready.insert((cb.header.height, *c.as_bytes()));
                }
            }
        }
        if order.len() != blocks.len() {
            return Err("the DAG has a cycle".into());
        }
        let index: HashMap<Hash, usize> = order.iter().enumerate().map(|(i, h)| (*h, i)).collect();
        let words = blocks.len().div_ceil(64);
        let mut past: Vec<Vec<u64>> = Vec::with_capacity(blocks.len());
        for h in &order {
            let b = map.get(h).ok_or("block")?;
            let mut bits = vec![0u64; words];
            for p in parents(b) {
                let pi = index[&p];
                for (w, pw) in bits.iter_mut().zip(past[pi].iter()) {
                    *w |= *pw;
                }
                bits[pi / 64] |= 1u64 << (pi % 64);
            }
            past.push(bits);
        }
        Ok(Self {
            blocks: map,
            index,
            order,
            past,
            records: HashMap::new(),
        })
    }

    /// `a ∈ past(b)`.
    pub fn in_past(&self, a: &Hash, b: &Hash) -> bool {
        match (self.index.get(a), self.index.get(b)) {
            (Some(&ai), Some(&bi)) => self.past[bi][ai / 64] & (1u64 << (ai % 64)) != 0,
            _ => false,
        }
    }

    /// The topological order the DAG was indexed in.
    pub fn topological(&self) -> &[Hash] {
        &self.order
    }

    /// The reference key of `h` (its record must exist).
    pub fn key(&self, h: &Hash) -> Key {
        let work = self.records.get(h).map(|r| r.blue_work).unwrap_or(0);
        let vrf = self
            .blocks
            .get(h)
            .map(|b| *b.header.vrf_reveal.output.as_bytes())
            .unwrap_or([0; 32]);
        (work, vrf, *h.as_bytes())
    }

    /// Color every block in topological order with `k`.
    pub fn color_all(&mut self, k: u32) -> Result<(), String> {
        let order = self.order.clone();
        for h in order {
            let rec = self.color(&h, k)?;
            self.records.insert(h, rec);
        }
        Ok(())
    }

    /// `Mergeset*(B)`: past(B) minus past(SP) minus SP, by BFS from the merge
    /// parents (spec 06 G4).
    pub fn mergeset_star(&self, b: &Hash, sp: &Hash) -> Vec<Hash> {
        let block = self.blocks[b];
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut q: VecDeque<Hash> = parents(block).into_iter().filter(|p| p != sp).collect();
        while let Some(x) = q.pop_front() {
            if x == *sp || self.in_past(&x, sp) || !seen.insert(x) {
                continue;
            }
            out.push(x);
            q.extend(parents(self.blocks[&x]));
        }
        out
    }

    fn color(&self, h: &Hash, k: u32) -> Result<Record, String> {
        let block = self.blocks[h];
        let ps = parents(block);
        if ps.is_empty() {
            return Ok(Record {
                selected_parent: None,
                blue_score: 0,
                blue_work: 0,
                blues: Vec::new(),
                reds: Vec::new(),
                anticone_sizes: BTreeMap::new(),
            });
        }
        // G3: the selected parent is the heaviest parent by key.
        let sp = ps
            .iter()
            .copied()
            .max_by_key(|p| self.key(p))
            .ok_or("no parent")?;
        let mut ms = self.mergeset_star(h, &sp);
        ms.sort_by_key(|x| self.key(x));
        let mut rec = Record {
            selected_parent: Some(sp),
            blue_score: 0,
            blue_work: 0,
            blues: vec![sp],
            reds: Vec::new(),
            anticone_sizes: BTreeMap::from([(sp, 0)]),
        };
        for c in ms {
            if let Some(updates) = self.blue_candidate(&rec, &c, k)? {
                rec.anticone_sizes.insert(c, updates.0);
                for (b, s) in updates.1 {
                    rec.anticone_sizes.insert(b, s + 1);
                }
                rec.blues.push(c);
            } else {
                rec.reds.push(c);
            }
        }
        let sp_rec = self.records.get(&sp).ok_or("selected parent uncolored")?;
        rec.blue_score = sp_rec.blue_score + rec.blues.len() as u64;
        rec.blue_work = sp_rec.blue_work + WORK_UNIT * rec.blues.len() as u128;
        Ok(rec)
    }

    /// Kaspa `check_blue_candidate`: `Some((|blue anticone of c|, updated
    /// sizes))` if `c` can be blue, `None` if red.
    fn blue_candidate(
        &self,
        new: &Record,
        c: &Hash,
        k: u32,
    ) -> Result<Option<BlueCandidate>, String> {
        if new.blues.len() as u64 == u64::from(k) + 1 {
            return Ok(None);
        }
        let mut sizes: Vec<(Hash, u32)> = Vec::new();
        let mut n: u32 = 0;
        let mut chain_hash: Option<Hash> = None;
        let mut chain_rec: &Record = new;
        loop {
            if let Some(ch) = chain_hash {
                if self.in_past(&ch, c) {
                    break;
                }
            }
            for b in &chain_rec.blues {
                if self.in_past(b, c) {
                    continue;
                }
                let s = self.blue_anticone_size(b, new)?;
                sizes.push((*b, s));
                n += 1;
                if n > k || s == k {
                    return Ok(None);
                }
            }
            let Some(next) = chain_rec.selected_parent else {
                break;
            };
            chain_hash = Some(next);
            chain_rec = self.records.get(&next).ok_or("chain record missing")?;
        }
        Ok(Some((n, sizes)))
    }

    /// The blue anticone size of blue `b` from `ctx`'s point of view: walk
    /// ctx's selected chain until a record holds it.
    fn blue_anticone_size(&self, b: &Hash, ctx: &Record) -> Result<u32, String> {
        let mut cur = ctx;
        loop {
            if let Some(s) = cur.anticone_sizes.get(b) {
                return Ok(*s);
            }
            let next = cur
                .selected_parent
                .ok_or_else(|| format!("blue {b} has no anticone size on the chain"))?;
            cur = self.records.get(&next).ok_or("chain record missing")?;
        }
    }

    /// Spec 06 §3.2: SP first, then `Mergeset*` (blues and reds) ascending by
    /// key, with `true` for blue.
    pub fn ordered_mergeset(&self, c: &Hash) -> Vec<(Hash, Color)> {
        let Some(rec) = self.records.get(c) else {
            return Vec::new();
        };
        let Some(sp) = rec.selected_parent else {
            return Vec::new();
        };
        let mut rest: Vec<(Key, Hash, Color)> = rec
            .blues
            .iter()
            .filter(|h| **h != sp)
            .map(|h| (self.key(h), *h, Color::Blue))
            .chain(rec.reds.iter().map(|h| (self.key(h), *h, Color::Red)))
            .collect();
        rest.sort_by_key(|x| x.0);
        let mut out = vec![(sp, Color::SelectedParent)];
        out.extend(rest.into_iter().map(|(_, h, c)| (h, c)));
        out
    }
}

/// A block's color relative to its accepting block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    SelectedParent,
    Blue,
    Red,
}

impl Color {
    pub fn is_blue(self) -> bool {
        !matches!(self, Self::Red)
    }
}

/// A blue candidate's anticone size and the blues whose anticone it joins,
/// each with its anticone size.
type BlueCandidate = (u32, Vec<(Hash, u32)>);
