//! Bounds-checked byte cursors for fixed-layout encodings (PANIC-S1).
//!
//! The crypto envelopes here decode bytes read back from disk, so a truncated
//! or corrupt value must surface as an error, never an index panic (which would
//! crash-loop the node). Decoders used to check a length once and then re-slice
//! with hand-computed offsets, so correctness depended on the two staying in
//! sync. `Reader` keeps the bound and the field layout in one place: every read
//! either yields exactly the bytes asked for or `None`.

/// Sequential reader over a byte slice.
pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// The next `N` bytes as an array, or `None` if fewer remain.
    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, tail) = self.0.split_first_chunk::<N>()?;
        self.0 = tail;
        Some(*head)
    }

    /// The next byte, or `None` if none remain.
    pub(crate) fn u8(&mut self) -> Option<u8> {
        let (head, tail) = self.0.split_first()?;
        self.0 = tail;
        Some(*head)
    }

    /// The next `n` bytes, or `None` if fewer remain.
    pub(crate) fn slice(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(n)?;
        self.0 = tail;
        Some(head)
    }

    /// Everything not yet read.
    pub(crate) fn rest(&self) -> &'a [u8] {
        self.0
    }
}

/// Sequential writer into a fixed buffer. Writes past the end are dropped and
/// reported by `finish()` returning `false`; callers pair this with a
/// compile-time assertion that the field widths sum to the buffer size, so
/// that cannot happen.
pub(crate) struct Writer<'a> {
    rest: &'a mut [u8],
    overflowed: bool,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self {
            rest: buf,
            overflowed: false,
        }
    }

    pub(crate) fn put(&mut self, bytes: &[u8]) {
        let rest = std::mem::take(&mut self.rest);
        if let Some((head, tail)) = rest.split_at_mut_checked(bytes.len()) {
            head.copy_from_slice(bytes);
            self.rest = tail;
        } else {
            // Once a write overflows the result is invalid (`finish()` is false);
            // the remaining buffer is dropped, so later writes are no-ops.
            self.overflowed = true;
        }
    }

    /// `true` iff every write fit and the buffer is exactly full.
    pub(crate) fn finish(self) -> bool {
        !self.overflowed && self.rest.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_yields_exact_fields_then_none() {
        let mut r = Reader::new(&[1, 2, 3, 4, 5]);
        assert_eq!(r.u8(), Some(1));
        assert_eq!(r.array::<2>(), Some([2, 3]));
        assert_eq!(r.slice(3), None, "only 2 left");
        assert_eq!(r.slice(2), Some(&[4u8, 5][..]));
        assert_eq!(r.u8(), None);
        assert!(r.rest().is_empty());
    }

    #[test]
    fn writer_reports_overflow_and_underfill() {
        let mut buf = [0u8; 3];
        let mut w = Writer::new(&mut buf);
        w.put(&[9, 8]);
        w.put(&[7]);
        assert!(w.finish());
        assert_eq!(buf, [9, 8, 7]);

        let mut buf = [0u8; 2];
        let mut w = Writer::new(&mut buf);
        w.put(&[1, 2, 3]);
        assert!(!w.finish(), "overflow is reported, not panicked");

        let mut buf = [0u8; 3];
        let mut w = Writer::new(&mut buf);
        w.put(&[1]);
        assert!(!w.finish(), "underfill is reported");
    }
}
