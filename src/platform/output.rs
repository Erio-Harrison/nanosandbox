//! Bounded capture of a program's stdout/stderr. Past the limit output is still read (so the
//! program doesn't block) but dropped, and the result is marked truncated.

/// One stream's output.
pub(crate) struct Captured {
    data: Vec<u8>,
    limit: usize,
    truncated: bool,
}

impl Captured {
    pub(crate) fn new(limit: u64) -> Self {
        Self {
            data: Vec::new(),
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
            truncated: false,
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) {
        let room = self.limit - self.data.len();
        if bytes.len() > room {
            self.truncated = true;
        }
        self.data.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    pub(crate) fn truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) fn into_string(self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keeps_up_to_the_limit() {
        let mut out = Captured::new(5);
        out.push(b"abc");
        assert!(!out.truncated());
        out.push(b"defg");
        out.push(b"h");
        assert!(out.truncated());
        assert_eq!(out.into_string(), "abcde");
    }
}
