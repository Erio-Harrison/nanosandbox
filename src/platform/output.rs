//! Collecting a sandboxed program's stdout or stderr, up to a limit.
//!
//! The output is kept in this process's memory, so a program printing
//! forever mustn't be able to fill it. Past the limit, output is still read,
//! so the program doesn't block writing it, but dropped, and the result says
//! it was truncated. Killing the program instead would fail one that just
//! logs a lot; not reading would leave it hanging until its time limit.

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

    /// Keeps what fits under the limit, drops the rest.
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

    /// The output as text, invalid UTF-8 replaced.
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
