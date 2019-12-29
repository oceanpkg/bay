use std::{fmt, io, mem, slice, str};

#[repr(transparent)]
pub struct LowerHexBytes<'a>(pub &'a [u8]);

impl fmt::Debug for LowerHexBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0 {
            fmt::LowerHex::fmt(byte, f)?;
        }
        Ok(())
    }
}

#[inline]
pub fn eq_hex(hash: &[u8], hex: &[u8]) -> bool {
    if hash.len().wrapping_mul(2) == hex.len() {
        // A cheap size check is inlined whereas the loop is not.
        unsafe { eq_hex_correct_size(hash, hex) }
    } else {
        false
    }
}

#[inline(never)]
unsafe fn eq_hex_correct_size(hash: &[u8], hex: &[u8]) -> bool {
    let hex_nibble = |n: u8| -> u8 {
        if n < 0xa {
            n + b'0'
        } else {
            n - 0xa + b'a'
        }
    };

    for i in 0..hash.len() {
        let byte = hash[i];
        let h1 = hex_nibble(byte >> 4);
        let h2 = hex_nibble(byte & 0xf);

        let i = i * 2;
        let ne1 = h1 ^ (32 | *hex.get_unchecked(i));
        let ne2 = h2 ^ (32 | *hex.get_unchecked(i));

        if ne1 | ne2 != 0 {
            return false;
        }
    }

    true
}

pub fn write_hex(
    hash: &[u8],
    uppercase: bool,
    writer: &mut dyn io::Write,
) -> io::Result<u64> {
    let uppercase = if uppercase { b'A' } else { b'a' };
    let hex_nibble = |n: u8| -> u8 {
        if n < 0xa {
            n + b'0'
        } else {
            n - 0xa + uppercase
        }
    };

    // Most hashes will be exactly the same size as a `HashBuf`.
    const BATCH_LIMIT: usize = mem::size_of::<super::HashBuf>();

    let mut hex_buf = [0u8; BATCH_LIMIT * 2];
    let mut hash = hash;
    let mut total = 0u64;

    loop {
        if hash.is_empty() {
            return Ok(total);
        }

        let hash = match hash.get(..BATCH_LIMIT) {
            Some(bytes) => {
                hash = &hash[BATCH_LIMIT..];
                bytes
            }
            None => {
                let old_hash = hash;
                hash = Default::default();
                old_hash
            }
        };

        let iter_len = hash.len();
        let hex_buf = unsafe { hex_buf.get_unchecked_mut(..(iter_len * 2)) };

        for i in 0..iter_len {
            let byte = hash[i];
            let h1 = hex_nibble(byte >> 4);
            let h2 = hex_nibble(byte & 0xf);

            let i = i * 2;
            unsafe {
                *hex_buf.get_unchecked_mut(i) = h1;
                *hex_buf.get_unchecked_mut(i + 1) = h2;
            }
        }

        writer.write_all(hex_buf)?;
        total += iter_len as u64;
    }
}

pub fn write_hex_buf<'b>(
    hash: &[u8],
    uppercase: bool,
    buf: &'b mut Vec<u8>,
) -> &'b mut str {
    let uppercase = if uppercase { b'A' } else { b'a' };
    let hex_nibble = |n: u8| -> u8 {
        if n < 0xa {
            n + b'0'
        } else {
            n - 0xa + uppercase
        }
    };

    let hex_len = hash.len() * 2;
    buf.reserve_exact(hex_len);

    let start_len = buf.len();
    let end_len = start_len + hex_len;

    // SAFETY: Because we're writing to potentially uninitialized memory, it
    // must be done behind a pointer.
    let hex_ptr = unsafe { buf.as_mut_ptr().add(start_len) };

    for i in 0..hash.len() {
        let byte = hash[i];
        let h1 = hex_nibble(byte >> 4);
        let h2 = hex_nibble(byte & 0xf);

        let i = i * 2;
        unsafe {
            *hex_ptr.add(i) = h1;
            *hex_ptr.add(i + 1) = h2;
        }
    }

    unsafe {
        buf.set_len(end_len);
        let hex = slice::from_raw_parts_mut(hex_ptr, hex_len);
        str::from_utf8_unchecked_mut(hex)
    }
}
