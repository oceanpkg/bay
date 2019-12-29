use std::fmt;

#[repr(transparent)]
pub struct HexByte(pub u8);

impl fmt::Debug for HexByte {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl HexByte {
    #[inline]
    pub fn slice(bytes: &[u8]) -> &[HexByte] {
        unsafe { &*(bytes as *const _ as *const _) }
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
