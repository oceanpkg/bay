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
