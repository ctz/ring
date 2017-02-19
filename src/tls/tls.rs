// Copyright 2017 Joseph Birr-Pixton.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! TLS-specific cryptography.
//!
//! This implements assorted TLS-specific mechanisms:
//!
//! - The TLS1.0 PRF
//! - The TLS1.2 PRF
//! - The TLS1.0 AES-CBC+HMAC construction, modelled as a two-key pseudo-AEAD.

//use {constant_time, c, digest, error, hmac, aead, polyfill};
use c;

// ensure that an AESContext is big enough to fit an AES_KEY.
const AES_CTX_LEN: usize = 31;
#[repr(C)]
struct AESContext([u64; AES_CTX_LEN]);

/// nodocs
pub struct AESDecrypt {
    ctx: AESContext,
}

/// nodocs
pub struct AESEncrypt {
    ctx: AESContext,
}

fn copy16(out: &mut [u8], val: &[u8]) {
    for i in 0..16 {
        out[i] = val[i];
    }
}

fn xor16(accum: &mut [u8], offs: &[u8]) {
    for i in 0..16 {
        accum[i] ^= offs[i];
    }
}

impl AESDecrypt {
    /// nodocs
    pub fn new(key: &[u8]) -> Option<AESDecrypt> {
        let mut r = AESDecrypt { ctx: AESContext([0u64; AES_CTX_LEN]) };
        let rc = unsafe {
            GFp_AES_set_decrypt_key(key.as_ptr(), key.len() * 8,
                                    &mut r.ctx)
        };

        if rc == 0 {
            Some(r)
        } else {
            None
        }
    }

    fn block(&self, block_in: &[u8], block_out: &mut [u8]) {
        unsafe {
            GFp_AES_decrypt(block_in.as_ptr(),
                            block_out.as_mut_ptr(),
                            &self.ctx)
        };
    }

    /// nodocs
    pub fn decrypt(&self, iv: &mut [u8], blocks_in: &[u8], blocks_out: &mut [u8]) -> Option<()> {
        if iv.len() != 16 ||
            blocks_in.len() != blocks_out.len() ||
            blocks_in.len() % 16 != 0 {
            return None;
        }

        let mut i = 0;
        let mut next_iv = [0u8; 16];
        while i < blocks_in.len() {
            copy16(&mut next_iv, &blocks_in[i..i+16]);
            self.block(&blocks_in[i..i+16], &mut blocks_out[i..i+16]);
            xor16(&mut blocks_out[i..i+16], iv);
            copy16(iv, &next_iv);
            i += 16;
        }

        Some(())
    }
}

extern "C" {
    fn GFp_AES_set_decrypt_key(key: *const u8, bits: usize,
                               aes_key: *mut AESContext) -> c::int;
    fn GFp_AES_decrypt(in_: *const u8, out: *mut u8, key: *const AESContext);
    fn GFp_AES_set_encrypt_key(key: *const u8, bits: usize,
                               aes_key: *mut AESContext) -> c::int;
    fn GFp_AES_encrypt(in_: *const u8, out: *mut u8, key: *const AESContext);
}

impl AESEncrypt {
    /// nodocs
    pub fn new(key: &[u8]) -> Option<AESEncrypt> {
        let mut r = AESEncrypt { ctx: AESContext([0u64; AES_CTX_LEN]) };
        let rc = unsafe {
            GFp_AES_set_encrypt_key(key.as_ptr(), key.len() * 8,
                                    &mut r.ctx)
        };

        if rc == 0 {
            Some(r)
        } else {
            None
        }
    }

    fn block(&self, block_in: &[u8], block_out: &mut [u8]) {
        unsafe {
            GFp_AES_encrypt(block_in.as_ptr(),
                            block_out.as_mut_ptr(),
                            &self.ctx);
        };
    }

    /// nodocs
    pub fn encrypt(&self, iv: &mut [u8], blocks_in: &[u8], blocks_out: &mut [u8]) -> Option<()> {
        if iv.len() != 16 ||
            blocks_in.len() != blocks_out.len() ||
            blocks_in.len() % 16 != 0 {
            return None;
        }

        let mut i = 0;
        while i < blocks_in.len() {
            xor16(iv, &blocks_in[i..i+16]);
            self.block(iv, &mut blocks_out[i..i+16]);
            copy16(iv, &mut blocks_out[i..i+16]);
            i += 16;
        }

        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::AESDecrypt;
    use super::AESEncrypt;

    #[test]
    fn test_decrypt() {
        let ctx = AESDecrypt::new(b"abcdabcdabcdabcd").unwrap();
        let mut plain = [0u8; 80];
        let mut iv = [0x69, 0x76, 0x69, 0x76, 0x69, 0x76, 0x69, 0x76,
            0x69, 0x76, 0x69, 0x76, 0x69, 0x76, 0x69, 0x76];
        ctx.decrypt(&mut iv,
                    b"\xfc\x4b\x81\x0b\x2b\x52\x30\xe2\x50\x7a\x25\x1e\x3d\x4f\x4e\xd3\x23\x26\x3a\x4a\x08\xed\x2c\xc2\x67\x3f\xbc\x2f\x95\x12\x31\x54\xa5\x69\x90\x82\xd6\x6f\x60\xfc\xee\x09\x6f\x4b\x69\x8d\xdc\x55\x1d\x35\x32\x79\x59\x73\x84\xdc\xee\x03\x16\x88\xf7\xce\x38\xb5\x93\x19\x99\x9f\xde\xda\x78\x3e\xab\xf0\xda\x06\x9b\xc6\x2b\x84",
                    &mut plain).unwrap();
        assert_eq!(plain.to_vec(),
                   b"hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello".to_vec());
    }

    #[test]
    fn test_encrypt() {
        let ctx = AESEncrypt::new(b"abcdabcdabcdabcd").unwrap();
        let mut cipher = [0u8; 80];
        let mut iv = [0x69, 0x76, 0x69, 0x76, 0x69, 0x76, 0x69, 0x76,
            0x69, 0x76, 0x69, 0x76, 0x69, 0x76, 0x69, 0x76];
        ctx.encrypt(&mut iv,
                    b"hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello",
                    &mut cipher).unwrap();
        assert_eq!(cipher.to_vec(),
                   b"\xfc\x4b\x81\x0b\x2b\x52\x30\xe2\x50\x7a\x25\x1e\x3d\x4f\x4e\xd3\x23\x26\x3a\x4a\x08\xed\x2c\xc2\x67\x3f\xbc\x2f\x95\x12\x31\x54\xa5\x69\x90\x82\xd6\x6f\x60\xfc\xee\x09\x6f\x4b\x69\x8d\xdc\x55\x1d\x35\x32\x79\x59\x73\x84\xdc\xee\x03\x16\x88\xf7\xce\x38\xb5\x93\x19\x99\x9f\xde\xda\x78\x3e\xab\xf0\xda\x06\x9b\xc6\x2b\x84".to_vec());
    }

}
