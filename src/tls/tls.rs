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

use {c, digest, hmac};

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
    pub fn encrypt(&self, blocks: &mut [u8], iv: &mut[u8]) -> Option<()> {
        if iv.len() != 16 ||
            blocks.len() % 16 != 0 {
            return None;
        }

        for block in blocks.chunks_mut(16) {
            xor16(iv, block);
            self.block(iv, block);
            copy16(iv, block);
        }

        Some(())
    }
}

/// nodocs
pub struct AESCBCHMACEncrypter {
    enc: AESEncrypt,
    mac: hmac::SigningKey,
}

impl AESCBCHMACEncrypter {
    /// Make a new AESCBCHMACEncrypter.
    /// `enc_key` is the AES key (either 16 or 32 bytes).
    /// `hmac_key` is the HMAC key, and `hmac_alg` is the underlying
    /// hash algorithm for HMAC.
    pub fn new(enc_key: &[u8], hmac_key: &[u8],
               hmac_alg: &'static digest::Algorithm) -> Option<AESCBCHMACEncrypter> {
        let aes_ctx = AESEncrypt::new(enc_key);
        aes_ctx.map(|enc| {
            AESCBCHMACEncrypter {
                enc: enc,
                mac: hmac::SigningKey::new(hmac_alg, hmac_key)
            }
        })
    }

    /// Encrypt the concatenation of `data`, `HMAC(header || data)` and
    /// enough padding to make up a whole block.  The ciphertext is
    /// writen to `out`, which must be a slice of at least `cipher_length()`
    /// bytes.
    ///
    /// `iv` is used for the encryption.  This function doesn't presuppose
    /// any particularly IV scheme; this must be done by the caller.  On
    /// exit, `iv` is updated with the next IV if inter-message chaining
    /// is being used.
    ///
    /// In TLS, `header` is the sequence number followed by the fragment
    /// header (type, version, length).
    pub fn encrypt(&self, header: &[u8], data: &[u8], iv: &mut [u8], out: &mut [u8]) {
        let mut sign_ctx = hmac::SigningContext::with_key(&self.mac);
        sign_ctx.update(header);
        sign_ctx.update(data);
        let hmac = sign_ctx.sign();

        let hmac_len = hmac.as_ref().len();

        out[..data.len()]
            .copy_from_slice(data);
        out[data.len()..data.len() + hmac_len]
            .copy_from_slice(hmac.as_ref());

        let total_len = data.len() + hmac_len;
        let pad_len = 15 - (total_len & 0xf);
        let ct_len = total_len + pad_len + 1;
        for i in 0..pad_len+1 {
            out[total_len + i] = pad_len as u8;
        }

        self.enc.encrypt(&mut out[..ct_len], iv).unwrap();
    }

    /// For a message of `data_len` bytes, returns the resulting fragment
    /// ciphertext that will be written by `encrypt`.
    pub fn cipher_length(&self, data_len: usize) -> usize {
        let hmac_len = self.mac.digest_algorithm().output_len;
        let total_len = data_len + hmac_len;
        let pad_len = 15 - (total_len & 0xf);
        total_len + pad_len + 1
    }
}

#[cfg(test)]
mod tests {


    #[test]
    fn test_aes_decrypt() {
        use super::AESDecrypt;
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
    fn test_aes_encrypt() {
        use super::AESEncrypt;
        let ctx = AESEncrypt::new(b"abcdabcdabcdabcd").unwrap();
        let mut cipher = [0u8; 80];
        cipher.copy_from_slice(b"hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello");
        let mut iv = [0x69, 0x76, 0x69, 0x76, 0x69, 0x76, 0x69, 0x76,
            0x69, 0x76, 0x69, 0x76, 0x69, 0x76, 0x69, 0x76];
        ctx.encrypt(&mut cipher, &mut iv).unwrap();
        assert_eq!(cipher.to_vec(),
                   b"\xfc\x4b\x81\x0b\x2b\x52\x30\xe2\x50\x7a\x25\x1e\x3d\x4f\x4e\xd3\x23\x26\x3a\x4a\x08\xed\x2c\xc2\x67\x3f\xbc\x2f\x95\x12\x31\x54\xa5\x69\x90\x82\xd6\x6f\x60\xfc\xee\x09\x6f\x4b\x69\x8d\xdc\x55\x1d\x35\x32\x79\x59\x73\x84\xdc\xee\x03\x16\x88\xf7\xce\x38\xb5\x93\x19\x99\x9f\xde\xda\x78\x3e\xab\xf0\xda\x06\x9b\xc6\x2b\x84".to_vec());
    }

    #[test]
    fn test_tls_encrypt() {
        use super::AESCBCHMACEncrypter;
        use digest;
        let ctx = AESCBCHMACEncrypter::new(b"key.key.key.key.",
                                           b"hmachmachmachmachmac",
                                           &digest::SHA1).unwrap();

        assert_eq!(ctx.cipher_length(0), 20 + 12);
        assert_eq!(ctx.cipher_length(1), 1 + 20 + 11);
        assert_eq!(ctx.cipher_length(4), 4 + 20 + 8);
        assert_eq!(ctx.cipher_length(8), 8 + 20 + 4);
        assert_eq!(ctx.cipher_length(11), 11 + 20 + 1);
        assert_eq!(ctx.cipher_length(12), 12 + 20 + 16);

        let mut iv = [0u8; 16];
        let mut ct = [0u8; 4 + 20 + 8];
        ctx.encrypt(b"header", b"data", &mut iv, &mut ct);
    }
}
