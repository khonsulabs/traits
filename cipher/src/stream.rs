//! Traits which define functionality of stream ciphers.
//!
//! See [RustCrypto/stream-ciphers](https://github.com/RustCrypto/stream-ciphers)
//! for ciphers implementation.

use crate::errors::{OverflowError, StreamCipherError};
use crate::stream_core::Counter;
use crate::{Block, BlockDecryptMut, BlockEncryptMut};
use block_buffer::inout::InOutBuf;

/// Marker trait for block-level asynchronous stream ciphers
pub trait AsyncStreamCipher: BlockEncryptMut + BlockDecryptMut + Sized {
    /// Encrypt data using `InOutBuf`.
    fn encrypt_inout(mut self, data: InOutBuf<'_, u8>) {
        let (blocks, tail) = data.into_chunks();
        self.encrypt_blocks_inout_mut(blocks, |_| {});
        let mut block = Block::<Self>::default();
        let n = tail.len();
        block[..n].copy_from_slice(tail.get_in());
        self.encrypt_block_mut(&mut block);
        tail.get_out().copy_from_slice(&block[..n]);
    }

    /// Decrypt data using `InOutBuf`.
    fn decrypt_inout(mut self, data: InOutBuf<'_, u8>) {
        let (blocks, tail) = data.into_chunks();
        self.decrypt_blocks_inout_mut(blocks, |_| {});
        let mut block = Block::<Self>::default();
        let n = tail.len();
        block[..n].copy_from_slice(tail.get_in());
        self.decrypt_block_mut(&mut block);
        tail.get_out().copy_from_slice(&block[..n]);
    }

    /// Encrypt data in place.
    fn encrypt(self, buf: &mut [u8]) {
        self.encrypt_inout(buf.into());
    }

    /// Decrypt data in place.
    fn decrypt(self, buf: &mut [u8]) {
        self.decrypt_inout(buf.into());
    }
}

/// Synchronous stream cipher core trait.
pub trait StreamCipher {
    /// Apply keystream to data behind `buf` and return explicit result.
    ///
    /// If end of the keystream will be achieved with the given data length,
    /// method will return [`StreamCipherError`] without modifying provided `data`.
    fn try_apply_keystream(&mut self, buf: InOutBuf<'_, u8>) -> Result<(), StreamCipherError>;

    /// Apply keystream to `inout` data.
    ///
    /// It will XOR generated keystream with the data behind `in` pointer
    /// and will write result to `out` pointer.
    ///
    /// # Panics
    /// If end of the keystream will be reached with the given data length,
    /// method will panic without modifying the provided `data`.
    #[inline]
    fn apply_keystream_inout(&mut self, buf: InOutBuf<'_, u8>) {
        self.try_apply_keystream(buf).unwrap();
    }

    /// Apply keystream to data in-place.
    ///
    /// It will XOR generated keystream with `data` and will write result
    /// to the same buffer.
    ///
    /// # Panics
    /// If end of the keystream will be reached with the given data length,
    /// method will panic without modifying the provided `data`.
    #[inline]
    fn apply_keystream(&mut self, buf: &mut [u8]) {
        self.try_apply_keystream(buf.into()).unwrap();
    }

    /// Apply keystream to data buffer-to-buffer.
    ///
    /// It will XOR generated keystream with data from the `input` buffer
    /// and will write result to the `output` buffer.
    ///
    /// Returns [`StreamCipherError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths or if end of the keystream will be reached with
    /// the given input data length.
    #[inline]
    fn apply_keystream_b2b(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), StreamCipherError> {
        InOutBuf::new(input, output)
            .map_err(|_| StreamCipherError)
            .and_then(|buf| self.try_apply_keystream(buf))
    }
}

/// Trait for seekable stream ciphers.
///
/// Methods of this trait are generic over the [`SeekNum`] trait, which is
/// implemented for primitive numeric types, i.e.: `i32`, `u32`, `u64`,
/// `u128`, and `usize`.
pub trait StreamCipherSeek {
    /// Try to get current keystream position
    ///
    /// Returns [`StreamCipherError`] if position can not be represented by type `T`
    fn try_current_pos<T: SeekNum>(&self) -> Result<T, OverflowError>;

    /// Try to seek to the given position
    ///
    /// Returns [`StreamCipherError`] if provided position value is bigger than
    /// keystream length.
    fn try_seek<T: SeekNum>(&mut self, pos: T) -> Result<(), StreamCipherError>;

    /// Get current keystream position
    ///
    /// # Panics
    /// If position can not be represented by type `T`
    fn current_pos<T: SeekNum>(&self) -> T {
        self.try_current_pos().unwrap()
    }

    /// Seek to the given position
    ///
    /// # Panics
    /// If provided position value is bigger than keystream leangth
    fn seek<T: SeekNum>(&mut self, pos: T) {
        self.try_seek(pos).unwrap()
    }
}

impl<C: StreamCipher> StreamCipher for &mut C {
    #[inline]
    fn apply_keystream_inout(&mut self, buf: InOutBuf<'_, u8>) {
        C::apply_keystream_inout(self, buf);
    }

    #[inline]
    fn try_apply_keystream(&mut self, buf: InOutBuf<'_, u8>) -> Result<(), StreamCipherError> {
        C::try_apply_keystream(self, buf)
    }
}

/// Trait implemented for numeric types which can be used with the
/// [`StreamCipherSeek`] trait.
///
/// This trait is implemented for `i32`, `u32`, `u64`, `u128`, and `usize`.
/// It is not intended to be implemented in third-party crates.
pub trait SeekNum: Sized {
    /// Try to get position for block number `block`, byte position inside
    /// block `byte`, and block size `bs`.
    fn from_block_byte<T: Counter>(block: T, byte: usize, bs: usize)
        -> Result<Self, OverflowError>;

    /// Try to get block number and bytes position for given block size `bs`.
    fn into_block_byte<T: Counter>(self, bs: usize) -> Result<(T, usize), OverflowError>;
}

macro_rules! impl_seek_num {
    {$($t:ty )*} => {
        $(
            impl SeekNum for $t {
                fn from_block_byte<T: Counter>(block: T, byte: usize, bs: usize) -> Result<Self, OverflowError> {
                    debug_assert!(byte < bs);
                    let mut block: Self = block.try_into().map_err(|_| OverflowError)?;
                    if byte != 0 {
                        block -= 1;
                    }
                    let pos = block.checked_mul(bs as Self).ok_or(OverflowError)? + (byte as Self);
                    Ok(pos)
                }

                fn into_block_byte<T: Counter>(self, bs: usize) -> Result<(T, usize), OverflowError> {
                    let bs = bs as Self;
                    let byte = self % bs;
                    let block = T::try_from(self/bs).map_err(|_| OverflowError)?;
                    Ok((block, byte as usize))
                }
            }
        )*
    };
}

impl_seek_num! { i32 u32 u64 u128 usize }
