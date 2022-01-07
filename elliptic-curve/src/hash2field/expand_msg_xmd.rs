use core::marker::PhantomData;

use super::{Domain, ExpandMsg};
use crate::{Error, Result};
use digest::core_api::{Block, BlockSizeUser};
use digest::{Digest, Output, Update};
use generic_array::typenum::{IsLessOrEqual, Unsigned, U256};
use generic_array::GenericArray;
use subtle::{Choice, ConditionallySelectable};

/// Placeholder type for implementing expand_message_xmd based on a hash function
pub struct ExpandMsgXmd<HashT>(PhantomData<HashT>)
where
    HashT: Digest + BlockSizeUser + Update,
    HashT::OutputSize: IsLessOrEqual<U256>,
    HashT::OutputSize: IsLessOrEqual<HashT::BlockSize>;

/// ExpandMsgXmd implements expand_message_xmd for the ExpandMsg trait
impl<HashT> ExpandMsg for ExpandMsgXmd<HashT>
where
    HashT: Digest + BlockSizeUser,
    // If `len_in_bytes` is bigger then 256, length of the `DST` will depend on
    // the output size of the hash, which is still not allowed to be bigger then 256:
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-5.4.1-6
    HashT::OutputSize: IsLessOrEqual<U256>,
    // Constraint set by `expand_message_xmd`:
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-5.4.1-4
    HashT::OutputSize: IsLessOrEqual<HashT::BlockSize>,
{
    fn expand_message<const L: u16>(msg: &[u8], dst: &[u8]) -> Result<[u8; L]> {
        let b_in_bytes = HashT::OutputSize::to_u32();
        if L == 0 {
            return Err(Error);
        }
        let ell = u8::try_from((u32::from(L) + b_in_bytes - 1) / b_in_bytes).map_err(|_| Error)?;

        let domain = Domain::xmd::<HashT>(dst);
        let b_0 = HashT::new()
            .chain(Block::<HashT>::default())
            .chain(msg)
            .chain(L.to_be_bytes())
            .chain([0])
            .chain(domain.data())
            .chain([domain.len()])
            .finalize();

        let mut b_vals = HashT::new()
            .chain(&b_0[..])
            .chain([1u8])
            .chain(domain.data())
            .chain([domain.len()])
            .finalize();

        let mut buf = GenericArray::<_, L>::default();
        let mut offset = 0;

        for i in 1..ell {
            // b_0 XOR b_(idx - 1)
            let tmp: Output<HashT> = b_0
                .iter()
                .zip(b_vals.as_slice())
                .map(|(b0val, bi1val)| b0val ^ bi1val)
                .collect();
            for b in b_vals {
                buf[offset % L]
                    .conditional_assign(&b, Choice::from(if offset < L { 1 } else { 0 }));
                offset += 1;
            }
            b_vals = HashT::new()
                .chain(tmp)
                .chain([i + 1])
                .chain(domain.data())
                .chain([domain.len()])
                .finalize();
        }
        for b in b_vals {
            buf[offset % L].conditional_assign(&b, Choice::from(if offset < L { 1 } else { 0 }));
            offset += 1;
        }
        buf
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::mem;

    struct Message<'a, HashT, const L: u16>
    where
        HashT: Digest + BlockSizeUser,
        HashT::OutputSize: IsLessOrEqual<U256>,
    {
        msg: &'a [u8],
        domain: &'a Domain<'a, HashT::OutputSize>,
    }

    impl<'a, HashT, const L: u16> Message<'a, HashT, L>
    where
        HashT: Digest + BlockSizeUser,
        HashT::OutputSize: IsLessOrEqual<U256>,
    {
        fn new(msg: &'a [u8], domain: &'a Domain<'a, HashT::OutputSize>) -> Self {
            Self { msg, domain }
        }

        fn assert(&self, bytes: &[u8]) {
            let block = HashT::BlockSize::to_usize();
            assert_eq!(Block::<HashT>::default().as_slice(), &bytes[..block]);

            let msg = block + self.msg.len();
            assert_eq!(self.msg, &bytes[block..msg]);

            let l = msg + mem::size_of::<u16>();
            assert_eq!(L.to_be_bytes(), &bytes[msg..l]);

            let pad = l + mem::size_of::<u8>();
            assert_eq!([0], &bytes[l..pad]);

            let domain = pad + self.domain.data().len();
            assert_eq!(self.domain.data(), &bytes[pad..domain]);

            let domain_len = domain + mem::size_of::<u8>();
            assert_eq!([self.domain.len()], &bytes[domain..domain_len]);

            assert_eq!(domain_len, bytes.len());
        }
    }

    struct TestVector {
        msg: &'static [u8],
        msg_prime: &'static [u8],
        uniform_bytes: &'static [u8],
    }

    #[test]
    fn expand_message_xmd_sha_256() {
        use generic_array::typenum::U32;
        use hex_literal::hex;
        use sha2::Sha256;

        const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";
        const DST_PRIME: &[u8] =
            &hex!("515555582d5630312d435330322d776974682d657870616e6465722d5348413235362d31323826");

        let dst_prime = Domain::xmd::<Sha256>(DST);
        dst_prime.assert(DST_PRIME);

        const TEST_VECTORS_32: &[TestVector] = &[TestVector {
            msg: b"",
            msg_prime: &hex!("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000515555582d5630312d435330322d776974682d657870616e6465722d5348413235362d31323826"),
            uniform_bytes: &hex!("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"),
        }];

        for test_vector in TEST_VECTORS_32 {
            let msg_prime = Message::<Sha256, U32>::new(test_vector.msg, &dst_prime);
            msg_prime.assert(test_vector.msg_prime);

            let uniform_bytes =
                <ExpandMsgXmd<Sha256> as ExpandMsg<U32>>::expand_message(test_vector.msg, DST);
            assert_eq!(uniform_bytes.as_slice(), test_vector.uniform_bytes,);
        }
    }
}
