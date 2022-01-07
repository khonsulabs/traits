use core::marker::PhantomData;

use super::ExpandMsg;
use crate::hash2field::Domain;
use crate::{Error, Result};
use digest::{ExtendableOutput, XofReader};
use generic_array::typenum::U32;
use generic_array::GenericArray;

/// Placeholder type for implementing expand_message_xof based on an extendable output function
pub struct ExpandMsgXof<HashT>(PhantomData<HashT>)
where
    HashT: Default + ExtendableOutput;

/// ExpandMsgXof implements expand_message_xof for the ExpandMsg trait
impl<HashT> ExpandMsg for ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput,
{
    fn expand_message< const L: u16>(msg: &[u8], dst: &[u8]) -> Result<[u8; L]> {
        if L == 0 {
            return Err(Error);
        }

        let domain = Domain::<U32>::xof::<HashT>(dst);
        let mut reader = HashT::default()
            .chain(msg)
            .chain(L.to_be_bytes())
            .chain(domain.data())
            .chain([domain.len()])
            .finalize_xof();
        let mut buf = GenericArray::default();
        reader.read(&mut buf);
        buf
    }
}

#[test]
fn expand_message_xmd_shake_128() {
    use generic_array::typenum::U32;
    use hex_literal::hex;
    use sha3::Shake128;

    const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHAKE128";

    let dst_prime = Domain::<U32>::xof::<Shake128>(DST);
    let test_dst_prime =
        hex!("515555582d5630312d435330322d776974682d657870616e6465722d5348414b4531323824");
    assert_eq!(
        dst_prime.data(),
        &test_dst_prime[..test_dst_prime.len() - 1]
    );
    assert_eq!(dst_prime.len(), test_dst_prime[test_dst_prime.len() - 1]);

    let uniform_bytes = <ExpandMsgXof<Shake128> as ExpandMsg<U32>>::expand_message(b"", DST);
    assert_eq!(
        uniform_bytes.as_slice(),
        hex!("86518c9cd86581486e9485aa74ab35ba150d1c75c88e26b7043e44e2acd735a2")
    );
}
