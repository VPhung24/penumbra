use std::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Formatter},
};

use anyhow::anyhow;

use crate::{
    balance, ka,
    keys::OutgoingViewingKey,
    note,
    symmetric::{OvkWrappedKey, PayloadKey, PayloadKind, WrappedMemoKey},
    Note,
};

pub const MEMO_CIPHERTEXT_LEN_BYTES: usize = 528;

// This is the `MEMO_CIPHERTEXT_LEN_BYTES` - MAC size (16 bytes).
pub const MEMO_LEN_BYTES: usize = 512;

// The memo is stored separately from the `Note`.
// TODO: MemoPlaintext should just be a fixed-length string, drop this type entirely
#[derive(Clone, PartialEq, Eq)]
pub struct MemoPlaintext(pub String);

impl Debug for MemoPlaintext {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "MemoPlaintext({})", hex::encode(&self.0))
    }
}

impl Default for MemoPlaintext {
    fn default() -> MemoPlaintext {
        MemoPlaintext(String::new())
    }
}

impl TryFrom<&[u8]> for MemoPlaintext {
    type Error = anyhow::Error;

    fn try_from(input: &[u8]) -> Result<MemoPlaintext, Self::Error> {
        if input.len() > MEMO_LEN_BYTES {
            return Err(anyhow::anyhow!("provided memo exceeds maximum memo size"));
        }
        let s: String = input.into_iter().map(|i| i.to_string()).collect::<String>();
        Ok(MemoPlaintext(s))
    }
}

impl From<[u8; MEMO_LEN_BYTES]> for MemoPlaintext {
    fn from(input: [u8; MEMO_LEN_BYTES]) -> MemoPlaintext {
        let no_pad = MemoPlaintext::strip_padding(input);
        let s: String = String::from_utf8_lossy(&no_pad).to_string();
        println!("Behold the string: {:?}", s);
        MemoPlaintext(s)
    }
}

#[derive(Clone, Debug)]
pub struct MemoCiphertext(pub [u8; MEMO_CIPHERTEXT_LEN_BYTES]);

impl MemoPlaintext {
    /// Encrypt a memo, returning its ciphertext.
    pub fn encrypt(&self, memo_key: PayloadKey) -> MemoCiphertext {
        let encryption_result = memo_key.encrypt(self.as_bytes().to_vec(), PayloadKind::Memo);
        let ciphertext: [u8; MEMO_CIPHERTEXT_LEN_BYTES] = encryption_result
            .try_into()
            .expect("memo encryption result fits in ciphertext len");

        MemoCiphertext(ciphertext)
    }

    /// Decrypt a `MemoCiphertext` to generate a plaintext `Memo`.
    pub fn decrypt(
        ciphertext: MemoCiphertext,
        memo_key: &PayloadKey,
    ) -> Result<MemoPlaintext, anyhow::Error> {
        let encryption_result = memo_key
            .decrypt(ciphertext.0.to_vec(), PayloadKind::Memo)
            .map_err(|_| anyhow!("decryption error"))?;
        let plaintext_bytes: [u8; MEMO_LEN_BYTES] = encryption_result
            .try_into()
            .map_err(|_| anyhow!("could not fit plaintext into memo size"))?;

        // Strip zero-byte padding
        let no_pad: Vec<u8> = MemoPlaintext::strip_padding(plaintext_bytes);
        let plaintext_str = String::from_utf8_lossy(no_pad.as_slice());
        Ok(MemoPlaintext(plaintext_str.to_string()))
    }

    /// Removes zero-byte padding from a slice of bytes
    pub fn strip_padding(input: [u8; MEMO_LEN_BYTES]) -> Vec<u8> {
        // TODO: Make this less naive; should only strip trailing contiguous zero-bytes.
        let result: Vec<u8> = input.into_iter().filter(|&x| x != 0u8).collect();
        result
    }

    /// Decrypt a `MemoCiphertext` using the wrapped OVK to generate a plaintext `Memo`.
    pub fn decrypt_outgoing(
        ciphertext: MemoCiphertext,
        wrapped_ovk: OvkWrappedKey,
        cm: note::Commitment,
        cv: balance::Commitment,
        ovk: &OutgoingViewingKey,
        epk: &ka::Public,
        wrapped_memo_key: &WrappedMemoKey,
    ) -> Result<MemoPlaintext, anyhow::Error> {
        let shared_secret = Note::decrypt_key(wrapped_ovk, cm, cv, ovk, epk)
            .map_err(|_| anyhow!("key decryption error"))?;

        let action_key = PayloadKey::derive(&shared_secret, epk);
        let memo_key = wrapped_memo_key
            .decrypt_outgoing(&action_key)
            .map_err(|_| anyhow!("could not decrypt wrapped memo key"))?;

        let plaintext = memo_key
            .decrypt(ciphertext.0.to_vec(), PayloadKind::Memo)
            .map_err(|_| anyhow!("decryption error"))?;

        let plaintext_bytes: [u8; MEMO_LEN_BYTES] = plaintext
            .try_into()
            .map_err(|_| anyhow!("could not fit plaintext into memo size"))?;

        let no_pad = MemoPlaintext::strip_padding(plaintext_bytes);
        let plaintext_str = String::from_utf8_lossy(no_pad.as_slice());

        Ok(MemoPlaintext(plaintext_str.to_string()))
    }

    /// Provide a custom bytes representation, ensuring that we always pad to exactly MEMO_LEN_BYTES,
    /// for ergonomic interfacing with cryptographic functions.
    pub fn as_bytes(&self) -> [u8; MEMO_LEN_BYTES] {
        let mut ab: [u8; MEMO_LEN_BYTES] = [0u8; MEMO_LEN_BYTES];
        ab[..self.0.as_bytes().len()].copy_from_slice(&self.0.as_bytes());
        ab
    }
}

impl TryFrom<&[u8]> for MemoCiphertext {
    type Error = anyhow::Error;

    fn try_from(input: &[u8]) -> Result<MemoCiphertext, Self::Error> {
        if input.len() > MEMO_CIPHERTEXT_LEN_BYTES {
            return Err(anyhow::anyhow!(
                "provided memo ciphertext exceeds maximum memo size"
            ));
        }
        let mut mc = [0u8; MEMO_CIPHERTEXT_LEN_BYTES];
        mc[..input.len()].copy_from_slice(input);

        Ok(MemoCiphertext(mc))
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use rand_core::OsRng;

    use super::*;
    use crate::{
        asset,
        keys::{SeedPhrase, SpendKey},
        Value,
    };
    use decaf377::Fr;

    #[test]
    fn test_memo_encryption_and_decryption() {
        let mut rng = OsRng;

        let seed_phrase = SeedPhrase::generate(&mut rng);
        let sk = SpendKey::from_seed_phrase(seed_phrase, 0);
        let fvk = sk.full_viewing_key();
        let ivk = fvk.incoming();
        let (dest, _dtk_d) = ivk.payment_address(0u64.into());

        let memo_s = "Hi";

        let esk = ka::Secret::new(&mut rng);

        // On the sender side, we have to encrypt the memo to put into the transaction-level,
        // and also the memo key to put on the action-level (output).
        let memo = MemoPlaintext(memo_s.to_string());
        let memo_key = PayloadKey::random_key(&mut OsRng);
        let ciphertext = memo.encrypt(memo_key.clone());
        let wrapped_memo_key = WrappedMemoKey::encrypt(
            &memo_key,
            esk.clone(),
            dest.transmission_key(),
            dest.diversified_generator(),
        );

        // On the recipient side, we have to decrypt the wrapped memo key, and then the memo.
        let epk = esk.diversified_public(dest.diversified_generator());
        let decrypted_memo_key = wrapped_memo_key
            .decrypt(epk, ivk)
            .expect("can decrypt memo key");
        let plaintext =
            MemoPlaintext::decrypt(ciphertext, &decrypted_memo_key).expect("can decrypt memo");

        assert_eq!(memo_key, decrypted_memo_key);
        assert_eq!(plaintext, memo);
    }

    #[test]
    fn test_memo_encryption_and_sender_decryption() {
        let mut rng = OsRng;

        let seed_phrase = SeedPhrase::generate(&mut rng);
        let sk = SpendKey::from_seed_phrase(seed_phrase, 0);
        let fvk = sk.full_viewing_key();
        let ivk = fvk.incoming();
        let ovk = fvk.outgoing();
        let (dest, _dtk_d) = ivk.payment_address(0u64.into());

        let memo_s = "Hi";

        let esk = ka::Secret::new(&mut rng);

        let value = Value {
            amount: 10u64.into(),
            asset_id: asset::REGISTRY.parse_denom("upenumbra").unwrap().id(),
        };
        let note = Note::generate(&mut rng, &dest, value);

        // On the sender side, we have to encrypt the memo to put into the transaction-level,
        // and also the memo key to put on the action-level (output).
        let memo = MemoPlaintext(memo_s.to_string());
        let memo_key = PayloadKey::random_key(&mut OsRng);
        let ciphertext = memo.encrypt(memo_key.clone());
        let wrapped_memo_key = WrappedMemoKey::encrypt(
            &memo_key,
            esk.clone(),
            dest.transmission_key(),
            dest.diversified_generator(),
        );

        let value_blinding = Fr::rand(&mut rng);
        let cv = note.value().commit(value_blinding);
        let wrapped_ovk = note.encrypt_key(&esk, ovk, cv);

        // Later, still on the sender side, we decrypt the memo by using the decrypt_outgoing method.
        let epk = esk.diversified_public(dest.diversified_generator());
        let plaintext = MemoPlaintext::decrypt_outgoing(
            ciphertext,
            wrapped_ovk,
            note.commit(),
            cv,
            ovk,
            &epk,
            &wrapped_memo_key,
        )
        .expect("can decrypt memo");

        assert_eq!(plaintext, memo);
    }
    #[test]
    fn test_memo_created_from_string() {
        let s = String::from("Hello, friend");
        let mp = MemoPlaintext(s.clone());
        assert_eq!(s, mp.0);
    }

    #[test]
    fn test_memo_created_from_bytes() {
        let b = b"Hello, friend";
        let mut t = [0u8; MEMO_LEN_BYTES];
        t[..b.len()].copy_from_slice(b);
        let mp = MemoPlaintext::from(t);
        assert_eq!(String::from_utf8_lossy(b), mp.0);
    }
}
