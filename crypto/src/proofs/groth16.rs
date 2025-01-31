use std::str::FromStr;

use ark_r1cs_std::uint8::UInt8;
use decaf377::{
    r1cs::{ElementVar, FqVar},
    Bls12_377, Fq, Fr,
};
use decaf377::{Element, FieldExt};
use decaf377_fmd as fmd;
use decaf377_ka as ka;

use ark_ff::{PrimeField, ToConstraintField};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::prelude::AllocVar;
use ark_relations::ns;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef};
use ark_snark::SNARK;
use rand::{CryptoRng, Rng};
use rand_core::OsRng;

use super::groth16_gadgets as gadgets;
use crate::keys::Diversifier;
use crate::{balance, note, Address, Note, Value};

// Public:
// * vcm (value commitment)
// * ncm (note commitment)
// * epk (point)
//
// Witnesses:
// * g_d (point)
// * pk_d (point)
// * v (u64 value plus asset ID (scalar))
// * vblind (Fr)
// * nblind (Fq)
// * esk (scalar)
#[derive(Clone)]
pub struct OutputCircuit {
    // Witnesses
    /// The note being created.
    note: Note,
    /// The blinding factor used for generating the balance commitment.
    v_blinding: Fr,
    /// The ephemeral secret key that corresponds to the public key.
    esk: ka::Secret,

    // Public inputs
    /// balance commitment of the new note,
    pub balance_commitment: balance::Commitment,
    /// note commitment of the new note,
    pub note_commitment: note::Commitment,
    /// the ephemeral public key used to generate the new note.
    pub epk: Element,
}

impl ConstraintSynthesizer<Fq> for OutputCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> ark_relations::r1cs::Result<()> {
        // Witnesses
        let note_blinding_var =
            FqVar::new_witness(cs.clone(), || Ok(self.note.note_blinding().clone()))?;
        let value_amount_var =
            FqVar::new_witness(cs.clone(), || Ok(Fq::from(self.note.value().amount)))?;
        let value_asset_id_var =
            FqVar::new_witness(cs.clone(), || Ok(self.note.value().asset_id.0))?;
        let diversified_generator_var: ElementVar =
            AllocVar::<Element, Fq>::new_witness(cs.clone(), || {
                Ok(self.note.diversified_generator().clone())
            })?;
        let transmission_key_s_var =
            FqVar::new_witness(cs.clone(), || Ok(self.note.transmission_key_s().clone()))?;
        let clue_key_var = FqVar::new_witness(cs.clone(), || {
            Ok(Fq::from_le_bytes_mod_order(&self.note.clue_key().0[..]))
        })?;
        let v_blinding_arr: [u8; 32] = self.v_blinding.to_bytes();
        let v_blinding_vars = UInt8::new_witness_vec(cs.clone(), &v_blinding_arr)?;
        let esk_arr: [u8; 32] = self.esk.to_bytes();
        let esk_vars = UInt8::new_witness_vec(cs.clone(), &esk_arr)?;
        let value_amount_arr = self.note.value().amount.to_le_bytes();
        let value_vars = UInt8::new_witness_vec(cs.clone(), &value_amount_arr)?;

        // Public inputs
        let note_commitment_var = FqVar::new_input(cs.clone(), || Ok(self.note_commitment.0))?;
        let epk = ElementVar::new_input(ns!(cs, "epk"), || Ok(self.epk))?;
        let balance_commitment_var =
            ElementVar::new_input(cs.clone(), || Ok(self.balance_commitment.0))?;

        gadgets::diversified_basepoint_not_identity(cs.clone(), diversified_generator_var.clone())?;
        gadgets::ephemeral_public_key_integrity(esk_vars, diversified_generator_var.clone(), epk)?;
        gadgets::value_commitment_integrity(
            cs.clone(),
            value_vars,
            value_asset_id_var.clone(),
            v_blinding_vars,
            balance_commitment_var,
        )?;
        gadgets::note_commitment_integrity(
            cs,
            note_blinding_var,
            value_amount_var,
            value_asset_id_var,
            diversified_generator_var,
            transmission_key_s_var,
            clue_key_var,
            note_commitment_var,
        )?;

        Ok(())
    }
}

impl OutputCircuit {
    pub fn generate_test_parameters() -> (ProvingKey<Bls12_377>, VerifyingKey<Bls12_377>) {
        let diversifier_bytes = [1u8; 16];
        let pk_d_bytes = [1u8; 32];
        let clue_key_bytes = [1; 32];
        let diversifier = Diversifier(diversifier_bytes);
        let address = Address::from_components(
            diversifier,
            ka::Public(pk_d_bytes),
            fmd::ClueKey(clue_key_bytes),
        )
        .expect("generated 1 address");
        let note = Note::from_parts(
            address,
            Value::from_str("1upenumbra").expect("valid value"),
            Fq::from(1),
        )
        .expect("can make a note");
        let v_blinding = Fr::from(1);
        let esk = ka::Secret::new_from_field(Fr::from(1));
        let epk = decaf377::basepoint();
        let circuit = OutputCircuit {
            note: note.clone(),
            note_commitment: note.commit(),
            v_blinding,
            esk,
            epk,
            balance_commitment: balance::Commitment(decaf377::basepoint()),
        };
        let (pk, vk) = Groth16::circuit_specific_setup(circuit, &mut OsRng)
            .expect("can perform circuit specific setup");
        (pk, vk)
    }
}

pub struct OutputProof(Proof<Bls12_377>);

impl OutputProof {
    #![allow(clippy::too_many_arguments)]
    pub fn prove<R: CryptoRng + Rng>(
        rng: &mut R,
        pk: &ProvingKey<Bls12_377>,
        note: Note,
        v_blinding: Fr,
        esk: ka::Secret,
        balance_commitment: balance::Commitment,
        note_commitment: note::Commitment,
        epk: ka::Public,
    ) -> anyhow::Result<Self> {
        let element_pk = decaf377::Encoding(epk.0).vartime_decompress().unwrap();
        let circuit = OutputCircuit {
            note,
            note_commitment,
            v_blinding,
            esk,
            epk: element_pk,
            balance_commitment,
        };
        let proof = Groth16::prove(pk, circuit, rng).map_err(|err| anyhow::anyhow!(err))?;
        Ok(Self(proof))
    }

    /// Called to verify the proof using the provided public inputs.
    ///
    /// The public inputs are:
    /// * balance commitment of the new note,
    /// * note commitment of the new note,
    /// * the ephemeral public key used to generate the new note.
    pub fn verify(
        &self,
        vk: &VerifyingKey<Bls12_377>,
        balance_commitment: balance::Commitment,
        note_commitment: note::Commitment,
        epk: ka::Public,
    ) -> anyhow::Result<bool> {
        let processed_pvk = Groth16::process_vk(vk).map_err(|err| anyhow::anyhow!(err))?;
        let element_pk = decaf377::Encoding(epk.0).vartime_decompress().unwrap();
        let mut public_inputs = Vec::new();
        public_inputs.extend(note_commitment.0.to_field_elements().unwrap());
        public_inputs.extend(element_pk.to_field_elements().unwrap());
        public_inputs.extend(balance_commitment.0.to_field_elements().unwrap());

        let proof_result =
            Groth16::verify_with_processed_vk(&processed_pvk, public_inputs.as_slice(), &self.0)
                .map_err(|err| anyhow::anyhow!(err))?;
        Ok(proof_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        asset,
        keys::{SeedPhrase, SpendKey},
    };
    use ark_ff::UniformRand;

    #[test]
    fn output_proof_happy_path() {
        let (pk, vk) = OutputCircuit::generate_test_parameters();
        let mut rng = OsRng;

        let seed_phrase = SeedPhrase::generate(rng);
        let sk_recipient = SpendKey::from_seed_phrase(seed_phrase, 0);
        let fvk_recipient = sk_recipient.full_viewing_key();
        let ivk_recipient = fvk_recipient.incoming();
        let (dest, _dtk_d) = ivk_recipient.payment_address(0u64.into());

        let value_to_send = Value {
            amount: 10u64.into(),
            asset_id: asset::REGISTRY.parse_denom("upenumbra").unwrap().id(),
        };

        let v_blinding = Fr::rand(&mut rng);
        let note = Note::generate(&mut rng, &dest, value_to_send);
        let note_commitment = note.commit();
        let esk = ka::Secret::new_from_field(Fr::rand(&mut rng));
        let epk = esk.diversified_public(&note.diversified_generator());
        let balance_commitment = value_to_send.commit(v_blinding);

        let proof = OutputProof::prove(
            &mut rng,
            &pk,
            note,
            v_blinding,
            esk,
            balance_commitment,
            note_commitment,
            epk,
        )
        .expect("can create proof");

        let proof_result = proof
            .verify(&vk, balance_commitment, note_commitment, epk)
            .expect("can compute success or not");

        assert!(proof_result);
    }

    #[test]
    fn output_proof_verification_note_commitment_integrity_failure() {
        let (pk, vk) = OutputCircuit::generate_test_parameters();
        let mut rng = OsRng;

        let seed_phrase = SeedPhrase::generate(rng);
        let sk_recipient = SpendKey::from_seed_phrase(seed_phrase, 0);
        let fvk_recipient = sk_recipient.full_viewing_key();
        let ivk_recipient = fvk_recipient.incoming();
        let (dest, _dtk_d) = ivk_recipient.payment_address(0u64.into());

        let value_to_send = Value {
            amount: 10u64.into(),
            asset_id: asset::REGISTRY.parse_denom("upenumbra").unwrap().id(),
        };

        let v_blinding = Fr::rand(&mut rng);
        let note = Note::generate(&mut rng, &dest, value_to_send);
        let note_commitment = note.commit();
        let esk = ka::Secret::new_from_field(Fr::rand(&mut rng));
        let epk = esk.diversified_public(&note.diversified_generator());
        let balance_commitment = value_to_send.commit(v_blinding);

        let proof = OutputProof::prove(
            &mut rng,
            &pk,
            note.clone(),
            v_blinding,
            esk,
            balance_commitment,
            note_commitment,
            epk,
        )
        .expect("can create proof");

        let incorrect_note_commitment = note::commitment(
            Fq::rand(&mut rng),
            value_to_send,
            note.diversified_generator(),
            note.transmission_key_s(),
            note.clue_key(),
        );

        let proof_result = proof
            .verify(&vk, balance_commitment, incorrect_note_commitment, epk)
            .expect("can compute success or not");

        assert!(!proof_result);
    }

    #[test]
    fn output_proof_verification_balance_commitment_integrity_failure() {
        let (pk, vk) = OutputCircuit::generate_test_parameters();
        let mut rng = OsRng;

        let seed_phrase = SeedPhrase::generate(rng);
        let sk_recipient = SpendKey::from_seed_phrase(seed_phrase, 0);
        let fvk_recipient = sk_recipient.full_viewing_key();
        let ivk_recipient = fvk_recipient.incoming();
        let (dest, _dtk_d) = ivk_recipient.payment_address(0u64.into());

        let value_to_send = Value {
            amount: 10u64.into(),
            asset_id: asset::REGISTRY.parse_denom("upenumbra").unwrap().id(),
        };

        let v_blinding = Fr::rand(&mut rng);
        let note = Note::generate(&mut rng, &dest, value_to_send);
        let note_commitment = note.commit();
        let esk = ka::Secret::new_from_field(Fr::rand(&mut rng));
        let epk = esk.diversified_public(&note.diversified_generator());
        let balance_commitment = value_to_send.commit(v_blinding);

        let proof = OutputProof::prove(
            &mut rng,
            &pk,
            note,
            v_blinding,
            esk,
            balance_commitment,
            note_commitment,
            epk,
        )
        .expect("can create proof");

        let incorrect_balance_commitment = value_to_send.commit(Fr::rand(&mut rng));

        let proof_result = proof
            .verify(&vk, incorrect_balance_commitment, note_commitment, epk)
            .expect("can compute success or not");

        assert!(!proof_result);
    }

    #[test]
    fn test_output_proof_verification_ephemeral_public_key_integrity_failure() {
        let (pk, vk) = OutputCircuit::generate_test_parameters();
        let mut rng = OsRng;

        let seed_phrase = SeedPhrase::generate(rng);
        let sk_recipient = SpendKey::from_seed_phrase(seed_phrase, 0);
        let fvk_recipient = sk_recipient.full_viewing_key();
        let ivk_recipient = fvk_recipient.incoming();
        let (dest, _dtk_d) = ivk_recipient.payment_address(0u64.into());

        let value_to_send = Value {
            amount: 10u64.into(),
            asset_id: asset::REGISTRY.parse_denom("upenumbra").unwrap().id(),
        };

        let v_blinding = Fr::rand(&mut rng);
        let note = Note::generate(&mut rng, &dest, value_to_send);
        let note_commitment = note.commit();
        let esk = ka::Secret::new_from_field(Fr::rand(&mut rng));
        let epk = esk.diversified_public(&note.diversified_generator());
        let balance_commitment = value_to_send.commit(v_blinding);

        let proof = OutputProof::prove(
            &mut rng,
            &pk,
            note.clone(),
            v_blinding,
            esk,
            balance_commitment,
            note_commitment,
            epk,
        )
        .expect("can create proof");

        let incorrect_esk = ka::Secret::new(&mut rng);
        let incorrect_epk = incorrect_esk.diversified_public(&note.diversified_generator());

        let proof_result = proof
            .verify(&vk, balance_commitment, note_commitment, incorrect_epk)
            .expect("can compute success or not");

        assert!(!proof_result);
    }
}
