// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
use std::vec::Vec;
use rand::rngs::OsRng;

use crate::compute_message_hash;
use crate::generate_commitment_share_lists;
use crate::DistributedKeyGeneration;
use crate::Parameters;
use crate::Participant;
use crate::SignatureAggregator;

#[no_mangle]
pub unsafe extern "C" fn simulation(_n: u32, _t: u32, primary: &[u32], msg: &[u8]) {
    let (n, t) = (4, 3);
    let params = Parameters { n, t };
    // let primary: &[u32] = primary.as_ref().unwrap();
    // let msg: &[u8] = msg.as_ref().unwrap();

    let (p1, p1coeffs) = Participant::new(&params, 1);
    let (p2, p2coeffs) = Participant::new(&params, 2);
    let (p3, p3coeffs) = Participant::new(&params, 3);
    let (p4, p4coeffs) = Participant::new(&params, 4);

    let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone(), p4.clone());
    let p1_state = DistributedKeyGeneration::<_>::new(&params,
                                                        &p1.index,
                                                        &p1coeffs,
                                                        &mut p1_other_participants).unwrap();
    let p1_their_secret_shares = p1_state.their_secret_shares().unwrap();
    
    let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone(), p4.clone());
    let p2_state = DistributedKeyGeneration::<>::new(&params,
                                                        &p2.index,
                                                        &p2coeffs,
                                                        &mut p2_other_participants).unwrap();
    let p2_their_secret_shares = p2_state.their_secret_shares().unwrap();

    let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p4.clone());
    let p3_state = DistributedKeyGeneration::<_>::new(&params,
                                                        &p3.index,
                                                        &p3coeffs,
                                                        &mut p3_other_participants).unwrap();
    let p3_their_secret_shares = p3_state.their_secret_shares().unwrap();

    let mut p4_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone());
    let p4_state = DistributedKeyGeneration::<_>::new(&params,
                                                        &p4.index,
                                                        &p4coeffs,
                                                        &mut p4_other_participants).unwrap();
    let p4_their_secret_shares = p4_state.their_secret_shares().unwrap();

    let p1_my_secret_shares = vec!(p2_their_secret_shares[0].clone(), // XXX FIXME indexing
                                    p3_their_secret_shares[0].clone(),
                                    p4_their_secret_shares[0].clone());

    let p2_my_secret_shares = vec!(p1_their_secret_shares[0].clone(),
                                    p3_their_secret_shares[1].clone(),
                                    p4_their_secret_shares[1].clone());
    
    let p3_my_secret_shares = vec!(p1_their_secret_shares[1].clone(),
                                    p2_their_secret_shares[1].clone(),
                                    p4_their_secret_shares[2].clone());
    
    let p4_my_secret_shares = vec!(p1_their_secret_shares[2].clone(),
                                    p2_their_secret_shares[2].clone(),
                                    p3_their_secret_shares[2].clone());
    
        
    let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();
    let p2_state = p2_state.to_round_two(p2_my_secret_shares).unwrap();
    let p3_state = p3_state.to_round_two(p3_my_secret_shares).unwrap();
    let p4_state = p4_state.to_round_two(p4_my_secret_shares).unwrap();

    let (group_key, p1_sk) = p1_state.finish(p1.public_key().unwrap()).unwrap();
    let (_, p2_sk) = p2_state.finish(p2.public_key().unwrap()).unwrap();
    let (_, p3_sk) = p3_state.finish(p3.public_key().unwrap()).unwrap();
    let (_, p4_sk) = p4_state.finish(p4.public_key().unwrap()).unwrap();

    let sk_vec = vec!(p1_sk, p2_sk, p3_sk, p4_sk);

    let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
    //let message = b"This is a test of the tsunami alert system. This is only a test.";

    let mut commitment_vec = Vec::new();
    for i in 0..n {
        let (public_comshares, secret_comshares) = generate_commitment_share_lists(&mut OsRng, i + 1, 1);
        commitment_vec.push((public_comshares, secret_comshares));
    }

    // let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
    // let (p2_public_comshares, mut p2_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);
    // let (p3_public_comshares, mut p3_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
    // let (p4_public_comshares, mut p4_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 4, 1);

    let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &msg[..]);

    for i in primary.iter() {
        let idx = i + 1;
        let (public_comshares, _) = &commitment_vec[idx as usize - 1];
        let sk = &sk_vec[idx as usize - 1];
        aggregator.include_signer(idx, public_comshares.commitments[0], sk.into());

    }

    // aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
    // aggregator.include_signer(3, p3_public_comshares.commitments[0], (&p3_sk).into());
    // aggregator.include_signer(4, p4_public_comshares.commitments[0], (&p4_sk).into());

    let signers = aggregator.get_signers();
    let message_hash = compute_message_hash(&context[..], &msg[..]);
    let mut partial_vec = Vec::new();

    for i in primary.iter() {
        let idx = i + 1;
        let (_, secret_comshares) = &mut commitment_vec[idx as usize -1];
        let sk = &sk_vec[idx as usize - 1];
        let partial = sk.sign(&message_hash, &group_key, secret_comshares, 0, signers).unwrap();
        partial_vec.push(partial);
        //aggregator.include_partial_signature(partial);   
    }

    for partial in partial_vec.into_iter() {
        aggregator.include_partial_signature(partial);
    }

    let aggregator = aggregator.finalize().unwrap();
    let threshold_signature = aggregator.aggregate().unwrap();

    threshold_signature.verify(&group_key, &message_hash).unwrap();

    // let p1_partial = p1_sk.sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers).unwrap();
    // let p3_partial = p3_sk.sign(&message_hash, &group_key, &mut p3_secret_comshares, 0, signers).unwrap();
    // let p4_partial = p4_sk.sign(&message_hash, &group_key, &mut p4_secret_comshares, 0, signers).unwrap();

    // aggregator.include_partial_signature(p1_partial);
    // aggregator.include_partial_signature(p3_partial);
    // aggregator.include_partial_signature(p4_partial);

    //let aggregator = aggregator.finalize().unwrap();

}

mod test {
    use super::*;

    #[test]
    fn test_simulation() {
        let n: u32 = 4;
        let t: u32 = 3;
        let primary: &[u32] = &[1, 2, 3];
        let msg: &[u8] = b"This is a secret message!";

        unsafe {
            simulation(n, t, primary, msg)
        }
    }
}