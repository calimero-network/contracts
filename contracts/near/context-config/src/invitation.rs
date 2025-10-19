use calimero_context_config::types::{ContextId, SignedRevealPayload, SignerId};
use calimero_context_config::repr::{Repr, ReprBytes};

use near_sdk::borsh::{self};
use near_sdk::{env, near, require, BlockHeight, CryptoHash};

use super::{
    ContextConfigs, ContextConfigsExt,
};

pub type Ed25519Signature = [u8; 64];

#[near]
impl ContextConfigs {
    /// ### Step 1: Commit Invitation
    /// 
    /// Anonymously commits to a hash of a future reveal payload. This action allows to
    /// prevent MEV attacks. This can be called by the new member (invitee) directly or by a relayer
    /// on their behalf.
    ///
    /// # Arguments
    ///
    /// * `context_id`: The `ContextId` for which the commitment is being made.
    /// * `commitment_hash`: A hex-encoded SHA-256 hash of the `RevealPayloadData`.
    pub fn commit_invitation(&mut self, context_id: Repr<ContextId>, commitment_hash: String, expiration_block_height: BlockHeight) {
        let context = self
            .contexts
            .get_mut(&context_id)
            .expect("Context does not exist");

        let hash_bytes: CryptoHash = hex::decode(commitment_hash.clone())
            .expect("Invalid hex hash")
            .try_into()
            .expect("Hash must be 32 bytes");

        require!(
            !context.commitments_open_invitations.contains_key(&hash_bytes),
            "This commitment has already been made"
        );

        let current_block_height: BlockHeight = env::block_height();
        require!(
            current_block_height < expiration_block_height,
            "This invitation is already expired"
        );

        let _ = context.commitments_open_invitations.insert(hash_bytes, expiration_block_height);

        // TODO: do we need to manually do it to persist the updated context state?
        //self.contexts.insert(&context_id, &context);
        
        env::log_str(&format!("Successfully committed the invitation image {} in context {}", commitment_hash, context_id));
    }

    /// ### Step 2: Reveal Invitation
    ///
    /// Submits the full payload to claim the invitation. The contract verifies this payload
    /// against the prior commitment and validates all signatures and permissions.
    /// This method can be safely called by a relayer.
    ///
    /// # Arguments
    ///
    /// * `payload`: A `SignedRevealPayload` containing the original data and the new member's signature.
    pub fn reveal_invitation(&mut self, #[serializer(borsh)] payload: SignedRevealPayload) {
        //let payload = payload.into_inner();
        let payload_data = payload.data;
        let invitation = payload_data.signed_open_invitation.invitation.clone();
        let context_id = invitation.context_id;

        // TODO: record whether it's mainnet or testnet contract on the contract creation and
        // verify against it.
        // TODO: verify maybe `protocol_name`, `contract_id`, similar to `ContextInvitationPayload`
        // fields.
        require!(invitation.protocol == "near",
            "The invitation was designated for another protocol");
        require!(invitation.contract_id == env::current_account_id(),
            "The invitation was designated for another contract");

        // Verify the context exists
        let context = self
            .contexts
            .get_mut(&context_id)
            .expect("Context does not exist");

        // 1. Hash the revealed data to find the original commitment.
        let payload_data_bytes = borsh::to_vec(&payload_data).expect("Failed to serialize payload data");
        let payload_data_hash_vec = env::sha256(&payload_data_bytes);
        let payload_data_hash: CryptoHash = payload_data_hash_vec.clone().try_into().unwrap();

        // 2. Remove the commitment using the hash, which also serves as a replay-prevention step.
        let _ = context.commitments_open_invitations.remove(&payload_data_hash)
            .expect("No matching commitment found. It may have expired, been invalid, or already used");
        // TODO: consider expiring immediately if the commitment image was not found?

        // Check if the invitation has expired.
        require!(
            env::block_height() <= invitation.expiration_height,
            "The invitation has expired."
        );

        // Check if the invitee is already in the context.
        require!(!context.members.contains(&payload_data.new_member_identity), "Member already in context");

        // 4. Authenticate the new member by verifying their signature over the payload data.
        let new_member_signature_bytes: Ed25519Signature = hex::decode(payload.invitee_signature)
            .expect("Invalid hex signature for new member")
            .try_into()
            .expect("Invalid signature length");
        require!(
            env::ed25519_verify(&new_member_signature_bytes, &payload_data_hash_vec, &payload_data.new_member_identity.as_bytes()),
            "New member's signature is invalid."
        );
        
        // 5. Verify the inviter's signed invitation.
        let inviter_identity = invitation.inviter_identity;
        let inviter_signature_bytes = hex::decode(payload_data.signed_open_invitation.inviter_signature)
            .expect("Invalid hex inviter signature")
            .try_into()
            .expect("Invalid signature length");

        // Check inviter's signature.
        let invitation_bytes = borsh::to_vec(&invitation).expect("Failed to serialize invitation");
        require!(
            env::ed25519_verify(&inviter_signature_bytes, &env::sha256(&invitation_bytes), &inviter_identity.as_bytes()),
            "Inviter's signature is invalid"
        );

        // Prevent replay of the inviter's signature.
        let inviter_signature_hash: CryptoHash = env::sha256(&inviter_signature_bytes)
            .try_into()
            .expect("infallible conversion");

        // This hack is needed as we don't have normal `From` implemnetations for `Identity`/`SignerId`.
        let inviter_identity_borsh = borsh::to_vec(&inviter_identity)
            .expect("Failed to serialize inviter identity");
        let inviter_signer_id: SignerId = borsh::from_slice(&inviter_identity_borsh)
            .expect("Failed to deserialize inviter identity");

        let mut used_open_invitations = context
            .used_open_invitations
            .get(&inviter_signer_id)
            .expect("Unable to update used open invitations list")
            .get_mut();

        require!(
            used_open_invitations.insert(inviter_signature_hash),
            "This invitation has already been used in this context."
        );

        //// TODO: what's the proper way to check inviter's permissions?
        //require!(
        //    context.members.priviledges().has_capability(&inviter_identity, Capability::ManageMembers),
        //    "The inviter does not have permission to add members."
        //);

        let mut context_members= context
            .members
            .get(&inviter_signer_id)
            //.get(payload_data.invitation.inviter_identity.as_bytes().into())
            .expect("Unable to update members list")
            .get_mut();

        // 6. Add the new member to the context.
        let _ = context_members.insert(payload_data.new_member_identity);
        // TODO: do we need to update member nonces?
        //context.member_nonces.insert(payload_data.new_member_identity, 0);

        env::log_str(&format!("Account {} successfully joined context {}", Repr::new(payload_data.new_member_identity), Repr::new(context_id)));
    }
}
