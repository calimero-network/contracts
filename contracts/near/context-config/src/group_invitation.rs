use calimero_context_config::repr::{Repr, ReprBytes};
use calimero_context_config::types::{ContextGroupId, SignedGroupRevealPayload};
use near_sdk::borsh;
use near_sdk::{env, require, BlockHeight, CryptoHash};

use super::ContextConfigs;

pub type Ed25519Signature = [u8; 64];

impl ContextConfigs {
    /// ### Step 1: Commit Group Invitation
    ///
    /// Anonymously commits to a hash of a future reveal payload.
    /// Prevents MEV attacks. Can be called by the joiner or a relayer.
    ///
    /// # Arguments
    ///
    /// * `group_id` - The group for which the commitment is being made.
    /// * `commitment_hash` - A hex-encoded SHA-256 hash of the `GroupRevealPayloadData`.
    /// * `expiration_block_height` - The block height at which the commitment expires.
    pub fn commit_group_invitation(
        &mut self,
        group_id: Repr<ContextGroupId>,
        commitment_hash: String,
        expiration_block_height: BlockHeight,
    ) {
        let group = self
            .groups
            .get_mut(&group_id)
            .expect("Group does not exist");

        let hash_bytes: CryptoHash = hex::decode(&commitment_hash)
            .expect("Invalid hex hash")
            .try_into()
            .expect("Hash must be 32 bytes");

        require!(
            !group.invitation_commitments.contains_key(&hash_bytes),
            "This commitment has already been made"
        );

        let current_block_height: BlockHeight = env::block_height();
        require!(
            current_block_height < expiration_block_height,
            "This invitation is already expired"
        );

        let _ignored = group
            .invitation_commitments
            .insert(hash_bytes, expiration_block_height);

        env::log_str(&format!(
            "Successfully committed the group invitation image {} in group {}",
            commitment_hash, group_id
        ));
    }

    /// ### Step 2: Reveal Group Invitation
    ///
    /// Submits the full payload to claim the group invitation. The contract verifies
    /// this payload against the prior commitment and validates all signatures and permissions.
    ///
    /// # Arguments
    ///
    /// * `payload` - A `SignedGroupRevealPayload` containing the original data and the
    ///   joiner's signature.
    pub fn reveal_group_invitation(&mut self, payload: SignedGroupRevealPayload) {
        let payload_data = payload.data;
        let invitation = payload_data.signed_open_invitation.invitation.clone();
        let group_id = invitation.group_id;

        require!(
            invitation.protocol == "near",
            "The invitation was designated for another protocol"
        );
        require!(
            invitation.contract_id == env::current_account_id(),
            "The invitation was designated for another contract"
        );

        let group = self
            .groups
            .get_mut(&group_id)
            .expect("Group does not exist");

        // 1. Hash the revealed data to find the original commitment.
        let payload_data_bytes =
            borsh::to_vec(&payload_data).expect("Failed to serialize payload data");
        let payload_data_hash_vec = env::sha256(&payload_data_bytes);
        let payload_data_hash: CryptoHash = payload_data_hash_vec
            .clone()
            .try_into()
            .expect("infallible conversion");

        // 2. Remove the commitment (replay prevention).
        let _ignored = group
            .invitation_commitments
            .remove(&payload_data_hash)
            .expect(
                "No matching commitment found. It may have expired, been invalid, or already used",
            );

        // 3. Check expiration.
        require!(
            env::block_height() <= invitation.expiration_height,
            "The invitation has expired."
        );

        // 4. Check the new member is not already in the group.
        require!(
            !group.members.contains(&payload_data.new_member_identity),
            "Member already in group"
        );
        require!(
            !group.admins.contains(&payload_data.new_member_identity),
            "Member is already a group admin"
        );

        // 5. Verify the joiner's signature over the payload data.
        let new_member_signature_bytes: Ed25519Signature = hex::decode(&payload.invitee_signature)
            .expect("Invalid hex signature for new member")
            .try_into()
            .expect("Invalid signature length");
        require!(
            env::ed25519_verify(
                &new_member_signature_bytes,
                &payload_data_hash_vec,
                &payload_data.new_member_identity.as_bytes()
            ),
            "New member's signature is invalid."
        );

        // 6. Verify the inviter's signature over the invitation.
        let inviter_identity = invitation.inviter_identity;
        let inviter_signature_bytes: Ed25519Signature =
            hex::decode(&payload_data.signed_open_invitation.inviter_signature)
                .expect("Invalid hex inviter signature")
                .try_into()
                .expect("Invalid signature length");

        let invitation_bytes = borsh::to_vec(&invitation).expect("Failed to serialize invitation");
        require!(
            env::ed25519_verify(
                &inviter_signature_bytes,
                &env::sha256(&invitation_bytes),
                &inviter_identity.as_bytes()
            ),
            "Inviter's signature is invalid"
        );

        // 7. Verify the inviter is a group admin.
        require!(
            group.admins.contains(&inviter_identity),
            "Inviter is not a group admin"
        );

        // 8. Prevent replay of the inviter's signature.
        let inviter_signature_hash: CryptoHash = env::sha256(&inviter_signature_bytes)
            .try_into()
            .expect("infallible conversion");
        require!(
            group.used_invitations.insert(inviter_signature_hash),
            "This invitation has already been used in this group."
        );

        // 9. Add the new member to the group.
        let _ignored = group.members.insert(payload_data.new_member_identity);

        env::log_str(&format!(
            "Account {} successfully joined group {}",
            Repr::new(payload_data.new_member_identity),
            Repr::new(group_id)
        ));
    }
}
