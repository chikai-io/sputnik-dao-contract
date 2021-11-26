use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};

use crate::policy::UserInfo;
use crate::types::Action;
use crate::*;

/// Votes recorded in the proposal.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub enum Vote {
    Approve = 0x0,
    Reject = 0x1,
    /// Used in a punitive way towards spams.
    Remove = 0x2,
}

impl From<Action> for Vote {
    fn from(action: Action) -> Self {
        match action {
            Action::VoteApprove => Vote::Approve,
            Action::VoteReject => Vote::Reject,
            Action::VoteRemove => Vote::Remove,
            _ => unreachable!(),
        }
    }
}

// TODO: test without using this structure,
// since only 3 bits are required and
// different ones can share the same byte
//
/// Represents [`Vote`] capabilities in a single byte.  
/// That capability can also be constructed from vote [`Action`]
/// variants.
///
/// Eg. the capability of both voting in approval
/// and also in rejection is expressed as `0b011`.
#[derive(Clone, Copy, PartialEq)]
pub struct VoteActionBitset(pub u8);

impl From<Vote> for VoteActionBitset {
    fn from(vote: Vote) -> VoteActionBitset {
        match vote {
            Vote::Approve => VoteActionBitset::APPROVE,
            Vote::Reject => VoteActionBitset::REJECT,
            Vote::Remove => VoteActionBitset::REMOVE,
        }
    }
}

impl VoteActionBitset {
    pub const APPROVE: Self = VoteActionBitset(0b001);
    pub const REJECT: Self = VoteActionBitset(0b010);
    pub const REMOVE: Self = VoteActionBitset(0b100);
    pub const NOTHING: Self = VoteActionBitset(0b000);

    /// Whether the approval capability is present.
    pub fn can_approve(&self) -> bool {
        *self & Self::APPROVE == Self::APPROVE
    }

    /// Whether the rejection capability is present.
    pub fn can_reject(&self) -> bool {
        *self & Self::REJECT == Self::REJECT
    }

    /// Whether the removal capability is present.
    pub fn can_remove(&self) -> bool {
        *self & Self::REMOVE == Self::REMOVE
    }

    /// Whether no capability is present.  
    /// Same as [`Self::NOTHING`].
    pub fn is_nothing(&self) -> bool {
        *self == Self::NOTHING
    }

    /// Whether some capability is present.  
    /// Opposite of `[Self::is_nothing()]`.
    pub fn is_something(&self) -> bool {
        !self.is_nothing()
    }

    /// Constructs a [`VoteActionBitset`] given a voting [`Action`] label.
    /// ie. given a labeled [`Action::VoteApprove`],
    /// [`Action::VoteReject`], [`Action::VoteRemove`], or a `*`.
    pub fn from_proposal_action(proposal_action: &str) -> Self {
        match proposal_action {
            "*" => {
                let mut vote_bitset = Self::NOTHING;
                vote_bitset |= Self::APPROVE;
                vote_bitset |= Self::REJECT;
                vote_bitset |= Self::REMOVE;
                vote_bitset
            }
            "VoteApprove" => Self::APPROVE,
            "VoteReject" => Self::REJECT,
            "VoteRemove" => Self::REMOVE,
            _ => Self::NOTHING,
        }
    }
}

/// Intersection.
impl std::ops::BitAnd for VoteActionBitset {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

/// Union.
impl std::ops::BitOr for VoteActionBitset {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Assigning intersection.
impl std::ops::BitAndAssign for VoteActionBitset {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs
    }
}

/// Assigning union.
impl std::ops::BitOrAssign for VoteActionBitset {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs
    }
}

pub struct RoleVoteInfo {
    pub name: NewRoleName,
    pub permissions: ProposalKindVotes,
    pub weights: VotePolicyWeights,
}

impl RoleVoteInfo {
    pub fn new(
        name: NewRoleName,
        permissions: ProposalKindVotes,
        weights: VotePolicyWeights,
    ) -> Self {
        Self {
            name,
            permissions,
            weights,
        }
    }
}

// TODO: test replacing by a u64, since 15*3 bits = 45bits.
// currently, 15*8bits = 120bits.
// but would require using array shifts instead of array indexing.
//
/// For each [`ProposalKind`] variant, expresses
/// which types of voting actions are allowed by a role.
///
/// Each proposal kind is represented as an element's index in a list.
#[derive(Clone, Copy)]
pub struct ProposalKindVotes(pub [VoteActionBitset; PROPOSAL_KIND_LEN]);

impl Default for ProposalKindVotes {
    fn default() -> Self {
        Self([VoteActionBitset::NOTHING; PROPOSAL_KIND_LEN])
    }
}

impl ProposalKindVotes {
    /// For a given [`ProposalKind`] label, eg. `"config"` or `"*"`,
    /// and for a `vote` capability, creates a [`ProposalKindVotes`]
    /// that relates that label with that vote capability.
    ///
    /// For example, if the label is `"*"`, then the given vote capability
    /// is applied to every variant of [`ProposalKind`].
    pub fn from_label(label: &str, vote: VoteActionBitset) -> Self {
        let votes = match ProposalKind::label_to_index(label) {
            // `*`, repeats the vote for every label
            None => [vote; PROPOSAL_KIND_LEN],
            Some(index) => {
                let mut votes = [VoteActionBitset::NOTHING; PROPOSAL_KIND_LEN];
                votes[index] = vote;
                votes
            }
        };
        Self(votes)
    }

    /// Whether all [`ProposalKind`] has no voting capability whatsoever.  
    pub fn is_nothing(&self) -> bool {
        self.0.iter().all(VoteActionBitset::is_nothing)
    }

    /// Whether any [`ProposalKind`] has some voting capability.  
    /// Opposite of [`Self::is_nothing()`]
    pub fn is_something(&self) -> bool {
        !self.is_nothing()
    }
}

/// Intersection.
impl std::ops::BitAnd for ProposalKindVotes {
    type Output = Self;

    fn bitand(mut self, rhs: Self) -> Self::Output {
        for (l, r) in self.0.iter_mut().zip(rhs.0) {
            *l &= r;
        }
        self
    }
}

/// Union.
impl std::ops::BitOr for ProposalKindVotes {
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self::Output {
        for (l, r) in self.0.iter_mut().zip(rhs.0) {
            *l |= r;
        }
        self
    }
}

/// Assigning intersection.
impl std::ops::BitAndAssign for ProposalKindVotes {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs
    }
}

/// Assigning union.
impl std::ops::BitOrAssign for ProposalKindVotes {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs
    }
}

impl Contract {
    pub fn get_user_and_default_weight(&self, member_id: &AccountId) -> (Balance, Balance) {
        let user_weight = self.get_user_weight(&member_id);
        let default_weight = match self
            .policy
            .get()
            .unwrap()
            .to_policy()
            .default_vote_policy
            .weight_kind
        {
            policy::WeightKind::TokenWeight => user_weight,
            policy::WeightKind::RoleWeight => 1,
        };
        (user_weight, default_weight)
    }

    /// Returns the role name and it's `permissions`
    /// information, that a user is related to.  
    ///
    /// Only information related to voting is considered.
    ///
    /// Returns `None` if that role is not related to voting
    /// at all.
    pub fn get_user_voting_role(
        &self,
        user: UserInfo,
        role_name: NewRoleName,
    ) -> Option<RoleVoteInfo> {
        let (user_weight, default_weight) = self.get_user_and_default_weight(&user.account_id);

        for role in self.roles.iter() {
            if role.name != role_name {
                continue;
            }
            if !role.kind.match_user(&user) {
                continue;
            }

            let mut permissions = ProposalKindVotes::default();

            for permission in &role.permissions {
                let (proposal_kind, proposal_action) = {
                    let split: Vec<&str> = permission.split(':').collect();
                    assert_eq!(split.len(), 2);
                    (split[0], split[1])
                };

                let vote_bitset = VoteActionBitset::from_proposal_action(proposal_action);

                // skip this `proposal_kind` if it's not related to voting
                if vote_bitset.is_nothing() {
                    continue;
                }

                let kind_votes = ProposalKindVotes::from_label(proposal_kind, vote_bitset);

                permissions |= kind_votes;
            }

            // skip this `role` if none of it's `proposal_action`'s
            // are related to voting
            return if permissions.is_nothing() {
                None
            } else {
                let role_vote_info = RoleVoteInfo::new(
                    role.name.clone(),
                    permissions,
                    role.vote_policy_weight_table(user_weight, default_weight),
                );
                Some(role_vote_info)
            };
        }
        env::panic_str("ERR_ROLE_NOT_FOUND")
    }

    /// Returns a lists relating role names, and it's `permissions`
    /// information, that a user is related to.  
    ///
    /// Only information related to voting is considered.
    pub fn get_user_voting_roles(&self, user: UserInfo) -> Vec<RoleVoteInfo> {
        let (user_weight, default_weight) = self.get_user_and_default_weight(&user.account_id);

        let mut roles = vec![];
        for role in self.roles.iter() {
            if !role.kind.match_user(&user) {
                continue;
            }

            let mut permissions = ProposalKindVotes::default();
            for permission in &role.permissions {
                let (proposal_kind, proposal_action) = {
                    let split: Vec<&str> = permission.split(':').collect();
                    assert_eq!(split.len(), 2);
                    (split[0], split[1])
                };

                let vote_bitset = VoteActionBitset::from_proposal_action(proposal_action);

                // skip this `proposal_kind` if it's not related to voting
                if vote_bitset.is_nothing() {
                    continue;
                }

                let kind_votes = ProposalKindVotes::from_label(proposal_kind, vote_bitset);
                permissions |= kind_votes;
            }

            // skip this `role` if none of it's `proposal_action`'s
            // are related to voting
            if permissions.is_nothing() {
                continue;
            }

            let role_vote_info = RoleVoteInfo::new(
                role.name.clone(),
                permissions,
                role.vote_policy_weight_table(user_weight, default_weight),
            );
            roles.push(role_vote_info);
        }
        roles
    }

    /// Returns a lists relating role names, and it's `permissions`
    /// information, that a user is related to.  
    ///
    /// Only information related to voting is considered.  
    /// The `target` role is filtered out, and the roles that
    /// cannot possibly have any "voting" relation to the `target`
    /// role are also filtered out.
    pub fn get_user_voting_roles_filtered(
        &self,
        user: UserInfo,
        target: &RoleVoteInfo,
    ) -> Vec<RoleVoteInfo> {
        let (user_weight, default_weight) = self.get_user_and_default_weight(&user.account_id);

        let mut roles = vec![];
        for role in self.roles.iter() {
            // already got the target, and it should be separated
            if role.name == target.name {
                continue;
            }
            // skip if it's not related to the user
            if !role.kind.match_user(&user) {
                continue;
            }

            let mut permissions = ProposalKindVotes::default();
            for permission in &role.permissions {
                let (proposal_kind, proposal_action) = {
                    let split: Vec<&str> = permission.split(':').collect();
                    assert_eq!(split.len(), 2);
                    (split[0], split[1])
                };

                let vote_bitset = VoteActionBitset::from_proposal_action(proposal_action);

                // skip this `proposal_kind` if it's not related to voting
                if vote_bitset.is_nothing() {
                    continue;
                }

                let kind_votes = ProposalKindVotes::from_label(proposal_kind, vote_bitset);

                permissions |= kind_votes;
            }

            // ignore permission votes that are not related to the target
            permissions &= target.permissions;

            // skip this `role` if none of it's `proposal_action`'s
            // are related to voting, or not related to the target role
            if permissions.is_nothing() {
                continue;
            }

            let role_vote_info = RoleVoteInfo::new(
                role.name.clone(),
                permissions,
                role.vote_policy_weight_table(user_weight, default_weight),
            );
            roles.push(role_vote_info);
        }
        roles
    }

    /// For a member that is leaving a role, and for all on-going proposals
    /// that member had voted before and that are being counted by
    /// that role, those proposals gets updated.  
    /// That member's votes subtracts the voting count.
    ///
    /// For a given proposal that got a vote subtracted from it,
    /// if no other role was counting/observing that vote,
    /// then that member's vote gets also completely delisted from that
    /// proposal.  
    /// Otherwise, if there are other roles still observing that vote,
    /// the vote is kept registered on the proposal.
    ///
    /// This method requires, at the point where it's being called,
    /// that even if the member is leaving the role,
    /// he must still be registered on it.  
    pub fn update_votes_from_role_removed_member(
        &mut self,
        target_role_name: &NewRoleName,
        member_id: &AccountId,
    ) {
        let user_info = UserInfo::new(self, member_id.clone());

        let target_role = if let Some(user_role) =
            self.get_user_voting_role(user_info.clone(), target_role_name.clone())
        {
            user_role
        } else {
            // if the role that the member is being removed from
            // is not related to voting, then there is no need to update
            // anything
            return;
        };

        let other_roles: Vec<_> = self.get_user_voting_roles_filtered(user_info, &target_role);

        let proposal_ids = self
            .role_votes
            .get(target_role_name)
            .unwrap_or_else(|| env::panic_str("ERR_ROLE_VOTES_MISSING_KEY"));
        for proposal_id in proposal_ids {
            let mut proposal: Proposal = self
                .proposals
                .get(&proposal_id)
                .unwrap_or_else(|| env::panic_str("ERR_NO_PROPOSAL"))
                .into();

            let vote = match proposal.votes.get(member_id) {
                // ignore proposal if `member_id` didn't vote on it
                None => continue,
                Some(vote) => vote,
            };
            let vote_bitset: VoteActionBitset = vote.clone().into();

            let kind_index = proposal.kind.to_index();

            // remove vote observed by target role
            {
                let vote_count = proposal
                    .vote_counts
                    .get_mut(target_role_name)
                    .unwrap_or_else(|| env::panic_str("ERR_MISSING_VOTE_COUNT"));

                // get ammount that should be subtracted
                // (as it could be token-weigthed)
                let weight = target_role.weights.0[kind_index];

                // subtracts from the cached view of the target role
                vote_count[vote.clone() as usize] -= weight;

                // TODO: this requires that changes in delegations
                // should always automatically update all of that
                // user's votes
            }

            // sanity check
            if target_role.permissions.0[kind_index] & vote_bitset == VoteActionBitset::NOTHING {
                unreachable!();
            }

            // if no other role observes that vote,
            // the vote should be unregistered from the proposal
            {
                let observed = other_roles.iter().any(|other_role| {
                    other_role.permissions.0[kind_index] & vote_bitset != VoteActionBitset::NOTHING
                });

                // no other roles are observing that vote,
                // so the vote should be completely unregistered
                if !observed {
                    proposal.votes.remove(member_id);
                }
            }

            // update proposal data
            {
                self.proposals
                    .insert(&proposal_id, &VersionedProposal::Default(proposal));
            }
        }
    }

    pub fn update_votes_from_quitting_member(&mut self, member_id: &AccountId) {
        let user_info = UserInfo::new(self, member_id.clone());

        let roles: Vec<_> = self.get_user_voting_roles(user_info);

        // merge all proposals observed by all roles
        // in a single list.
        //
        // a given proposal is not necessarily watched
        // by all roles.
        let proposal_ids = {
            let mut proposal_ids = vec![];

            let roles_len = roles.len();
            let proposal_ids_2d: Vec<Vec<_>> = roles
                .iter()
                .map(|role| self.role_votes.get(&role.name).unwrap_or_else(Vec::new))
                .collect();
            let mut proposal_indexes = vec![0usize; roles_len];

            loop {
                let mut min = u64::MAX;
                for i in 0..roles_len {
                    let j = proposal_indexes[i];
                    let proposal_id = proposal_ids_2d[i]
                        // may have gotten all of the proposal_ids watched
                        // by this role already
                        .get(j)
                        .cloned();
                    // u64::MAX has a special meaning, it cannot be an
                    // actual value
                    assert!(proposal_id != Some(u64::MAX));
                    min = u64::min(proposal_id.unwrap_or(u64::MAX), min);
                }
                // if we got all proposal_ids from all roles
                if min == u64::MAX {
                    break;
                }

                // adds a new proposal_id
                proposal_ids.push(min);

                // progress the indexes
                for i in 0..roles_len {
                    let j = &mut proposal_indexes[i];
                    if proposal_ids_2d[i][*j] == min {
                        *j += 1;
                    };
                }
            }
            proposal_ids
        };

        for proposal_id in proposal_ids {
            let mut proposal: Proposal = self
                .proposals
                .get(&proposal_id)
                .unwrap_or_else(|| env::panic_str("ERR_NO_PROPOSAL"))
                .into();

            let vote = match proposal.votes.remove(member_id) {
                // ignore proposal if `member_id` didn't vote on it
                None => continue,
                Some(vote) => vote,
            };
            let vote_bitset: VoteActionBitset = vote.clone().into();

            let kind_index = proposal.kind.to_index();

            for role in roles.iter() {
                // ignore role if it's not specifically related to the
                // given vote
                if (
                    role.permissions.0[kind_index] 
                    // the `vote_bitset` has only one bit that is set,
                    // so a divergence implies this role ignores this vote
                    & vote_bitset
                ).is_nothing() {
                    continue;
                }

                let vote_count = proposal
                    .vote_counts
                    .get_mut(&role.name)
                    .unwrap_or_else(|| env::panic_str("ERR_MISSING_VOTE_COUNT"));

                // get ammount that should be subtracted
                // (as it could be token-weigthed)
                let weight = role.weights.0[kind_index];

                // subtracts from the cached view of the target role
                vote_count[vote.clone() as usize] -= weight;

                // TODO: this requires that changes in delegations
                // should always automatically update all of that
                // user's votes
            }

            // update proposal data
            {
                self.proposals
                    .insert(&proposal_id, &VersionedProposal::Default(proposal));
            }
        }
    }
}
