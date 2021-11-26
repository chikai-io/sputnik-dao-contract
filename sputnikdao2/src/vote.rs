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
#[derive(Clone, Copy, PartialEq)]
pub struct VoteBitset(pub u8);

impl From<Vote> for VoteBitset {
    fn from(vote: Vote) -> VoteBitset {
        match vote {
            Vote::Approve => VoteBitset::APPROVE,
            Vote::Reject => VoteBitset::REJECT,
            Vote::Remove => VoteBitset::REMOVE,
        }
    }
}

impl VoteBitset {
    pub const APPROVE: Self = VoteBitset(0b001);
    pub const REJECT: Self = VoteBitset(0b010);
    pub const REMOVE: Self = VoteBitset(0b100);
    pub const NOTHING: Self = VoteBitset(0b000);

    pub fn can_approve(&self) -> bool {
        *self & Self::APPROVE == Self::APPROVE
    }

    pub fn can_reject(&self) -> bool {
        *self & Self::REJECT == Self::REJECT
    }

    pub fn can_remove(&self) -> bool {
        *self & Self::REMOVE == Self::REMOVE
    }

    pub fn is_nothing(&self) -> bool {
        *self == Self::NOTHING
    }

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
impl std::ops::BitAnd for VoteBitset {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

/// Union.
impl std::ops::BitOr for VoteBitset {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Assigning intersection.
impl std::ops::BitAndAssign for VoteBitset {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs
    }
}

/// Assigning union.
impl std::ops::BitOrAssign for VoteBitset {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs
    }
}

pub struct RoleVoteInfo {
    pub name: NewRoleName,
    pub permissions: ProposalKindVotes,
}

impl RoleVoteInfo {
    pub fn new(name: NewRoleName, permissions: ProposalKindVotes) -> Self {
        Self { name, permissions }
    }
}

// TODO: test replacing by a u64, since 15*3 bits = 45bits.
// currently, 15*8bits = 120bits.
// but would require using array shifts instead of array indexing.
//
/// A table that represents all forms of votes possible
/// on all kinds of proposals by a given role permission.
#[derive(Clone, Copy)]
pub struct ProposalKindVotes(pub [VoteBitset; PROPOSAL_KIND_LEN]);

impl Default for ProposalKindVotes {
    fn default() -> Self {
        Self([VoteBitset::NOTHING; PROPOSAL_KIND_LEN])
    }
}

impl ProposalKindVotes {
    pub fn from_label(label: &str, vote: VoteBitset) -> Self {
        let votes = match ProposalKind::label_to_index(label) {
            // `*`, repeats the vote for every label
            None => [vote; PROPOSAL_KIND_LEN],
            Some(index) => {
                let mut votes = [VoteBitset::NOTHING; PROPOSAL_KIND_LEN];
                votes[index] = vote;
                votes
            }
        };
        Self(votes)
    }

    pub fn is_nothing(&self) -> bool {
        self.0.iter().all(VoteBitset::is_nothing)
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

                let vote_bitset = VoteBitset::from_proposal_action(proposal_action);

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
                let role_vote_info = RoleVoteInfo::new(role.name.clone(), permissions);
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

                let vote_bitset = VoteBitset::from_proposal_action(proposal_action);

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

            let role_vote_info = RoleVoteInfo::new(role.name.clone(), permissions);
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

                let vote_bitset = VoteBitset::from_proposal_action(proposal_action);

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

            let role_vote_info = RoleVoteInfo::new(role.name.clone(), permissions);
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
    /// This method requires, when being called,
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
            let vote_bitset: VoteBitset = vote.clone().into();

            // remove vote observed by target role
            {
                let vote_count = proposal
                    .vote_counts
                    .get_mut(target_role_name)
                    .unwrap_or_else(|| env::panic_str("ERR_MISSING_VOTE_COUNT"));

                // get ammount that should be subtracted
                // (as it could be token-weigthed)
                let amount = if self.is_token_weighted(
                    target_role_name,
                    &proposal.kind.to_policy_label().to_string(),
                ) {
                    self.get_user_weight(member_id)
                } else {
                    1
                };
                // subtracts from the cached view of the target role
                vote_count[vote.clone() as usize] -= amount;

                // TODO: this requires that changes in delegations
                // should always automatically update all of that
                // user's votes
            }

            let kind_index = proposal.kind.to_index();

            // sanity check
            if target_role.permissions.0[kind_index] & vote_bitset == VoteBitset::NOTHING {
                unreachable!();
            }

            // if no other role observes that vote,
            // the vote should be unregistered from the proposal
            {
                let observed = other_roles.iter().any(|other_role| {
                    other_role.permissions.0[kind_index] & vote_bitset != VoteBitset::NOTHING
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
}
