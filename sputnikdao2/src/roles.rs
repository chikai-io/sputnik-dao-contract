use std::cmp::min;
use std::collections::{HashMap, HashSet};

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LazyOption, LookupMap};
use near_sdk::json_types::{U128, U64};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, AccountId, Balance};

use crate::policy::{UserInfo, VotePolicy, WeightKind};
use crate::proposals::{Proposal, ProposalId, ProposalKind, ProposalStatus, Vote};
use crate::types::Action;

use crate::*;

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq))]
#[serde(crate = "near_sdk::serde")]
pub struct RolePermission {
    /// Name of the role to display to the user.
    pub name: NewRoleName,
    /// Kind of the role: defines which users this permissions apply.
    pub kind: RoleKind,
    /// Set of proposal actions (on certain kinds of proposals) that this
    /// role allow it's members to execute.  
    /// <proposal_kind>:<proposal_action>
    pub permissions: HashSet<ProposalPermission>,
    /// For each proposal kind, defines voting policy.
    pub vote_policy: HashMap<String, VotePolicy>,
}

#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Eq, PartialEq, Hash, PartialOrd,
)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug))]
#[serde(crate = "near_sdk::serde")]
pub struct NewRoleName(pub String);

/// Set of proposal actions (on certain kinds of proposals) that a
/// role allow it's members to execute.  
/// <proposal_kind>:<proposal_action>
pub type ProposalPermission = String;

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq))]
#[serde(crate = "near_sdk::serde")]
pub enum RoleKind {
    /// Matches everyone, who is not matched by other roles.
    Everyone,
    /// Member greater or equal than given balance. Can use `1` as non-zero balance.
    Member(U128),
    /// Set of accounts.
    Group(HashSet<AccountId>),
}

pub struct RoleVoteInfo {
    pub name: NewRoleName,
    pub permissions: Vec<PermissionVoteInfo>,
}

impl RoleVoteInfo {
    pub fn new(name: NewRoleName) -> Self {
        Self {
            name,
            permissions: Vec::new(),
        }
    }

    // TODO: avoid needing this because a role can have many
    // "*"'s, and many repeated `proposal_kind` on it's permissions.
    // should use a table instead, containing all info from it's
    // permissions
    pub fn find(&self, proposal_kind: &str) -> Option<PermissionVoteInfo> {
        self.permissions
            .iter()
            .find(|permission| {
                (permission.proposal_kind == proposal_kind)
                    || (permission.proposal_kind == "*")
                    || (proposal_kind == "*")
            })
            .cloned()
    }
}

/// Permission information that are related to voting.
#[derive(Clone)]
pub struct PermissionVoteInfo {
    pub proposal_kind: String,
    pub vote_bitset: VoteBitset,
}

impl PermissionVoteInfo {
    pub fn new(proposal_kind: String, vote_bitset: VoteBitset) -> Self {
        Self {
            proposal_kind,
            vote_bitset,
        }
    }
}

pub fn default_roles(council: Vec<AccountId>) -> Vec<RolePermission> {
    vec![
        RolePermission {
            name: NewRoleName("all".to_string()),
            kind: RoleKind::Everyone,
            permissions: vec!["*:AddProposal".to_string()].into_iter().collect(),
            vote_policy: HashMap::default(),
        },
        RolePermission {
            name: NewRoleName("council".to_string()),
            kind: RoleKind::Group(council.into_iter().collect()),
            // All actions except RemoveProposal are allowed by council.
            permissions: vec![
                "*:AddProposal".to_string(),
                "*:VoteApprove".to_string(),
                "*:VoteReject".to_string(),
                "*:VoteRemove".to_string(),
                "*:Finalize".to_string(),
            ]
            .into_iter()
            .collect(),
            vote_policy: HashMap::default(),
        },
    ]
}

impl RoleKind {
    /// Checks if user matches given role.
    pub fn match_user(&self, user: &UserInfo) -> bool {
        match self {
            RoleKind::Everyone => true,
            RoleKind::Member(amount) => user.amount >= amount.0,
            RoleKind::Group(accounts) => accounts.contains(&user.account_id),
        }
    }

    /// Returns the number of people in the this role or None if not supported role kind.
    pub fn get_role_size(&self) -> Option<usize> {
        match self {
            RoleKind::Group(accounts) => Some(accounts.len()),
            _ => None,
        }
    }

    pub fn add_member_to_group(&mut self, member_id: &AccountId) -> Result<(), ()> {
        match self {
            RoleKind::Group(accounts) => {
                accounts.insert(member_id.clone());
                Ok(())
            }
            _ => Err(()),
        }
    }

    pub fn remove_member_from_group(&mut self, member_id: &AccountId) -> Result<(), ()> {
        match self {
            RoleKind::Group(accounts) => {
                accounts.remove(member_id);
                Ok(())
            }
            _ => Err(()),
        }
    }
}

impl Contract {
    // TODO: update other infos
    /// Doesn't fail, because will be used on the finalization of the proposal.
    pub fn add_role(&mut self, new_role: RolePermission) -> bool {
        for role in self.roles.iter() {
            if role.name == new_role.name {
                env::log_str(&format!(
                    "ERR_ROLE_DUPLCIATED_NAME:{}",
                    new_role.name.0.as_str()
                ));
                return false;
            }
        }
        self.roles.push(new_role.clone());
        self.init_proposal_relation(new_role.name);
        true
    }

    // TODO: update other infos
    /// Doesn't fail, because will be used on the finalization of the proposal.
    pub fn change_role(&mut self, role_name: &NewRoleName, new_role: RolePermission) -> bool {
        for role in self.roles.iter_mut() {
            let old_role_name = role.name.clone();
            if old_role_name != *role_name {
                continue;
            }

            *role = new_role;
            let old_role_proposals = self
                .role_votes
                .remove(&old_role_name)
                .unwrap_or_else(|| env::panic_str("ERR_ROLE_NAME_NOT_FOUND"));

            // TODO: need to filter-out some proposals,
            // and also scan for new proposals to add

            if let Some(_prev) = self.role_votes.insert(role_name, &old_role_proposals) {
                env::panic_str("ERR_ROLE_VOTES_REPEATED_KEY");
            }

            return true;
        }

        env::log_str(&format!("ERR_ROLE_NAME_NOT_FOUND:{}", new_role.name.0));
        false
    }

    // TODO: update other infos
    /// Doesn't fail, because will be used on the finalization of the proposal.
    pub fn remove_role(&mut self, role_name: &NewRoleName) -> bool {
        for i in 0..self.roles.len() {
            let role = &self.roles[i];
            if role.name != *role_name {
                continue;
            }

            self.roles.swap_remove(i);
            if self.role_votes.remove(role_name).is_none() {
                env::panic_str("ERR_ROLE_VOTES_MISSING_VALUE");
            }

            return true;
        }
        env::log_str(&format!("ERR_ROLE_NAME_NOT_FOUND:{}", role_name.0));
        false
    }

    // TODO: if member had voted in a proposal,
    // need to update the "role" vote cache
    ///
    /// Doesn't fail, because will be used on the finalization of the proposal.
    pub fn add_member_to_role(&mut self, role_name: &NewRoleName, member_id: &AccountId) {
        for i in 0..self.roles.len() {
            if &self.roles[i].name == role_name {
                self.roles[i]
                    .kind
                    .add_member_to_group(member_id)
                    .unwrap_or_else(|()| {
                        env::log_str(&format!("ERR_ROLE_WRONG_KIND:{}", role_name.0));
                    });
                return;
            }
        }
        env::log_str(&format!("ERR_ROLE_NOT_FOUND:{}", role_name.0));
    }

    // TODO: if member had voted in a proposal,
    // need to update the "role" vote cache
    pub fn remove_member_from_role(&mut self, role_name: &NewRoleName, member_id: &AccountId) {
        self.update_votes_from_removed_member(role_name, member_id);

        for i in 0..self.roles.len() {
            if &self.roles[i].name == role_name {
                self.roles[i]
                    .kind
                    .remove_member_from_group(member_id)
                    .unwrap_or_else(|()| {
                        env::log_str(&format!("ERR_ROLE_WRONG_KIND:{}", role_name.0));
                    });

                return;
            }
        }
        env::log_str(&format!("ERR_ROLE_NOT_FOUND:{}", role_name.0));
    }

    /// Updates the Role's vote cache stored in Proposals
    /// related to a member that is getting removed from a Role.
    ///
    /// This should be called _before_ the user is removed
    /// from the Role.
    pub fn update_votes_from_removed_member(
        &mut self,
        role_name: &NewRoleName,
        member_id: &AccountId,
    ) {
        let user_info = UserInfo::new(self, member_id.clone());
        let user_role = if let Some(user_role) =
            self.get_user_voting_role(user_info.clone(), role_name.clone())
        {
            user_role
        } else {
            // if the role that the member is being removed from
            // is not related to voting, then there is no need to update
            // anything
            return;
        };
        let user_roles: Vec<_> = self
            .get_user_voting_roles(user_info)
            .into_iter()
            .filter(|role| role.name != user_role.name)
            .collect();

        let proposals = self
            .role_votes
            .get(role_name)
            .unwrap_or_else(|| env::panic_str("ERR_ROLE_VOTES_MISSING_KEY"));
        for proposal in proposals {}
    }

    // TODO: if member had voted in a proposal,
    // need to update the "role" vote cache
    /// Removes `member_id` from all roles.  
    /// Returns `true` if the member was removed from at least one role.
    pub fn remove_member_from_all_roles(&mut self, member_id: &AccountId) -> bool {
        let mut removed_from_any = false;
        for role in self.roles.iter_mut() {
            if let RoleKind::Group(ref mut members) = role.kind {
                let removed = members.remove(member_id);

                removed_from_any |= removed;
            };
        }
        removed_from_any
    }

    /// Returns a set of role names (with the role's permissions) that this
    /// user is a member of.
    fn get_user_roles(&self, user: UserInfo) -> HashMap<NewRoleName, &HashSet<ProposalPermission>> {
        let mut roles = HashMap::default();
        for role in self.roles.iter() {
            if role.kind.match_user(&user) {
                roles.insert(role.name.clone(), &role.permissions);
            }
        }
        roles
    }

    /// Returns the role name and it's `permissions`
    /// information, that a user is related to.  
    ///
    /// Only information related to voting is considered.
    ///
    /// Returns `None` if that role is not related to voting
    /// at all.
    fn get_user_voting_role(&self, user: UserInfo, role_name: NewRoleName) -> Option<RoleVoteInfo> {
        for role in self.roles.iter() {
            if role.name != role_name {
                continue;
            }
            if !role.kind.match_user(&user) {
                continue;
            }

            let mut permissions = vec![];
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

                let proposal_kind = proposal_kind.to_string();
                permissions.push(PermissionVoteInfo::new(proposal_kind, vote_bitset));
            }

            // skip this `role` if none of it's `proposal_action`'s
            // are related to voting
            return if permissions.is_empty() {
                None
            } else {
                let mut role = RoleVoteInfo::new(role.name.clone());
                role.permissions = permissions;
                Some(role)
            };
        }
        env::panic_str("ERR_ROLE_NOT_FOUND")
    }

    /// Returns a lists relating role names, and it's `permissions`
    /// information, that a user is related to.  
    ///
    /// Only information related to voting is considered.
    fn get_user_voting_roles(&self, user: UserInfo) -> Vec<RoleVoteInfo> {
        let mut roles = vec![];
        for role in self.roles.iter() {
            if !role.kind.match_user(&user) {
                continue;
            }

            let mut permissions = vec![];
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

                let proposal_kind = proposal_kind.to_string();
                permissions.push(PermissionVoteInfo::new(proposal_kind, vote_bitset));
            }

            // skip this `role` if none of it's `proposal_action`'s
            // are related to voting
            if permissions.is_empty() {
                continue;
            }

            let mut role = RoleVoteInfo::new(role.name.clone());
            role.permissions = permissions;
            roles.push(role);
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
    fn get_user_voting_roles_filtered(
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

            let mut permissions = vec![];
            for permission in &role.permissions {
                let (proposal_kind, proposal_action) = {
                    let split: Vec<&str> = permission.split(':').collect();
                    assert_eq!(split.len(), 2);
                    (split[0], split[1])
                };

                let target_permission = if let Some(target_permission) = target
                    .permissions
                    .iter()
                    .find(|permission| permission.proposal_kind == proposal_kind)
                {
                    target_permission
                } else {
                    // skip this `proposal_kind` if it's not related to the
                    // target's ones
                    continue;
                };

                let vote_bitset = VoteBitset::from_proposal_action(proposal_action);

                // skip this `proposal_kind` if it's not related to voting,
                // or if it's not related at all to the target's types of
                // voting
                if (vote_bitset & target_permission.vote_bitset).is_nothing() {
                    continue;
                }

                let proposal_kind = proposal_kind.to_string();
                permissions.push(PermissionVoteInfo::new(proposal_kind, vote_bitset));
            }

            // skip this `role` if none of it's `proposal_action`'s
            // are related to voting, or not related to the target role
            if permissions.is_empty() {
                continue;
            }

            let mut role = RoleVoteInfo::new(role.name.clone());
            role.permissions = permissions;
            roles.push(role);
        }
        roles
    }

    /// Can given user execute given action on this proposal.
    /// Returns all roles that allow this action.
    pub fn can_execute_action(
        &self,
        user: UserInfo,
        proposal_kind: &ProposalKind,
        action: &Action,
    ) -> (Vec<NewRoleName>, bool) {
        let roles = self.get_user_roles(user);
        let mut allowed = false;
        let proposal_kind = proposal_kind.to_policy_label();
        let action = action.to_policy_label();
        let allowed_roles = roles
            .into_iter()
            .filter_map(|(role, permissions)| {
                let allowed_role = permissions.contains(&format!("{}:{}", proposal_kind, action))
                    || permissions.contains(&format!("{}:*", proposal_kind))
                    || permissions.contains(&format!("*:{}", action))
                    || permissions.contains("*:*");
                allowed = allowed || allowed_role;
                if allowed_role {
                    Some(role)
                } else {
                    None
                }
            })
            .collect();
        (allowed_roles, allowed)
    }

    /// Roles that may interact or decide the state of a proposal.  
    ///
    /// This is not related to any user nor member in particular and
    /// depends only on the Role's settings.
    pub fn allowed_roles(&self, proposal_kind: &ProposalKind, action: &Action) -> Vec<NewRoleName> {
        let proposal_kind = proposal_kind.to_policy_label();
        let action = action.to_policy_label();
        let allowed_roles = self
            .roles
            .iter()
            .filter_map(|role| {
                let permissions = &role.permissions;
                let allowed_role = permissions.contains(&format!("{}:{}", proposal_kind, action))
                    || permissions.contains(&format!("{}:*", proposal_kind))
                    || permissions.contains(&format!("*:{}", action))
                    || permissions.contains("*:*");
                if allowed_role {
                    Some(role.name.clone())
                } else {
                    None
                }
            })
            .collect();
        allowed_roles
    }

    pub fn init_proposal_relation(&mut self, role: NewRoleName) {
        if let Some(_prev) = self.role_votes.insert(&role, &vec![]) {
            env::panic_str("ERR_ROLE_VOTES_REPEATED_KEY");
        }
    }

    /// For proposals that are entering the in-progress state,
    /// adds a relationship from roles that are allowed to
    /// set that proposal's state.
    pub fn add_proposal_relation(&mut self, proposal_kind: &ProposalKind, proposal_id: ProposalId) {
        for role in self.allowed_roles(proposal_kind, &Action::AddProposal) {
            let mut proposal_ids = self
                .role_votes
                .get(&role)
                .unwrap_or_else(|| env::panic_str("ERR_ROLE_VOTES_MISSING_KEY"));
            proposal_ids.push(proposal_id);
            self.role_votes.insert(&role, &proposal_ids);
        }
    }

    /// For proposals that are leaving the in-progress state,
    /// removes the relationship from roles that are allowed to
    /// set that proposal's state.
    pub fn remove_proposal_relation(
        &mut self,
        proposal_kind: &ProposalKind,
        action: &Action,
        proposal_id: ProposalId,
    ) {
        for role in self.allowed_roles(proposal_kind, action) {
            let mut proposal_ids = self
                .role_votes
                .get(&role)
                .unwrap_or_else(|| env::panic_str("ERR_ROLE_VOTES_MISSING_KEY"));
            let i = proposal_ids
                .binary_search(&proposal_id)
                .unwrap_or_else(|_| env::panic_str("ERR_ROLE_VOTES_MISSING_ID"));
            proposal_ids.remove(i);
            self.role_votes.insert(&role, &proposal_ids);
        }
    }

    /// Returns if given proposal kind is token weighted.
    pub fn is_token_weighted(&self, role_name: &NewRoleName, proposal_kind_label: &String) -> bool {
        let role_info = self
            .internal_get_role(role_name)
            .expect("ERR_ROLE_NOT_FOUND");
        match role_info
            .vote_policy
            .get(proposal_kind_label)
            .unwrap_or(&self.policy.get().unwrap().to_policy().default_vote_policy)
            .weight_kind
        {
            WeightKind::TokenWeight => true,
            _ => false,
        }
    }

    pub fn internal_get_role(&self, role_name: &NewRoleName) -> Option<&RolePermission> {
        for role in self.roles.iter() {
            if role.name == *role_name {
                return Some(role);
            }
        }
        None
    }
}
