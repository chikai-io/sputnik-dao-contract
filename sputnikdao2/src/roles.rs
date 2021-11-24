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
