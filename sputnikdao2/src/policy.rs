use std::cmp::min;
use std::collections::{HashMap, HashSet};

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::{WrappedDuration, U128};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, AccountId, Balance};

use crate::proposals::{Proposal, ProposalKind, ProposalStatus, Vote};
use crate::types::Action;
use crate::Weight;

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq))]
#[serde(crate = "near_sdk::serde")]
pub enum Membership {
    /// Matches everyone, who is not matched by other roles.
    Everyone,
    /// Member greater or equal than given balance. Can use `1` as non-zero balance.
    MinimumBalance(U128),
    /// Set of accounts.
    Group(HashSet<AccountId>),
}

impl Membership {
    /// Checks if user matches given role.
    pub fn match_user(&self, user: &UserInfo) -> bool {
        match self {
            Membership::Everyone => true,
            Membership::MinimumBalance(amount) => user.amount >= amount.0,
            Membership::Group(accounts) => accounts.contains(&user.account_id),
        }
    }

    /// Returns the number of people in the this role or None if not supported role kind.
    pub fn get_role_size(&self) -> Option<usize> {
        match self {
            Membership::Group(accounts) => Some(accounts.len()),
            _ => None,
        }
    }

    pub fn add_member_to_group(&mut self, member_id: &AccountId) -> Result<(), ()> {
        match self {
            Membership::Group(accounts) => {
                accounts.insert(member_id.clone());
                Ok(())
            }
            _ => Err(()),
        }
    }

    pub fn remove_member_from_group(&mut self, member_id: &AccountId) -> Result<(), ()> {
        match self {
            Membership::Group(accounts) => {
                accounts.remove(member_id);
                Ok(())
            }
            _ => Err(()),
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq))]
#[serde(crate = "near_sdk::serde")]
pub struct RolePermission {
    /// Name of the role to display to the user.
    pub name: String,
    /// Membership of the role: defines which users this permissions apply.
    pub membership: Membership,
    /// Set of proposal actions (on certain kinds of proposals) that this
    /// role allow it's members to execute.  
    ///
    /// Stringified as:
    /// <proposal_kind>:<proposal_action>
    pub permissions: HashSet<ProposalPermission>,
    /// For each _proposal kind,_ defines a decision and voting policy.
    pub decision_policy: HashMap<String, DecisionPolicy>,
}

/// Set of proposal actions (on certain kinds of proposals) that a
/// role allow it's members to execute.  
///
/// Stringfied as:
/// <proposal_kind>:<proposal_action>
pub type ProposalPermission = String;

pub struct UserInfo {
    pub account_id: AccountId,
    pub amount: Balance,
}

/// Direct weight or ratio to total weight, used for the voting policy.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq))]
#[serde(crate = "near_sdk::serde")]
#[serde(untagged)]
pub enum WeightOrRatio {
    Weight(U128),
    Ratio(u64, u64),
}

impl WeightOrRatio {
    /// Convert weight or ratio to a specific weight given a maximum weight.
    ///
    /// The `maximum_weight` could be _the total number of tokens_
    /// (as a `Balance`), or it could be _the total count of participants
    /// of a role_.
    pub fn to_weight(&self, maximum_weight: Weight) -> Weight {
        match self {
            WeightOrRatio::Weight(weight) => min(weight.0, maximum_weight),
            WeightOrRatio::Ratio(num, denom) => min(
                (*num as u128 * maximum_weight) / *denom as u128 + 1,
                maximum_weight,
            ),
        }
    }
}

/// How the voting policy votes get weigthed.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq))]
#[serde(crate = "near_sdk::serde")]
pub enum WeightKind {
    /// Using token amounts and total delegated at the moment.
    TokenWeight,
    /// Weight of the group role. Roles that don't have scoped group are not supported.
    RoleWeight,
}

/// Defines the configuration for the decisions of a role.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq))]
#[serde(crate = "near_sdk::serde")]
pub struct DecisionPolicy {
    /// Kind of weight to use for the vote counting.
    pub weight_kind: WeightKind,
    /// A cached minimum number required for the decision to finalize.
    ///
    /// If the weight kind is [`WeightKind::TokenWeight`], then `quorum`
    /// is a cached minimum number of _tokens_ that are required.  
    /// This allows to avoid the situation where the number of staked
    /// tokens from the total supply got too small.
    ///
    /// Otherwise if the weight kind is [`WeightKind::RoleWeight`], then
    /// `quorum` is the cached minimum number of _votes_ that are required.
    /// This allows to avoid the situation where the role lost too many
    /// members but the policy requirement was kept too high, such as at
    /// 1/2, for example.
    pub quorum: U128,
    /// How many votes are required to decide in agreement.
    pub threshold: WeightOrRatio,
}

impl Default for DecisionPolicy {
    fn default() -> Self {
        DecisionPolicy {
            weight_kind: WeightKind::RoleWeight,
            quorum: U128(0),
            threshold: WeightOrRatio::Ratio(1, 2),
        }
    }
}

/// Defines voting / decision making policy of this DAO.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq))]
#[serde(crate = "near_sdk::serde")]
pub struct Policy {
    /// List of roles and permissions for them in the current policy.
    pub roles: Vec<RolePermission>,
    /// Default decision policy. Used when given proposal kind doesn't
    /// have a specific decision policy.
    pub default_decision_policy: DecisionPolicy,
    /// Proposal bond.
    pub proposal_bond: U128,
    /// Expiration period for proposals.
    pub proposal_period: WrappedDuration,
    /// Bond for claiming a bounty.
    pub bounty_bond: U128,
    /// Period in which giving up on the bounty is not punishable.
    pub bounty_forgiveness_period: WrappedDuration,
}

/// Versioned policy.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq))]
#[serde(crate = "near_sdk::serde", untagged)]
pub enum VersionedPolicy {
    /// Default policy with given accounts as council.
    Default(Vec<AccountId>),
    Current(Policy),
}

/// Defines default policy:
///     - everyone can add proposals
///     - group consisting of the call can do all actions, consists of caller.
///     - non token weighted voting, requires 1/2 of the group to vote
///     - proposal & bounty bond is 1N
///     - proposal & bounty forgiveness period is 1 day
fn default_policy(council: Vec<AccountId>) -> Policy {
    Policy {
        roles: vec![
            RolePermission {
                name: "all".to_string(),
                membership: Membership::Everyone,
                permissions: vec!["*:AddProposal".to_string()].into_iter().collect(),
                decision_policy: HashMap::default(),
            },
            RolePermission {
                name: "council".to_string(),
                membership: Membership::Group(council.into_iter().collect()),
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
                decision_policy: HashMap::default(),
            },
        ],
        default_decision_policy: DecisionPolicy::default(),
        proposal_bond: U128(10u128.pow(24)),
        proposal_period: WrappedDuration::from(1_000_000_000 * 60 * 60 * 24 * 7),
        bounty_bond: U128(10u128.pow(24)),
        bounty_forgiveness_period: WrappedDuration::from(1_000_000_000 * 60 * 60 * 24),
    }
}

impl VersionedPolicy {
    /// Upgrades either version of policy into the latest.
    pub fn upgrade(self) -> Self {
        match self {
            VersionedPolicy::Default(accounts) => {
                VersionedPolicy::Current(default_policy(accounts))
            }
            VersionedPolicy::Current(policy) => VersionedPolicy::Current(policy),
        }
    }

    /// Return recent version of policy.
    pub fn to_policy(self) -> Policy {
        match self {
            VersionedPolicy::Current(policy) => policy,
            _ => unimplemented!(),
        }
    }

    pub fn to_policy_mut(&mut self) -> &mut Policy {
        match self {
            VersionedPolicy::Current(policy) => policy,
            _ => unimplemented!(),
        }
    }
}

impl Policy {
    ///
    /// Doesn't fail, because will be used on the finalization of the proposal.
    pub fn add_member_to_role(&mut self, role_name: &String, member_id: &AccountId) {
        if let Some(role) = self.roles.iter_mut().find(|role| role.name == *role_name) {
            role.membership
                .add_member_to_group(member_id)
                .unwrap_or_else(|()| {
                    env::log(format!("ERR_ROLE_WRONG_KIND:{}", role_name).as_bytes());
                });
        } else {
            env::log(&format!("ERR_ROLE_NOT_FOUND:{}", role_name).into_bytes());
        }
    }

    pub fn remove_member_from_role(&mut self, role_name: &String, member_id: &AccountId) {
        if let Some(role) = self.roles.iter_mut().find(|role| role.name == *role_name) {
            role.membership
                .remove_member_from_group(member_id)
                .unwrap_or_else(|()| {
                    env::log(&format!("ERR_ROLE_WRONG_KIND:{}", role_name).into_bytes());
                });
        } else {
            env::log(&format!("ERR_ROLE_NOT_FOUND:{}", role_name).into_bytes());
        }
    }

    /// Removes `member_id` from all roles.  
    /// Returns `true` if the member was removed from at least one role.
    pub fn remove_member_from_all_roles(&mut self, member_id: &AccountId) -> bool {
        let mut removed = false;
        for role in self.roles.iter_mut() {
            if let Membership::Group(ref mut members) = role.membership {
                removed |= members.remove(member_id);
            };
        }
        removed
    }

    /// Returns a set of role names (with the role's permissions) that this
    /// user is a member of.
    fn get_user_roles(&self, user: UserInfo) -> HashMap<String, &HashSet<ProposalPermission>> {
        let mut roles = HashMap::default();
        for role in self.roles.iter() {
            if role.membership.match_user(&user) {
                roles.insert(role.name.clone(), &role.permissions);
            }
        }
        roles
    }

    /// Whether the `user` can execute the `action` on `proposal_kind`.
    /// Returns all roles that allow this action.
    pub fn can_execute_action(
        &self,
        user: UserInfo,
        proposal_kind: &ProposalKind,
        action: &Action,
    ) -> (Vec<String>, bool) {
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
                allowed |= allowed_role;
                if allowed_role {
                    Some(role)
                } else {
                    None
                }
            })
            .collect();
        (allowed_roles, allowed)
    }

    /// Returns if given proposal kind is token weighted.
    pub fn is_token_weighted(&self, role_name: &String, proposal_kind_label: &String) -> bool {
        let role_info = self
            .internal_get_role(role_name)
            .expect("ERR_ROLE_NOT_FOUND");
        matches!(
            role_info
                .decision_policy
                .get(proposal_kind_label)
                .unwrap_or(&self.default_decision_policy)
                .weight_kind,
            WeightKind::TokenWeight
        )
    }

    fn internal_get_role(&self, name: &String) -> Option<&RolePermission> {
        self.roles.iter().find(|role| role.name == *name)
    }

    /// Get proposal status for given proposal.
    /// Usually is called after changing it's state.
    pub fn proposal_status(
        &self,
        proposal: &Proposal,
        role_names: Vec<String>,
        total_supply: Balance,
    ) -> ProposalStatus {
        assert_eq!(
            proposal.status,
            ProposalStatus::InProgress,
            "ERR_PROPOSAL_NOT_IN_PROGRESS"
        );
        if env::block_timestamp() >= proposal.submission_time.0 + self.proposal_period.0 {
            // Proposal expired.
            return ProposalStatus::Expired;
        };
        for role_name in role_names {
            let role = self
                .internal_get_role(&role_name)
                .expect("ERR_MISSING_ROLE");
            let decision_policy = role
                .decision_policy
                .get(&proposal.kind.to_policy_label().to_string())
                .unwrap_or(&self.default_decision_policy);
            let decision_threshold = std::cmp::max(
                decision_policy.quorum.0,
                match &decision_policy.weight_kind {
                    WeightKind::TokenWeight => {
                        decision_policy.threshold.to_weight(total_supply as Weight)
                    }
                    WeightKind::RoleWeight => decision_policy.threshold.to_weight(
                        role.membership
                            .get_role_size()
                            .expect("ERR_UNSUPPORTED_ROLE") as Weight,
                    ),
                },
            );
            // Check if there is anything voted above the threshold
            // specified by policy for given role.
            let vote_counts = proposal
                .vote_counts
                .get(&role_name)
                .expect("ERR_MISSING_ROLE");
            if vote_counts[Vote::Approve as usize] >= decision_threshold {
                return ProposalStatus::Approved;
            } else if vote_counts[Vote::Reject as usize] >= decision_threshold {
                return ProposalStatus::Rejected;
            } else if vote_counts[Vote::Remove as usize] >= decision_threshold {
                return ProposalStatus::Removed;
            } else {
                // continue to next role.
            }
        }
        proposal.status.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vote_policy() {
        let r1 = WeightOrRatio::Weight(U128(100));
        assert_eq!(r1.to_weight(1_000_000), 100);
        let r2 = WeightOrRatio::Ratio(1, 2);
        assert_eq!(r2.to_weight(2), 2);
        let r2 = WeightOrRatio::Ratio(1, 2);
        assert_eq!(r2.to_weight(5), 3);
        let r2 = WeightOrRatio::Ratio(1, 1);
        assert_eq!(r2.to_weight(5), 5);
    }
}
