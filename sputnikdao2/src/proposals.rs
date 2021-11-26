use std::collections::HashMap;
use std::convert::TryFrom;

use near_contract_standards::fungible_token::core_impl::ext_fungible_token;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::{Base64VecU8, U128, U64};
use near_sdk::{log, AccountId, Balance, Gas, PromiseOrValue};

use crate::policy::UserInfo;
use crate::types::{
    upgrade_remote, upgrade_self, Action, Config, GAS_FOR_FT_TRANSFER, ONE_YOCTO_NEAR,
};
use crate::*;

/// Status of a proposal.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(crate = "near_sdk::serde")]
pub enum ProposalStatus {
    InProgress,
    /// If quorum voted yes, this proposal is successfully approved.
    Approved,
    /// If quorum voted no, this proposal is rejected. Bond is returned.
    Rejected,
    /// If quorum voted to remove (e.g. spam), this proposal is rejected and bond is not returned.
    /// Interfaces shouldn't show removed proposals.
    Removed,
    /// Expired after period of time.
    Expired,
    /// If proposal was moved to Hub or somewhere else.
    Moved,
}

/// Function call arguments.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug))]
#[serde(crate = "near_sdk::serde")]
pub struct ActionCall {
    method_name: String,
    args: Base64VecU8,
    deposit: U128,
    gas: U64,
}

/// Kinds of proposals, doing different action.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug))]
#[serde(crate = "near_sdk::serde")]
pub enum ProposalKind {
    /// Change the DAO config.
    ChangeConfig {
        config: Config,
    },
    /// Change the full policy.
    ChangePolicy {
        policy: VersionedPolicy,
    },
    AddRole {
        role: RolePermission,
    },
    ChangeRole {
        name: NewRoleName,
        change_to: RolePermission,
    },
    RemoveRole {
        name: NewRoleName,
    },
    /// Add member to given role in the policy. This is short cut to updating the whole policy.
    AddMemberToRole {
        member_id: AccountId,
        role: NewRoleName,
    },
    /// Remove member to given role in the policy. This is short cut to updating the whole policy.
    RemoveMemberFromRole {
        member_id: AccountId,
        role: NewRoleName,
    },
    /// Calls `receiver_id` with list of method names in a single promise.
    /// Allows this contract to execute any arbitrary set of actions in other contracts.
    FunctionCall {
        receiver_id: AccountId,
        actions: Vec<ActionCall>,
    },
    /// Upgrade this contract with given hash from blob store.
    UpgradeSelf {
        hash: Base58CryptoHash,
    },
    /// Upgrade another contract, by calling method with the code from given hash from blob store.
    UpgradeRemote {
        receiver_id: AccountId,
        method_name: String,
        hash: Base58CryptoHash,
    },
    /// Transfers given amount of `token_id` from this DAO to `receiver_id`.
    /// If `msg` is not None, calls `ft_transfer_call` with given `msg`. Fails if this base token.
    /// For `ft_transfer` and `ft_transfer_call` `memo` is the `description` of the proposal.
    Transfer {
        /// Can be "" for $NEAR or a valid account id.
        #[serde(with = "serde_with::rust::string_empty_as_none")]
        token_id: Option<AccountId>,
        receiver_id: AccountId,
        amount: U128,
        msg: Option<String>,
    },
    /// Sets staking contract. Can only be proposed if staking contract is not set yet.
    SetStakingContract {
        staking_id: AccountId,
    },
    /// Add new bounty.
    AddBounty {
        bounty: Bounty,
    },
    /// Indicates that given bounty is done by given user.
    BountyDone {
        bounty_id: u64,
        receiver_id: AccountId,
    },
    /// Just a signaling vote, with no execution.
    Vote,
}
pub const PROPOSAL_KIND_LEN: usize = 15;

impl ProposalKind {
    /// Returns label of policy for given type of proposal.
    pub fn to_policy_label(&self) -> &str {
        match self {
            ProposalKind::ChangeConfig { .. } => "config",
            ProposalKind::ChangePolicy { .. } => "policy",
            ProposalKind::AddRole { .. } => "add_role",
            ProposalKind::ChangeRole { .. } => "change_role",
            ProposalKind::RemoveRole { .. } => "remove_role",
            ProposalKind::AddMemberToRole { .. } => "add_member_to_role",
            ProposalKind::RemoveMemberFromRole { .. } => "remove_member_from_role",
            ProposalKind::FunctionCall { .. } => "call",
            ProposalKind::UpgradeSelf { .. } => "upgrade_self",
            ProposalKind::UpgradeRemote { .. } => "upgrade_remote",
            ProposalKind::Transfer { .. } => "transfer",
            ProposalKind::SetStakingContract { .. } => "set_vote_token",
            ProposalKind::AddBounty { .. } => "add_bounty",
            ProposalKind::BountyDone { .. } => "bounty_done",
            ProposalKind::Vote => "vote",
        }
    }

    pub fn to_index(&self) -> usize {
        match self {
            ProposalKind::ChangeConfig { .. } => 0,
            ProposalKind::ChangePolicy { .. } => 1,
            ProposalKind::AddRole { .. } => 2,
            ProposalKind::ChangeRole { .. } => 3,
            ProposalKind::RemoveRole { .. } => 4,
            ProposalKind::AddMemberToRole { .. } => 5,
            ProposalKind::RemoveMemberFromRole { .. } => 6,
            ProposalKind::FunctionCall { .. } => 7,
            ProposalKind::UpgradeSelf { .. } => 8,
            ProposalKind::UpgradeRemote { .. } => 9,
            ProposalKind::Transfer { .. } => 10,
            ProposalKind::SetStakingContract { .. } => 11,
            ProposalKind::AddBounty { .. } => 12,
            ProposalKind::BountyDone { .. } => 13,
            ProposalKind::Vote => 14,
        }
    }

    pub fn label_to_index(label: &str) -> Option<usize> {
        match label {
            "*" => None,
            "config" => Some(0),
            "policy" => Some(1),
            "add_role" => Some(2),
            "change_role" => Some(3),
            "remove_role" => Some(4),
            "add_member_to_role" => Some(5),
            "remove_member_from_role" => Some(6),
            "call" => Some(7),
            "upgrade_self" => Some(8),
            "upgrade_remote" => Some(9),
            "transfer" => Some(10),
            "set_vote_token" => Some(11),
            "add_bounty" => Some(12),
            "bounty_done" => Some(13),
            "vote" => Some(14),
            _ => env::panic_str("ERR_BAD_PROPOSAL_KIND_LABEL"),
        }
    }
}

pub type ProposalId = u64;

/// Proposal that are sent to this DAO.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug))]
#[serde(crate = "near_sdk::serde")]
pub struct Proposal {
    /// Original proposer.
    pub proposer: AccountId,
    /// Description of this proposal.
    pub description: String,
    /// Kind of proposal with relevant information.
    pub kind: ProposalKind,
    /// Current status of the proposal.
    pub status: ProposalStatus,
    /// Count of votes per role per decision: yes / no / spam.
    pub vote_counts: HashMap<NewRoleName, [Balance; 3]>,
    /// Map of who voted and how.
    pub votes: HashMap<AccountId, Vote>,
    /// Submission time (for voting period).
    pub submission_time: U64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug))]
#[serde(crate = "near_sdk::serde")]
pub enum VersionedProposal {
    Default(Proposal),
}

impl From<VersionedProposal> for Proposal {
    fn from(v: VersionedProposal) -> Self {
        match v {
            VersionedProposal::Default(p) => p,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct ProposalInput {
    /// Description of this proposal.
    pub description: String,
    /// Kind of proposal with relevant information.
    pub kind: ProposalKind,
}

impl From<ProposalInput> for Proposal {
    fn from(input: ProposalInput) -> Self {
        Self {
            proposer: env::predecessor_account_id(),
            description: input.description,
            kind: input.kind,
            status: ProposalStatus::InProgress,
            vote_counts: HashMap::default(),
            votes: HashMap::default(),
            submission_time: U64::from(env::block_timestamp()),
        }
    }
}

impl Contract {
    /// Execute payout of given token to given user.
    pub(crate) fn internal_payout(
        &mut self,
        token_id: &Option<AccountId>,
        receiver_id: &AccountId,
        amount: Balance,
        memo: String,
        msg: Option<String>,
    ) -> PromiseOrValue<()> {
        if token_id.is_none() {
            Promise::new(receiver_id.clone()).transfer(amount).into()
        } else {
            if let Some(msg) = msg {
                ext_fungible_token::ft_transfer_call(
                    receiver_id.clone(),
                    U128(amount),
                    Some(memo),
                    msg,
                    token_id.as_ref().unwrap().clone(),
                    ONE_YOCTO_NEAR,
                    GAS_FOR_FT_TRANSFER,
                )
                .into()
            } else {
                ext_fungible_token::ft_transfer(
                    receiver_id.clone(),
                    U128(amount),
                    Some(memo),
                    token_id.as_ref().unwrap().clone(),
                    ONE_YOCTO_NEAR,
                    GAS_FOR_FT_TRANSFER,
                )
                .into()
            }
        }
    }

    /// Executes given proposal and updates the contract's state.
    fn internal_execute_proposal(
        &mut self,
        policy: &Policy,
        proposal: &Proposal,
    ) -> PromiseOrValue<()> {
        // Return the proposal bond.
        Promise::new(proposal.proposer.clone()).transfer(policy.proposal_bond.0);
        match &proposal.kind {
            ProposalKind::ChangeConfig { config } => {
                self.config.set(config);
                PromiseOrValue::Value(())
            }
            ProposalKind::ChangePolicy { policy } => {
                self.policy.set(policy);
                PromiseOrValue::Value(())
            }
            ProposalKind::AddRole { role } => {
                self.add_role(role.clone());
                PromiseOrValue::Value(())
            }
            ProposalKind::ChangeRole { name, change_to } => {
                self.change_role(name, change_to.clone());
                PromiseOrValue::Value(())
            }
            ProposalKind::RemoveRole { name } => {
                self.remove_role(name);
                PromiseOrValue::Value(())
            }
            ProposalKind::AddMemberToRole { member_id, role } => {
                self.add_member_to_role(role, &member_id.clone());
                // let mut new_policy = policy.clone();
                // new_policy.add_member_to_role(role, &member_id.clone().into());
                // self.policy.set(&VersionedPolicy::Current(new_policy));
                PromiseOrValue::Value(())
            }
            ProposalKind::RemoveMemberFromRole { member_id, role } => {
                self.remove_member_from_role(role, &member_id.clone());
                // let mut new_policy = policy.clone();
                // new_policy.remove_member_from_role_name(role, &member_id.clone().into());
                // self.policy.set(&VersionedPolicy::Current(new_policy));
                PromiseOrValue::Value(())
            }
            ProposalKind::FunctionCall {
                receiver_id,
                actions,
            } => {
                let mut promise = Promise::new(receiver_id.clone());
                for action in actions {
                    promise = promise.function_call(
                        action.method_name.clone(),
                        action.args.clone().into(),
                        action.deposit.0,
                        Gas(action.gas.0),
                    )
                }
                promise.into()
            }
            ProposalKind::UpgradeSelf { hash } => {
                upgrade_self(&CryptoHash::from(*hash));
                PromiseOrValue::Value(())
            }
            ProposalKind::UpgradeRemote {
                receiver_id,
                method_name,
                hash,
            } => {
                upgrade_remote(&receiver_id.clone(), method_name, &CryptoHash::from(*hash));
                PromiseOrValue::Value(())
            }
            ProposalKind::Transfer {
                token_id,
                receiver_id,
                amount,
                msg,
            } => self.internal_payout(
                token_id,
                &receiver_id.clone(),
                amount.0,
                proposal.description.clone(),
                msg.clone(),
            ),
            ProposalKind::SetStakingContract { staking_id } => {
                assert!(self.staking_id.is_none(), "ERR_INVALID_STAKING_CHANGE");
                self.staking_id = Some(staking_id.clone());
                PromiseOrValue::Value(())
            }
            ProposalKind::AddBounty { bounty } => {
                self.internal_add_bounty(bounty);
                PromiseOrValue::Value(())
            }
            ProposalKind::BountyDone {
                bounty_id,
                receiver_id,
            } => self.internal_execute_bounty_payout(*bounty_id, &receiver_id.clone(), true),
            ProposalKind::Vote => PromiseOrValue::Value(()),
        }
    }

    /// Process rejecting proposal.
    fn internal_reject_proposal(
        &mut self,
        policy: &Policy,
        proposal: &Proposal,
        return_bond: bool,
    ) -> PromiseOrValue<()> {
        if return_bond {
            // Return bond to the proposer.
            Promise::new(proposal.proposer.clone()).transfer(policy.proposal_bond.0);
        }
        match &proposal.kind {
            ProposalKind::BountyDone {
                bounty_id,
                receiver_id,
            } => self.internal_execute_bounty_payout(*bounty_id, &receiver_id.clone(), false),
            _ => PromiseOrValue::Value(()),
        }
    }

    pub(crate) fn internal_user_info(&self) -> UserInfo {
        let account_id = env::predecessor_account_id();
        UserInfo::new(&self, account_id)
    }

    /// Adds vote of the given user with given `amount` of weight. If user already voted, fails.
    pub fn update_votes(
        &mut self,
        proposal: &mut Proposal,
        account_id: &AccountId,
        roles: &[NewRoleName],
        vote: Vote,
        policy: &Policy,
        user_weight: Balance,
    ) {
        for role in roles {
            let amount =
                if self.is_token_weighted(role, &proposal.kind.to_policy_label().to_string()) {
                    user_weight
                } else {
                    1
                };
            proposal
                .vote_counts
                .entry(role.clone())
                .or_insert([0u128; 3])[vote.clone() as usize] += amount;
        }
        assert!(
            proposal.votes.insert(account_id.clone(), vote).is_none(),
            "ERR_ALREADY_VOTED"
        );
    }

    // /// Removes vote of the given user with given `amount` of weight. If user has no registered vote, fails.
    // pub fn update_votes_removed(
    //     &mut self,
    //     account_id: &AccountId,
    //     roles: &[RoleId],
    //     vote: Vote,
    //     policy: &Policy,
    //     user_weight: Balance,
    // ) {
    //     for role in roles {
    //         let amount = if policy.is_token_weighted(role, &self.kind.to_policy_label().to_string())
    //         {
    //             user_weight
    //         } else {
    //             1
    //         };
    //         self.vote_counts.entry(role.clone()).or_insert([0u128; 3])[vote.clone() as usize] +=
    //             amount;
    //     }
    //     assert!(
    //         self.votes.insert(account_id.clone(), vote).is_none(),
    //         "ERR_ALREADY_VOTED"
    //     );
    // }
}

#[near_bindgen]
impl Contract {
    /// Add proposal to this DAO.
    #[payable]
    pub fn add_proposal(&mut self, proposal: ProposalInput) -> ProposalId {
        // 0. validate bond attached.
        // TODO: consider bond in the token of this DAO.
        let policy = self.policy.get().unwrap().to_policy();
        assert!(
            env::attached_deposit() >= policy.proposal_bond.0,
            "ERR_MIN_BOND"
        );

        // 1. Validate proposal.
        match &proposal.kind {
            ProposalKind::ChangePolicy { policy } => match policy {
                VersionedPolicy::Current(_) => {}
                _ => panic!("ERR_INVALID_POLICY"),
            },
            ProposalKind::Transfer { token_id, msg, .. } => {
                assert!(
                    !(token_id.is_none()) || msg.is_none(),
                    "ERR_BASE_TOKEN_NO_MSG"
                );
            }
            ProposalKind::SetStakingContract { .. } => assert!(
                self.staking_id.is_none(),
                "ERR_STAKING_CONTRACT_CANT_CHANGE"
            ),
            // TODO: add more verifications.
            _ => {}
        };

        // 2. Check permission of caller to add this type of proposal.
        assert!(
            self.can_execute_action(
                self.internal_user_info(),
                &proposal.kind,
                &Action::AddProposal
            )
            .1,
            "ERR_PERMISSION_DENIED"
        );

        // 3. Actually add proposal to the current list of proposals.
        let id = self.last_proposal_id;
        self.proposals
            .insert(&id, &VersionedProposal::Default(proposal.clone().into()));
        self.last_proposal_id += 1;

        // 4. For this new in-progress proposal,
        // adds a relationship from the roles that can decide it's
        // state
        self.add_proposal_relation(&proposal.kind, id);

        id
    }

    /// Act on given proposal by id, if permissions allow.
    /// Memo is logged but not stored in the state. Can be used to leave notes or explain the action.
    pub fn act_proposal(&mut self, id: ProposalId, action: Action, memo: Option<String>) {
        let mut proposal: Proposal = self
            .proposals
            .get(&id)
            .unwrap_or_else(|| env::panic_str("ERR_NO_PROPOSAL"))
            .into();
        let policy = self.policy.get().unwrap().to_policy();
        // Check permissions for the given action.
        let (roles, allowed) =
            self.can_execute_action(self.internal_user_info(), &proposal.kind, &action);
        if !allowed {
            env::panic_str("ERR_PERMISSION_DENIED")
        }
        let sender_id = env::predecessor_account_id();
        // Update proposal given action. Returns true if should be updated in storage.
        let update_proposal = match action {
            Action::AddProposal => env::panic_str("ERR_WRONG_ACTION"),
            Action::RemoveProposal => {
                self.proposals.remove(&id);
                // proposal no longer in-progress
                self.remove_proposal_relation(&proposal.kind, &action, id);
                false
            }
            Action::VoteApprove | Action::VoteReject | Action::VoteRemove => {
                assert_eq!(
                    proposal.status,
                    ProposalStatus::InProgress,
                    "ERR_PROPOSAL_NOT_IN_PROGRESS"
                );
                self.update_votes(
                    &mut proposal,
                    &sender_id,
                    &roles,
                    Vote::from(action.clone()),
                    &policy,
                    self.get_user_weight(&sender_id),
                );
                // Updates proposal status with new votes using the policy.
                proposal.status =
                    self.proposal_status(&proposal, &policy, roles, self.total_delegation_amount);
                match proposal.status {
                    ProposalStatus::Approved => {
                        // proposal no longer in-progress
                        self.remove_proposal_relation(&proposal.kind, &action, id);

                        self.internal_execute_proposal(&policy, &proposal);
                        true
                    }
                    ProposalStatus::Rejected => {
                        self.internal_reject_proposal(&policy, &proposal, true);
                        // proposal no longer in-progress
                        self.remove_proposal_relation(&proposal.kind, &action, id);
                        true
                    }
                    ProposalStatus::Removed => {
                        self.internal_reject_proposal(&policy, &proposal, false);
                        self.proposals.remove(&id);
                        // proposal no longer in-progress
                        self.remove_proposal_relation(&proposal.kind, &action, id);
                        false
                    }
                    _ => {
                        // Still in progress, moved or expired.
                        true
                    }
                }
            }
            Action::Finalize => {
                proposal.status = self.proposal_status(
                    &proposal,
                    &policy,
                    self.roles.iter().map(|r| r.name.clone()).collect(),
                    self.total_delegation_amount,
                );
                match proposal.status {
                    // no decision made
                    ProposalStatus::InProgress => false,
                    ProposalStatus::Approved => {
                        self.internal_execute_proposal(&policy, &proposal);
                        // proposal no longer in-progress
                        self.remove_proposal_relation(&proposal.kind, &action, id);
                        true
                    }
                    ProposalStatus::Rejected => {
                        self.internal_reject_proposal(&policy, &proposal, true);
                        // proposal no longer in-progress
                        self.remove_proposal_relation(&proposal.kind, &action, id);
                        true
                    }
                    ProposalStatus::Removed => {
                        self.internal_reject_proposal(&policy, &proposal, false);
                        self.proposals.remove(&id);
                        // proposal no longer in-progress
                        self.remove_proposal_relation(&proposal.kind, &action, id);
                        false
                    }
                    ProposalStatus::Expired => {
                        self.internal_reject_proposal(&policy, &proposal, true);
                        // proposal no longer in-progress
                        self.remove_proposal_relation(&proposal.kind, &action, id);
                        true
                    }
                    ProposalStatus::Moved => {
                        // not yet implemented
                        env::panic_str("ERR_TODO_MOVED_PROPOSAL")
                    }
                }
            }
            Action::MoveToHub => false,
        };
        if update_proposal {
            self.proposals
                .insert(&id, &VersionedProposal::Default(proposal));
        }
        if let Some(memo) = memo {
            log!("Memo: {}", memo);
        }
    }
}
