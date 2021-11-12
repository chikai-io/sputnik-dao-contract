use std::collections::HashMap;

use near_sdk::json_types::U128;
use near_sdk::AccountId;
use near_sdk_sim::{call, to_yocto, view, UserAccount};

use sputnikdao2::{
    Action, DecisionPolicy, Membership, Policy, Proposal, ProposalInput, ProposalKind,
    ProposalStatus, RolePermission, VersionedPolicy,
};

use crate::utils::{
    add_member_proposal, add_member_to_role_proposal, add_proposal, setup_dao, setup_staking,
    setup_test_token, to_va, vote,
};

mod utils;

fn user(id: u32) -> String {
    format!("user{}", id)
}

/// Users (2, 3) collude against users (4, 5) to pass a proposal without
/// having all the necessary tokens.
///
/// 1. The dao, the users, the test-token contract and the staking
/// contract were created.
/// 2. Create a role that is token-based and change the policy to reflect
/// that.
/// 3. In the dao, register which acc id is the staking contract.
/// 4. Register users 2~5 in the staking and token contracts,
/// (the staking acc should also be registered in the token contract).
/// 5. Give each user a token, and have them transfer to the staking acc.
/// 6. Have the users call for delegation in the dao, regarding the
/// staking contract.
#[test]
fn test_staking_collusion() {
    // 1
    let (root, dao) = setup_dao();
    let user2 = root.create_user(user(2), to_yocto("1000"));
    let user3 = root.create_user(user(3), to_yocto("1000"));
    let user4 = root.create_user(user(4), to_yocto("1000"));
    let user5 = root.create_user(user(5), to_yocto("1000"));
    let test_token = setup_test_token(&root);
    let staking = setup_staking(&root);

    assert!(view!(dao.get_staking_contract())
        .unwrap_json::<AccountId>()
        .is_empty());

    // 2- creates a new token-based role, and add members to it
    {
        use sputnikdao2::{WeightKind, WeightOrRatio};
        use std::collections::HashSet;

        let token_role = {
            let mut token_role = RolePermission {
                name: "token_role".to_string(),
                membership: Membership::Group(HashSet::new()),
                permissions: HashSet::new(),
                decision_policy: HashMap::new(),
            };
            let token_based_decision = DecisionPolicy {
                weight_kind: WeightKind::TokenWeight,
                quorum: 0u128.into(),
                threshold: WeightOrRatio::Weight(3u128.into()),
            };
            token_role
                .decision_policy
                .insert("*".to_string(), token_based_decision);
            let permission = "*:*";
            token_role.permissions.insert(permission.to_string());
            token_role
        };

        // change the policy to reflect the token-based role
        {
            let mut policy = view!(dao.get_policy()).unwrap_json::<Policy>();
            // adds the token-based role
            policy.roles.push(token_role);
            add_proposal(
                &root,
                &dao,
                ProposalInput {
                    description: "new_policy".to_string(),
                    kind: ProposalKind::ChangePolicy {
                        policy: VersionedPolicy::Current(policy.clone()),
                    },
                },
            )
            .assert_success();
            let change_policy_proposal_id = view!(dao.get_last_proposal_id()).unwrap_json::<u64>();
            assert_eq!(change_policy_proposal_id, 1);
            call!(
                root,
                dao.act_proposal(change_policy_proposal_id - 1, Action::VoteApprove, None)
            )
            .assert_success();
        }

        let add_to_token_role = |user: &UserAccount| {
            add_member_to_role_proposal(
                &root,
                &dao,
                user.account_id.clone(),
                "token_role".to_string(),
            )
            .assert_success();

            // approval
            let proposal = view!(dao.get_last_proposal_id()).unwrap_json::<u64>();

            // only root is needed for approval since root is the only user
            // on the "council" role
            call!(
                root,
                dao.act_proposal(proposal - 1, Action::VoteApprove, None)
            )
            .assert_success();
        };
        add_to_token_role(&user2);
        add_to_token_role(&user3);
        add_to_token_role(&user4);
        add_to_token_role(&user5);
    }

    fn group_members(membership: &Membership) -> Vec<&str> {
        if let Membership::Group(members) = membership {
            let mut members: Vec<_> = members.iter().map(|m| m.as_str()).collect();
            members.sort();
            members
        } else {
            vec![]
        }
    }

    // users 2~5 are in the token-based role
    {
        let policy = view!(dao.get_policy()).unwrap_json::<Policy>();
        assert_eq!(policy.roles.len(), 3);
        assert_eq!(
            group_members(&policy.roles[2].membership),
            vec![
                &user2.account_id,
                &user3.account_id,
                &user4.account_id,
                &user5.account_id,
            ]
        );
    }

    // 3- add and approve staking config
    {
        add_proposal(
            &root,
            &dao,
            ProposalInput {
                description: "add staking acc id".to_string(),
                kind: ProposalKind::SetStakingContract {
                    staking_id: to_va("staking".to_string()),
                },
            },
        )
        .assert_success();

        let proposal = view!(dao.get_last_proposal_id()).unwrap_json::<u64>();
        vote(vec![&root], &dao, proposal - 1);

        assert!(!view!(dao.get_staking_contract())
            .unwrap_json::<AccountId>()
            .is_empty());
        assert_eq!(
            view!(dao.get_proposal(proposal - 1))
                .unwrap_json::<Proposal>()
                .status,
            ProposalStatus::Approved
        );
    };

    // 4,5- mint the token to each users, and they transfers to the staking
    // acc on the token
    {
        // assert the token has not been minted
        assert_eq!(
            view!(staking.ft_total_supply()).unwrap_json::<U128>().0,
            to_yocto("0")
        );

        // creates the staking user account on the token
        call!(
            root,
            test_token.storage_deposit(Some(to_va(staking.account_id())), None),
            deposit = to_yocto("1")
        )
        .assert_success();

        let mint_to_user = |user: &UserAccount| {
            // mint tokens to the user
            call!(
                user,
                test_token.mint(to_va(user.account_id.clone()), U128(to_yocto("1")))
            )
            .assert_success();

            // register the user in the staking contract
            call!(
                user,
                staking.storage_deposit(None, None),
                deposit = to_yocto("1")
            );

            // make users transfer to staking acc, on the token contract
            call!(
                user,
                test_token.ft_transfer_call(
                    to_va(staking.account_id()),
                    U128(to_yocto("1")),
                    None,
                    "".to_string()
                ),
                deposit = 1
            )
            .assert_success();
        };

        // 5- users are registered and get 1 token each,
        // and they transfer to the staking acc in the token
        {
            mint_to_user(&user2);
            mint_to_user(&user3);
            mint_to_user(&user4);
            mint_to_user(&user5);
        }

        // total of tokens is 4
        assert_eq!(
            view!(staking.ft_total_supply()).unwrap_json::<U128>().0,
            to_yocto("4")
        );
    }

    // each user delegates to themselves
    for user in [&user2, &user3, &user4, &user5] {
        call!(
            user,
            staking.delegate(to_va(user.account_id.clone()), U128(to_yocto("1")))
        )
        .assert_success();

        // check the dao ack
        assert_eq!(
            view!(dao.delegation_balance_of(to_va(user.account_id.clone())))
                .unwrap_json::<U128>()
                .0,
            to_yocto("1")
        );
    }
    // check the dao ack of the total
    assert_eq!(
        view!(dao.delegation_total_supply()).unwrap_json::<U128>().0,
        to_yocto("4")
    );

    // two identical proposals are created, which are about adding
    // users 6 and 7,
    //
    // for adding user 6, users (2, 3) will vote normally and will fail
    // to approve it alone;
    // for adding user 7, users (2, 3) will collude and will successfully
    // aprove it, without approval of users (4, 5) (which won't vote for
    // anything)

    let user_normal = root.create_user(user(6), to_yocto("1000"));
    let user_colluded = root.create_user(user(7), to_yocto("1000"));

    add_member_proposal(&root, &dao, user_normal.account_id.clone()).assert_success();
    let add_user_normal = view!(dao.get_last_proposal_id()).unwrap_json::<u64>();

    add_member_proposal(&root, &dao, user_colluded.account_id.clone()).assert_success();
    let add_user_colluded = view!(dao.get_last_proposal_id()).unwrap_json::<u64>();

    // users (2, 3) vote for the add_user_normal, and we check that it
    // hasn't passed yet
    {
        vote(vec![&user2, &user3], &dao, add_user_normal - 1);
        assert_eq!(
            view!(dao.get_proposal(add_user_normal - 1))
                .unwrap_json::<Proposal>()
                .status,
            ProposalStatus::InProgress
        );
    }

    // colluded token voting
    {
        // for the other proposal, user2 first votes
        vote(vec![&user2], &dao, add_user_colluded - 1);

        // undelegates to be able to withdraw
        // assert_eq!(
        //     view!(dao.delegation_balance_of(to_va(user2.account_id.clone())))
        //         .unwrap_json::<U128>()
        //         .0,
        //     to_yocto("1")
        // );
        call!(
            user2,
            staking.undelegate(to_va(user2.account_id.clone()), U128(to_yocto("1")))
        )
        .assert_success();
        // check the dao ack
        // TODO: in a test run, instead of being `0`
        // the value was `1000000000000000000000000` ..?
        assert_eq!(
            view!(dao.delegation_balance_of(to_va(user2.account_id.clone())))
                .unwrap_json::<U128>()
                .0,
            to_yocto("0")
        );
        panic!("PANIC 5");
        // _withdraws_ from the staking contract
        call!(user2, staking.withdraw(U128(to_yocto("1")))).assert_success();
        panic!("PANIC 6");

        // user3 sends to the staking acc in the token
        call!(
            user3,
            test_token.ft_transfer_call(
                to_va(staking.account_id()),
                U128(to_yocto("1")),
                None,
                "".to_string()
            ),
            deposit = 1
        )
        .assert_success();

        // and add a new delegation for himself
        call!(
            user3,
            staking.delegate(to_va(user3.account_id.clone()), U128(to_yocto("1")))
        )
        .assert_success();
        // check the dao ack
        assert_eq!(
            view!(dao.delegation_balance_of(to_va(user3.account_id.clone())))
                .unwrap_json::<U128>()
                .0,
            to_yocto("2")
        );
        panic!("PANIC 7");

        // user 3 also votes
        vote(vec![&user3], &dao, add_user_colluded - 1);
        // assert that it has been approved
        assert_eq!(
            view!(dao.get_proposal(add_user_colluded - 1))
                .unwrap_json::<Proposal>()
                .status,
            ProposalStatus::Approved
        );
    }
}
