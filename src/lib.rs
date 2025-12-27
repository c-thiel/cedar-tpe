use std::{str::FromStr, sync::LazyLock};

pub static CEDAR_SCHEMA: LazyLock<cedar_policy::Schema> = LazyLock::new(|| {
    cedar_policy::Schema::from_str(include_str!("./resources/example.cedarschema"))
        .unwrap_or_else(|e| {
            panic!(
                "Failed to parse Cedar schema. This indicates a bug in the schema definition. Error: {e}"
            )
        })
});

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use cedar_policy::{
        Authorizer, Decision, Entities, EntityTypeName, EntityUid, PolicySet, Request,
        ValidationMode, Validator,
    };
    use itertools::Itertools;

    use super::*;

    // We will query these later for policies that are "may be determining" for the following request:
    // principal: MyApp::User (no ID specified)
    // action: MyApp::Action::"GetProjectMetadata"
    // resource: MyApp::Project::"0"
    const SAMPLE_POLICIES: &str = r#"
// 0 - As expected: Returned as "may be determining"
permit (
    principal == MyApp::User::"0",
    action == MyApp::Action::"GetProjectMetadata",
    resource == MyApp::Project::"0"
);
// 1 - As expected: Returned as "may be determining"
permit (
    principal == MyApp::User::"1",
    action,
    resource in MyApp::Server::"0"
);
// 2 - Not as expected: Is returned as "may be determining" although action doesn't match.
permit (
    principal == MyApp::User::"2",
    action == MyApp::Action::"DeleteProject",
    resource
);
// 3 - As expected: Not returned as "may be determining" as project 0 is not in server 1.
permit (
    principal,
    action == MyApp::Action::"GetProjectMetadata",
    resource in MyApp::Server::"3"
);
// 4 - As expected: Not returned as "may be determining" as project 0 is not in project 1.
permit (
    principal,
    action == MyApp::Action::"GetProjectMetadata",
    resource in MyApp::Project::"4"
);
// 5 - Unexpected: Returned as "may be determining" although project 0 is not in project 2.
// Especially unexpected as the much wider "wildcard" polciy above without restricted principal
// is not returned as "may be determining".
permit (
    principal == MyApp::User::"5",
    action == MyApp::Action::"GetProjectMetadata",
    resource in MyApp::Project::"5"
);
// 6 - Unexpected: Returned as "may be determining", although resource doesn't match.
permit (
    principal == MyApp::User::"6",
    action == MyApp::Action::"GetProjectMetadata",
    resource == MyApp::Project::"6"
);
// 7 - Unexpected: Returned as "may be determining", although action is a server action
// and query is for a project action.
permit (
    principal == MyApp::User::"7",
    action in MyApp::Action::"ServerActions",
    resource
);
// 8 - Unexpected: Returned as "may be determining", although action is a server action and does not apply to
// projects
// and query is for a project action.
permit (
    principal == MyApp::User::"8",
    action in MyApp::Action::"ProjectActions",
    resource
);
"#;

    // All existing entities with any relationship to the queried resource (MyApp::Project::"0").
    // Additional entities for which policies exist are not included.
    const SAMPLE_ENTITIES: &str = r#"
[
    {
        "uid": { "type": "MyApp::Server", "id": "0" },
        "attrs" : {},
        "parents": []
    },
    {
        "uid": { "type": "MyApp::Project", "id": "0"},
        "attrs" : {},
        "parents": [
            { "type": "MyApp::Server", "id": "0" }
        ]
    }
]
"#;

    fn policies() -> PolicySet {
        let policies = PolicySet::from_str(SAMPLE_POLICIES).unwrap();
        let validator = Validator::new(CEDAR_SCHEMA.clone());
        let validation_result = validator.validate(&policies, ValidationMode::Strict);
        assert!(validation_result.validation_passed());
        policies
    }

    #[test]
    fn test_authorization() {
        let policies = policies();
        let entities = Entities::from_json_str(SAMPLE_ENTITIES, Some(&CEDAR_SCHEMA)).unwrap();

        let authorizer = Authorizer::new();

        let request = Request::builder()
            .principal(EntityUid::from_str("MyApp::User::\"0\"").unwrap())
            .action(EntityUid::from_str("MyApp::Action::\"GetProjectMetadata\"").unwrap())
            .resource(EntityUid::from_str("MyApp::Project::\"0\"").unwrap())
            .schema(&CEDAR_SCHEMA)
            .build()
            .unwrap();

        let is_authorized = authorizer.is_authorized(&request, &policies, &entities);
        assert!(matches!(is_authorized.decision(), Decision::Allow));
    }

    #[test]
    fn test_partial_eval() {
        let policies = policies();
        let entities = Entities::from_json_str(SAMPLE_ENTITIES, Some(&CEDAR_SCHEMA)).unwrap();

        let project_0_uid = EntityUid::from_str("MyApp::Project::\"0\"").unwrap();

        let request = Request::builder()
            .unknown_principal_with_type(EntityTypeName::from_str("MyApp::User").unwrap())
            .action(EntityUid::from_str("MyApp::Action::\"GetProjectMetadata\"").unwrap())
            .resource(project_0_uid)
            .schema(&CEDAR_SCHEMA)
            .build()
            .unwrap();

        let authorizer = Authorizer::new();

        let result = authorizer.is_authorized_partial(&request, &policies, &entities);

        let definitly_errored = result
            .definitely_errored()
            .map(ToString::to_string)
            .sorted()
            .collect::<HashSet<_>>();
        println!("Definitly errored policies: {:?}", definitly_errored);

        let returned_policies = result
            .may_be_determining()
            .map(|p| p.id().to_string())
            .sorted()
            .collect::<HashSet<_>>();
        let expected_policies = HashSet::from(["policy0".to_string(), "policy1".to_string()]);

        assert_eq!(
            returned_policies,
            expected_policies,
            "\nReturned policies: {:?}\nExpected policies: {:?}",
            returned_policies.iter().sorted().collect::<Vec<_>>(),
            expected_policies.iter().sorted().collect::<Vec<_>>(),
        )
    }

    // #[test]
    // fn test_tpe() {
    //     let policies = cedar_policy::PolicySet::from_str(SAMPLE_POLICIES).unwrap();
    //     let entities = Entities::from_json_str(SAMPLE_ENTITIES, Some(&CEDAR_SCHEMA)).unwrap();

    //     let project_0_uid = EntityUid::from_str("MyApp::Project::\"0\"").unwrap();

    //     let partial_request = PartialRequest::new(
    //         PartialEntityUid::new("MyApp::Role".parse::<EntityTypeName>().unwrap(), None),
    //         EntityUid::from_str("MyApp::Action::\"GetProjectMetadata\"").unwrap(),
    //         PartialEntityUid::from_concrete(project_0_uid.clone()),
    //         None,
    //         &CEDAR_SCHEMA,
    //     )
    //     .unwrap();

    //     let partial_entities = PartialEntities::from_concrete(entities, &CEDAR_SCHEMA).unwrap();

    //     let tpe_result = policies
    //         .tpe(&partial_request, &partial_entities, &CEDAR_SCHEMA)
    //         .unwrap();
    //     let residual_policies = tpe_result
    //         .residual_policies()
    //         .map(|p| p.id().to_string())
    //         .sorted()
    //         .collect::<HashSet<_>>();

    //     println!("Residual policies: {:?}", residual_policies);
    //     assert_eq!(residual_policies, HashSet::from(["policy0".to_string()]));
    // }
}
