use super::*;

#[test]
fn fragment_contains_only_the_two_trust_domain_headers() {
    let source = TrustDomainId::new("ak:trust_domain:source.example".to_owned()).unwrap();
    let destination = TrustDomainId::new("ak:trust_domain:destination.example".to_owned()).unwrap();

    let fragment = federation_trust_domain_transcript_fragment(&source, &destination);

    assert_eq!(
        fragment,
        "\"source-trust-domain\": ak:trust_domain:source.example\n\
             \"destination-trust-domain\": ak:trust_domain:destination.example\n"
    );
    assert!(!fragment.contains("request-canonical-digest"));
}
