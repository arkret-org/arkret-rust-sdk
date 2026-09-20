use arkret_wire::{SERVICE_OPERATION_DESCRIPTORS, ServiceOperationId};

#[test]
fn generated_transport_bindings_round_trip_exactly() {
    for descriptor in SERVICE_OPERATION_DESCRIPTORS {
        match descriptor.grpc {
            Some(grpc) => assert_eq!(ServiceOperationId::from_grpc(grpc), Some(descriptor.id)),
            None => assert!(descriptor.mq.is_none()),
        }
        match descriptor.mq {
            Some(topic) => assert_eq!(
                ServiceOperationId::from_mq_topic(topic),
                Some(descriptor.id)
            ),
            None => assert!(descriptor.grpc.is_none()),
        }
    }
}

#[test]
fn unknown_transport_bindings_fail_closed() {
    assert_eq!(ServiceOperationId::from_grpc("Unknown/Method"), None);
    assert_eq!(ServiceOperationId::from_mq_topic("unknown.topic"), None);
}
