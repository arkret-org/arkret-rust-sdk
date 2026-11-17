// Keep the wire enum and its schema branches on the same definition. Salvo's
// chained builder for this large union exceeds the default Windows main stack
// in debug builds; each branch instead gets its own bounded construction frame.
macro_rules! current_selector {
    (
        #[derive($($derive:path),* $(,)?)]
        #[serde $serde:tt]
        pub enum $name:ident {
            $($(#[$attribute:meta])* $variant:ident $({ $($fields:tt)* })?,)*
        }
    ) => {
        #[derive($($derive),*)]
        #[serde $serde]
        pub enum $name {
            $($(#[$attribute])* $variant $({ $($fields)* })?,)*
        }

        #[cfg(feature = "openapi")]
        const _: () = {
            use salvo_oapi::{Components, ComposeSchema, Discriminator, Ref, RefOr, Schema, ToSchema};
            use salvo_oapi::naming::{NameRule, assign_name};
            use salvo_oapi::schema::{OneOf, compose_schema, register_schema};
            use std::any::TypeId;

            fn build_schema(components: &mut Components) -> RefOr<Schema> {
                let builders: &[fn(&mut Components) -> RefOr<Schema>] = &[$({
                    #[inline(never)]
                    fn build(components: &mut Components) -> RefOr<Schema> {
                        // This local type supplies metadata, never a wire value.
                        #[allow(dead_code)]
                        #[derive(serde::Serialize, salvo_oapi::ToSchema)]
                        #[salvo(schema(inline))]
                        #[serde $serde]
                        enum Branch {
                            $(#[$attribute])* $variant $({ $($fields)* })?,
                        }
                        let RefOr::Type(Schema::OneOf(mut branch)) = Branch::to_schema(components) else {
                            unreachable!("a tagged selector branch must derive a oneOf schema");
                        };
                        assert_eq!(branch.items.len(), 1);
                        branch.items.pop().expect("one selector branch")
                    }
                    build
                }),*];
                let mut schema = OneOf::with_capacity(builders.len())
                    .discriminator(Discriminator::new("kind"));
                for build in builders {
                    schema.items.push(build(components));
                }
                schema.into()
            }

            impl ToSchema for $name {
                fn to_schema(components: &mut Components) -> RefOr<Schema> {
                    compose_schema::<Self>(components, TypeId::of::<Self>(), &[], |components| {
                        let name = assign_name::<Self>(NameRule::Auto);
                        let reference = RefOr::Ref(Ref::new(format!("#/components/schemas/{name}")));
                        if !components.schemas.contains_key(&name) {
                            register_schema(components, name, build_schema);
                        }
                        reference
                    })
                }
            }

            impl ComposeSchema for $name {
                fn __compose_declaration_id() -> TypeId {
                    struct DeclarationMarker;
                    TypeId::of::<DeclarationMarker>()
                }

                fn compose(components: &mut Components, generics: Vec<RefOr<Schema>>) -> RefOr<Schema> {
                    let generics = generics.into_iter().map(Some).collect::<Vec<_>>();
                    compose_schema::<Self>(
                        components,
                        Self::__compose_declaration_id(),
                        &generics,
                        build_schema,
                    )
                }
            }
        };
    };
}
