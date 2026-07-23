# arkret-models

Unified documentation and re-export surface for Arkret v1 protocol models.

A pure aggregation and documentation boundary. Protocol definitions remain
owned by the five consumer-profile model crates (collaboration, crypto,
discovery, identity, integration). SDK implementation crates must depend on
those owners directly instead of depending on this aggregate.
