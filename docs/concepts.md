# Concepts and how they relate to public ideas
Ontolite is **inspired by publicly documented concepts**; it claims no compatibility with, or endorsement by, any vendor.
| Here | Public idea it echoes |
| --- | --- |
| ObjectType, property, primary key, LinkType (both directions) | typed objects and link types in an ontology |
| ActionType + ChangeSet (propose -> approve -> apply, declared `edit_set`, preconditions) | action types / staged edits |
| QueryType (typed params, permission-aware, small-cell suppression) | declarative query types |
| `authz.yaml` relation rewrites (`this`, `computed`, `ttu`, union, intersection, exclusion) | Zanzibar-style relation-based access control (Pang et al., 2019) |
| property `visibility` (roles) + object-level relations | property- and object-level security |
| Merkle audit with signed heads and consistency proofs | transparency logs (RFC 6962 / 9162) |
| Schema proposals + migrations behind a human gate | governed schema evolution |
Out of scope: UI, multi-tenancy, streaming, interfaces.
