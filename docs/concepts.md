# Concepts and the Palantir-inspired mapping
Ontolite is **inspired by public concepts**; it claims no compatibility with or endorsement by Palantir.
| Concept here | Public idea it echoes |
| --- | --- |
| ObjectType / property / primary key | typed objects |
| LinkType (both directions, cardinality) | link types |
| ActionType + ChangeSet (propose -> approve -> apply) | action types / staged edits |
| `edit_set` | declared scope of an action's side effects |
| property `visibility`, `access: relationship|inherit` | property- and object-level security |
| Principal acts-for | delegated agent identity |
Out of scope: UI, multi-tenancy, streaming, interfaces.
