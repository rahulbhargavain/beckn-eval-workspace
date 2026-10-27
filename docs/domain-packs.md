# Domain packs, policy, catalog store and multi-domain BPP

Lives in the mockup; the stack-agnostic harness is unchanged. Restructured to follow the schema
design guide and the beckn-agents schema-builder checklist (see the comparison in the session
notes: no mandatory fields in schemas, no closed enums, no generic-suffix type names, one
directory per schema and version).

## Layout (`packs/`)
```
schemas/<Type>/<vN.M>/  schema.json  attributes.yaml  context.jsonld  vocab.jsonld  README.md  examples.json
external/*.json         upstream schemas recognised but not mirrored (validation deferred)
policies/*.json         network policy: required attributes and controlled vocabularies
catalogs/*.json         sample catalogs used by the tests
```
A schema's `$id` names its own directory and defines its `@context` URL (`.../context.jsonld`).
Adding a schema or a version is adding a directory; no code changes. Published version
directories should never be edited in place (not enforced yet).

| Type | Carries (structural) | Policy requires / vocabulary |
|---|---|---|
| `Produce` | originCountry, harvestDate, certifications | originCountry |
| `ProduceTerms` | unitCode, minOrderQuantity, deliveryLeadDays | unitCode in KGM, TNE, C62, LTR |
| `EnergySource` | sourceType, capacityKw, meterId | all three; sourceType in DEG-style terms plus BATTERY |
| `EnergyTerms` | unitCode, deliveryWindow, minQuantityKwh | unit KWH; window required |
| `Listing` | category, countryCode, capacity | all three; category in stay, tour, experience, transport |
| `ListingTerms` | unitCode, cancellationPolicyId | unit in C62, DAY, HUR |

Descriptive facts (commodity name, grade, place name) moved to the `Descriptor`. Price is the
upstream `PriceSpecification` (`external/`), whose structural validation is deferred until a pinned
local mirror exists; the store still checks currency and a numeric value.

**UNVERIFIED:** the packs are workspace-owned scaffolding, not upstream Beckn schemas. The
`EnergySource` and `EnergyTerms` types are placeholders for DEG's `EnergyResource*` and
`EnergyTradeOffer`. The external `PriceSpecification` context URL follows the
`schema.nfh.global/<Name>/<ver>/context.jsonld` pattern and was not resolved. `vocab.jsonld`
mappings are provisional, and the type names are provisional (the guide discourages generic
suffixes; `...Terms` is a stand-in). Contexts use the reserved `.invalid` domain.

## Policy (`mockup/beckn_mock/policy.py`)
A small stand-in for the Rego policy-as-code the guide mentions. Rules are keyed by `@type`:
`require` (field names) and `vocabulary` (field to allowed values). Different networks can ship
different policies over the same schemas; a store without a policy accepts what the schemas allow.

## Catalog store (`catalogstore.py`)
- `publish` validates the Beckn `Catalog` schema, then every `*Attributes` container against the
  packs and the policy, then references and prices; failure leaves the store unchanged.
- Offer and resource ids are unique store-wide; an offer must have a numeric price.
- Every changed publish creates a new version; identical content is a no-op.
- In-memory only.

## BPP
`BppNode` takes a `store`. `discover` searches all active catalogs; `select/init/confirm` recompute
price from the store and return the offer's `unitCode`. The legacy single-catalog path still works.

## Known limits
- Only `Intent.textSearch` discovery is implemented.
- Delivery-window ordering is unchecked.
- The price is assumed to live in `considerations[0]`.
- No inventory or availability.
- Policy rules match on `@type` only, not on context.
- Not mirrored: the real upstream schemas. Aligning with DEG and `beckn/schemas` needs a pinned
  local mirror (the upstream files are OpenAPI 3.1 YAML with `$ref`s to `schema.nfh.global`), and
  the upstream repos are CC BY-NC-SA 4.0, so reference rather than copy.
