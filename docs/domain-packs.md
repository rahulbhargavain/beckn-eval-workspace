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

## Lot ledger and the smallholder policy (`lots.py`, `packs/policies/kumaon-smallholder.json`)
For an aggregation hub that sells graded smallholder produce. Written for the Kumaon value-chain design on
cottonspace.com, which is a proposal, not an operating system (UNVERIFIED against any live hub).
- **Lots.** `LotLedger.receive` takes a lot: id, product, grade, decimal quantity, unit, `originType`
  (`own-land` or `lawful-collection`; produce from Green Credit forest parcels is refused), the household or group
  `source` ids, and optional grading standard, certification scheme and scope (`domestic` or `export`),
  moisture and Brix, harvest date and location.
- **Events.** Every change is an append-only event; on-hand equals the event sum. Sales draw stock first-in-first-out,
  all-or-nothing and thread-safe. `unsell` and `resell` serve cancel and update; `transfer` moves stock to the hub's own
  factory without a sale; `write_off` needs a reason.
- **Catalog.** `catalog()` publishes one resource and offer per product, grade and certificate, using the least
  favourable lot figure (highest moisture, lowest Brix, earliest harvest). `availableQuantity` is a snapshot.
- **Seller node.** With `BppNode(..., ledger=...)`, select/init/update check stock; confirm takes it (a refused confirm
  creates no contract); a committed cancel returns it; a committed update adjusts it. Previews move nothing.
  Two buyers who both quoted the last kilograms: the second confirm is refused with `BIZ_QUANTITY_UNAVAILABLE`.
- **Pack additions.** `Produce` gains `originType`, `gradingStandard`, `certificationScheme`, `certificationScope`,
  `moisturePercent`, `brixDegrees`; `ProduceTerms` gains `availableQuantity`. The `kumaon-smallholder` policy requires
  `originType` and limits its values and `certificationScope`; `eval-default` is unchanged.
- **Not covered.** No hold at select/init (stock is taken at confirm only); no persistence, expiry of stale state or
  physical-count reconciliation; no auction, bid or payout flow; one process only.

## Known limits
- Only `Intent.textSearch` discovery is implemented.
- Quantities are decimals with at most three places (see `docs/mockup-findings.md`); no per-offer step or minimum is enforced yet.
- Delivery-window ordering is unchecked.
- The price is assumed to live in `considerations[0]`.
- Inventory exists only when the node is given a lot ledger (below); the default node sells without stock limits.
- Policy rules match on `@type` only, not on context.
- Not mirrored: the real upstream schemas. Aligning with DEG and `beckn/schemas` needs a pinned
  local mirror (the upstream files are OpenAPI 3.1 YAML with `$ref`s to `schema.nfh.global`), and
  the upstream repos are CC BY-NC-SA 4.0, so reference rather than copy.
