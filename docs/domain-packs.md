# Domain packs, catalog store and multi-domain BPP

What this adds (steps 1-3 of the catalog-hosting plan). All of it lives in the mockup; the
stack-agnostic harness is unchanged.

## 1. Domain schema packs (`packs/`)
A pack is a directory: `pack.json` (name, version, `@context` URI, `@type` to schema-file map),
one JSON Schema 2020-12 file per type, `examples.json` (valid and invalid cases) and an optional
`catalog.json` sample. Adding a domain means adding a directory; no code changes (tested in
`test_adding_a_domain_needs_only_files_no_code`).

| Pack | Types | Carries |
|---|---|---|
| `agri-produce` | `Produce`, `ProduceOffer` | commodity, origin country, harvest date, grade; unit (KGM, TNE, C62, LTR), minimum order, lead days |
| `energy-der` | `EnergySource`, `EnergyOffer` | source type, capacity kW, meter id; unit KWH, delivery window, minimum kWh |
| `tourism-listing` | `Listing`, `ListingOffer` | category, location, country, capacity; unit (C62, DAY, HUR), cancellation policy |
| `pricing-core` | `PriceSpecification` | currency, value (the shape the BPP quotes from) |

Attributes are kept thin on purpose (docs/Schema_Design_Guide.md: structured attributes only for
facts that drive filtering, arithmetic or compliance; the rest belongs in `Descriptor`). The
contexts live under `packs.beckn-eval.invalid`, a reserved name, so no real domain is claimed.

**UNVERIFIED:** none of these packs has been checked against upstream `beckn/schemas` or
`beckn/DEG`; upstream may already define energy and other types. The agri licence/regulatory
fields, energy settlement terms and tourism taxes are not modelled. Treat the packs as scaffolding
to replace or align once upstream schemas are known.

## 2. Catalog store (`mockup/beckn_mock/catalogstore.py`)
- `publish` validates against the Beckn `Catalog` schema, then every `*Attributes` container
  against the packs, then checks references and prices; failure leaves the store unchanged.
- Offer and resource ids are unique store-wide; an offer must have a numeric price.
- Every changed publish creates a new version; identical content is a no-op; `history` and
  `get(version=)` read old versions; `deactivate` hides a catalog from discovery.
- In-memory only. File persistence beyond `from_dir` loading is not built.

## 3. BPP wiring
`BppNode` takes a `store`. `discover` searches all active catalogs, `select/init/confirm`
recompute price from the store (never from client input) and return the offer's `unitCode`.
The legacy single-catalog path still works (non-strict packs).

## Known limits
- Only the `Intent.textSearch` filter is implemented; `filters` and `spatial` are ignored.
- Delivery-window ordering (end after start) is not expressible in the schema and is unchecked.
- Strict context checking applies to packs only; the BPP still assumes the price lives in
  `considerations[0]`.
- No inventory, availability or quantity limits per offer.
