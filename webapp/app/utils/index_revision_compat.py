"""Exact build aliases for reviewed storage fixes with unchanged parser output.

The complete source fingerprint must match an entry. Changing any parser, rule
evaluator or other fingerprinted file falls back to its new revision as usual.
Do not add a general bypass: frozen jobs and published coverage depend on this.
"""

# COPY now skips absent source keys, preserving the previously intended empty
# field/tombstone semantics. Rules, parser output and stored formats are unchanged.
STORAGE_COMPATIBLE_REVISIONS = {
    # Port evidence adds independent keys without changing normalized fields
    # or the inputs required to resume a frozen reconciliation job.
    (
        "bc67ba095b9656836597a6bba3076a0e1183a4833005ab6bdf44cddb6be5d4a2"
        "828b286177f690a580fa30c8384d085f21d11c1034f037011fde04b511c261d1"
    ): (
        "a45819bf65c1334c10292103b5adf8fe9806c75e3f38ed02fa1c289211ad4946"
        "502d749b9d26a483ffe9100ddc68fe31564608ccbbd992aacdb537802d3984aa"
    ),
    # Selective incremental reparsing preserves the parsed fields, tag rules
    # and frozen generation format of the reviewed build.
    (
        "2df92127dd3340f12a059e02d6faa05d9ef10c0857467d63487b72d24da61923"
        "498d08b7114b84265e0a0dac1e6f848bfa556468e48e4e428fbc4e52d24aae82"
    ): (
        "9080e1b7959c0ce42eec1037a148eadc37e3a876f3d144545dada298030f14c1"
        "91b7aec177f3bedcafeaf44b39d1ee96c79b5377cc5b62a0488b7f9c24e539d0"
    ),
    # Retag supersession and timestamp-ordered batches retain existing frozen
    # jobs and coverage. Parser output and rule evaluation are unchanged.
    (
        "ba5c40e8e63b5cdaef03abaae86f1dd161a8bc836555d5e3dd4571c2924eef06"
        "0b5cd6281819290e9e71aaa9fb29ad5371520ad8caa288b1a6f577534ea6ca7e"
    ): (
        "9080e1b7959c0ce42eec1037a148eadc37e3a876f3d144545dada298030f14c1"
        "91b7aec177f3bedcafeaf44b39d1ee96c79b5377cc5b62a0488b7f9c24e539d0"
    ),
    # Live ingestion journals the rule revision without changing extraction or
    # the meaning of previously frozen inputs. Admit both reviewed source trees.
    (
        "348caf6d5f5a3f57c78e8a20590bc353eb01c270349ba979d4eb6ee218480fe4"
        "09cb19db911c98b0fd229bb9b9951ff2e47f196aac69410d0ccaa458b6bf3632"
    ): (
        "4688dea5f2a4e2dd26ebbd0c09716b1e85dea2616c37a7ae793d412a71c9fba2"
        "4ed639cd8dd83c03baf784ce67023cd8967322d286fcd067bbe14fef0e8a12c5"
    ),
    (
        "c7940fc7f108ef7cde70b7649c28a9a105d16b675a4ff522163f0a8cdc541172"
        "599b6da031455694040fbe2059533b41bb42eee87a24eb2c8d2658a0afc5eb16"
    ): (
        "97e75600ecf019651e1878d839ca5b52643d612a48e40f5e74f99c9ad3990743"
        "d691c2e5ea4a296d23b10810397c01990df0538cdcff0cbf1391c34d7bd3e3c3"
    ),
    (
        "a15d58e516d701c284361138b729c3d0f64f02437b8c1be5ed63b00452dbf9b923"
        "a98bcacb722f26fde4194277173ff1d6ccd195099ebcb467a0d20d1fdce31f"
    ): (
        "0b328bca199730c3db289ebc6a7ea7ad835418f48b32102006d186c7622032f907"
        "2408cadd38b2be55a4e1b479bd0b9c6790d1a645f6beab70f4d0e996342509"
    ),
}


def compatible_code_revision(revision):
    """Keep frozen work resumable only for an explicitly reviewed whole build."""
    return STORAGE_COMPATIBLE_REVISIONS.get(revision, revision)
