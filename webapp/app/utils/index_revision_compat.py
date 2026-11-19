"""Exact build aliases for reviewed storage fixes with unchanged parser output.

The complete source fingerprint must match an entry. Changing any parser, rule
evaluator or other fingerprinted file falls back to its new revision as usual.
Do not add a general bypass: frozen jobs and published coverage depend on this.
"""

# COPY now skips absent source keys, preserving the previously intended empty
# field/tombstone semantics. Rules, parser output and stored formats are unchanged.
STORAGE_COMPATIBLE_REVISIONS = {
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
