"""Iterable helpers shared by tools."""


def chunk_items(items, chunk_size):
    """Yield items in fixed-size chunks."""
    for start in range(0, len(items), chunk_size):
        yield items[start : start + chunk_size]
