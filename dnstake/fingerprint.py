"""Response-body normalization and fingerprint matching."""

import re

_TAG_RE = re.compile(r"<[^>]*>")
_WHITESPACE_RE = re.compile(r"\s+")

# Entity decoding happens strictly in this order, after tag stripping.
_ENTITIES = (
    ("&amp;", "&"),
    ("&lt;", "<"),
    ("&gt;", ">"),
    ("&quot;", '"'),
    ("&apos;", "'"),
)


def normalize_body(text):
    """Normalize a response body (or fingerprint) for comparison.

    Steps, in order (the order must not change):
    1. remove paired angle brackets together with their contents (HTML tags)
    2. decode HTML entities (&amp; &lt; &gt; &quot; &apos;)
    3. collapse every run of whitespace into a single space
    4. strip leading/trailing spaces
    5. lowercase

    Because tags are removed before entities are decoded, a literal
    &lt;b&gt; in the source decodes to the text <b> and is kept.
    """
    if text is None:
        return None
    result = _TAG_RE.sub("", str(text))
    for entity, char in _ENTITIES:
        result = result.replace(entity, char)
    result = _WHITESPACE_RE.sub(" ", result)
    result = result.strip()
    return result.lower()


def fingerprint_matches(normalized_body, fingerprint):
    """Return True if the normalized body contains the normalized fingerprint."""
    if normalized_body is None or fingerprint is None:
        return False
    return normalize_body(fingerprint) in normalized_body
