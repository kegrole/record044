"""Known hosting-provider table and platform matching."""

from .hosts import normalize_host

# Columns: provider id, domain suffix, expected HTTP status set, body
# fingerprint substring.
PROVIDERS = (
    {
        "id": "github-pages",
        "suffix": "github.io",
        "statuses": frozenset({404}),
        "fingerprint": "there isn't a github pages site here.",
    },
    {
        "id": "heroku",
        "suffix": "herokuapp.com",
        "statuses": frozenset({404, 503}),
        "fingerprint": "no such app",
    },
    {
        "id": "netlify",
        "suffix": "netlify.app",
        "statuses": frozenset({404}),
        "fingerprint": "page not found",
    },
    {
        "id": "surge",
        "suffix": "surge.sh",
        "statuses": frozenset({404}),
        "fingerprint": "project not found",
    },
    {
        "id": "bitbucket",
        "suffix": "bitbucket.io",
        "statuses": frozenset({404}),
        "fingerprint": "repository not found",
    },
    {
        "id": "shopify",
        "suffix": "myshopify.com",
        "statuses": frozenset({404}),
        "fingerprint": "sorry, this shop is currently unavailable",
    },
)


def match_provider(host):
    """Return the provider whose suffix covers host, else None.

    host must already be normalized. A host falls on a platform when
    it equals the platform suffix or ends with a dot plus the suffix.
    """
    if not host:
        return None
    for provider in PROVIDERS:
        suffix = provider["suffix"]
        if host == suffix or host.endswith("." + suffix):
            return provider
    return None


def claimable_account(host, suffix):
    """Derive the claimable platform account name from a chain tail.

    The account name is the label immediately in front of the platform
    suffix. When the host equals the suffix itself (the platform root
    domain) there is no claimable account and None is returned.
    """
    host = normalize_host(host)
    suffix = normalize_host(suffix)
    if not host or not suffix or host == suffix:
        return None
    if not host.endswith("." + suffix):
        return None
    prefix = host[: -(len(suffix) + 1)]
    if not prefix:
        return None
    return prefix.rsplit(".", 1)[-1]
