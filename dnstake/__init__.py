"""dnstake: detect dangling DNS records and subdomain takeover risks.

Pure standard-library implementation. The tool never performs real DNS
queries or HTTP requests; it only evaluates pre-collected observations.
"""

__version__ = "1.0.0"
