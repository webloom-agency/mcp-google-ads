"""
Google Ads OAuth Scopes

Centralized scope definitions for Google Ads MCP.
"""

import logging

logger = logging.getLogger(__name__)

# Base OAuth scopes required for user identification
USERINFO_EMAIL_SCOPE = 'https://www.googleapis.com/auth/userinfo.email'
USERINFO_PROFILE_SCOPE = 'https://www.googleapis.com/auth/userinfo.profile'
OPENID_SCOPE = 'openid'

BASE_SCOPES = [
    USERINFO_EMAIL_SCOPE,
    USERINFO_PROFILE_SCOPE,
    OPENID_SCOPE,
]

# Google Ads API scope
GOOGLE_ADS_SCOPE = 'https://www.googleapis.com/auth/adwords'

# All scopes needed for Google Ads MCP
SCOPES = BASE_SCOPES + [GOOGLE_ADS_SCOPE]


def get_current_scopes():
    """Returns all scopes required by the Google Ads MCP."""
    return list(set(SCOPES))
