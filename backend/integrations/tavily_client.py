"""
backend/integrations/tavily_client.py
-------------------------------------
Tavily Search API integration for real-time threat intelligence lookup.
"""

import os
from typing import Any, Dict, List
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

FALLBACK_RESULT: List[Dict[str, Any]] = [
    {
        "title": "Local Heuristics",
        "content": "Live search skipped. Using signature checks.",
    }
]


def is_valid_api_key(key: str | None) -> bool:
    """Check if the provided key is non-empty and not a dummy placeholder."""
    if not key:
        return False
    clean = key.strip()
    placeholder_keys = {"your_tavily_api_key", "tavily_api_key", "none", "placeholder"}
    if not clean or clean.lower() in placeholder_keys:
        return False
    return True


def search_threat_intel(query: str) -> list:
    """
    Search real-time threat intelligence using Tavily Search API.

    Returns:
        list: Search results containing external intelligence, or a fallback
              dictionary if the API key is missing, invalid, or upon error.
    """
    tavily_key = os.getenv("TAVILY_API_KEY")

    if not is_valid_api_key(tavily_key):
        return list(FALLBACK_RESULT)

    try:
        from tavily import TavilyClient

        client = TavilyClient(api_key=tavily_key)
        response = client.search(
            query=query,
            search_depth="advanced",
            max_results=3,
        )

        if isinstance(response, dict):
            results = response.get("results", [])
            return results if results else list(FALLBACK_RESULT)
        elif isinstance(response, list):
            return response if response else list(FALLBACK_RESULT)
        return list(FALLBACK_RESULT)

    except Exception as exc:
        print(f"[tavily_client] Warning: Threat intel lookup failed ({exc}). Using fallback.")
        return list(FALLBACK_RESULT)
