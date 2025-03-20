import asyncio
import json
import os
import sys
from pathlib import Path

# Add the parent directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import your MCP server module
import google_ads_server

def test_format_customer_id():
    """Test the format_customer_id function with various input formats."""
    test_cases = [
        # Regular ID
        ("9873186703", "9873186703"),
        # ID with dashes
        ("987-318-6703", "9873186703"),
        # ID with quotes
        ('"9873186703"', "9873186703"),
        # ID with escaped quotes
        ('\"9873186703\"', "9873186703"),
        # ID with leading zeros
        ("0009873186703", "9873186703"),
        # Short ID that needs padding
        ("12345", "0000012345"),
        # ID with other non-digit characters
        ("{9873186703}", "9873186703"),
    ]
    
    print("\n=== Testing format_customer_id with various formats ===")
    for input_id, expected in test_cases:
        result = google_ads_server.format_customer_id(input_id)
        print(f"Input: {input_id}")
        print(f"Result: {result}")
        print(f"Expected: {expected}")
        print(f"Test {'PASSED' if result == expected else 'FAILED'}")
        print("-" * 50)

async def test_mcp_tools():
    """Test Google Ads MCP tools directly."""
    # Get a list of available customer IDs first
    print("=== Testing list_accounts ===")
    accounts_result = await google_ads_server.list_accounts()
    print(accounts_result)
    
    # Parse the accounts to extract a customer ID for further tests
    customer_id = None
    for line in accounts_result.split('\n'):
        if line.startswith("Account ID:"):
            customer_id = line.replace("Account ID:", "").strip()
            break
    
    if not customer_id:
        print("No customer IDs found. Cannot continue testing.")
        return
    
    print(f"\nUsing customer ID: {customer_id} for testing\n")
    
    # Test campaign performance
    print("\n=== Testing get_campaign_performance ===")
    campaign_result = await google_ads_server.get_campaign_performance(customer_id, days=90)
    print(campaign_result)
    
    # Test ad performance
    print("\n=== Testing get_ad_performance ===")
    ad_result = await google_ads_server.get_ad_performance(customer_id, days=90)
    print(ad_result)
    
    # Test ad creatives
    print("\n=== Testing get_ad_creatives ===")
    creatives_result = await google_ads_server.get_ad_creatives(customer_id)
    print(creatives_result)
    
    # Test custom GAQL query
    print("\n=== Testing run_gaql ===")
    query = """
        SELECT 
            campaign.id, 
            campaign.name, 
            campaign.status 
        FROM campaign 
        LIMIT 5
    """
    gaql_result = await google_ads_server.run_gaql(customer_id, query, format="json")
    print(gaql_result)

if __name__ == "__main__":
    # Run format_customer_id tests first
    test_format_customer_id()
    
    # Setup environment variables if they're not already set
    if not os.environ.get("GOOGLE_ADS_CREDENTIALS_PATH"):
        # Set environment variables for testing (comment out if already set in your environment)
        os.environ["GOOGLE_ADS_CREDENTIALS_PATH"] = "google_ads_token.json"
        os.environ["GOOGLE_ADS_DEVELOPER_TOKEN"] = "YOUR_DEVELOPER_TOKEN"  # Replace with placeholder
        os.environ["GOOGLE_ADS_CLIENT_ID"] = "YOUR_CLIENT_ID"  # Replace with placeholder
        os.environ["GOOGLE_ADS_CLIENT_SECRET"] = "YOUR_CLIENT_SECRET"  # Replace with placeholder
    
    # Run the MCP tools test (uncomment to run full tests)
    # asyncio.run(test_mcp_tools())