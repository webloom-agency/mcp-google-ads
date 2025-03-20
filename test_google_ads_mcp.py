import asyncio
import json
import os
import sys
from pathlib import Path

# Add the parent directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import your MCP server module
import google_ads_server

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
    # Setup environment variables if they're not already set
    if not os.environ.get("GOOGLE_ADS_CREDENTIALS_PATH"):
        # Set environment variables for testing (comment out if already set in your environment)
        os.environ["GOOGLE_ADS_CREDENTIALS_PATH"] = "google_ads_token.json"
        os.environ["GOOGLE_ADS_DEVELOPER_TOKEN"] = "YOUR_DEVELOPER_TOKEN"  # Replace with placeholder
        os.environ["GOOGLE_ADS_CLIENT_ID"] = "YOUR_CLIENT_ID"  # Replace with placeholder
        os.environ["GOOGLE_ADS_CLIENT_SECRET"] = "YOUR_CLIENT_SECRET"  # Replace with placeholder
    
    # Run the test
    asyncio.run(test_mcp_tools())