#!/usr/bin/env python3

import sys
import os
sys.path.append('/home/ioss/Documents/Server_Security/security-checklist-automation')
sys.path.append('/home/ioss/Documents/Server_Security/security-checklist-automation/app')

from app.scanner.node_checker import check_nodejs_env_file
import json

class MockConnection:
    def __init__(self, env_file_path):
        self.env_file_path = env_file_path
    
    def run(self, command, hide=True, warn=True):
        class MockResult:
            def __init__(self, stdout="", ok=True):
                self.stdout = stdout
                self.ok = ok
        
        if 'test -f' in command and '.env' in command:
            if os.path.exists(self.env_file_path):
                return MockResult("EXISTS", True)
            else:
                return MockResult("NOT_EXISTS", True)
        elif 'cat' in command and '.env' in command:
            try:
                with open(self.env_file_path, 'r') as f:
                    content = f.read()
                return MockResult(content, True)
            except:
                return MockResult("", False)
        else:
            return MockResult("", True)

def test_nodejs_env_checker():
    print("=== Testing Node.js .env Checker ===\n")
    
    # Test with sample .env file
    env_file = '/home/ioss/Documents/Server_Security/security-checklist-automation/test_node.env'
    project_path = '/home/ioss/Documents/Server_Security/security-checklist-automation'
    
    # Create mock connection that uses our test .env file
    conn = MockConnection(env_file)
    
    # Test the checker
    result = check_nodejs_env_file(conn, project_path)
    
    print("Node.js .env Security Check Results:")
    print("=" * 50)
    
    # Print basic info
    print(f"✓ .env file exists: {result['env_file_exists']}")
    
    # Print NODE_ENV check
    node_env = result.get('node_env', {})
    print(f"✗ NODE_ENV: {node_env.get('value')} (Secure: {node_env.get('secure')})")
    
    # Print DEMO_STATUS check
    demo_status = result.get('demo_status', {})
    print(f"✓ DEMO_STATUS: {demo_status.get('value')} (Secure: {demo_status.get('secure')})")
    
    # Print PREFIX check
    prefix_config = result.get('prefix_config', {})
    print(f"✓ PREFIX: {prefix_config.get('value')} (Configured: {prefix_config.get('configured')})")
    
    # Print database configuration
    db_config = result.get('database_config', {})
    print(f"✓ Database config complete: {db_config.get('complete')}")
    print(f"✗ Database config secure: {db_config.get('secure')}")
    
    # Print URL security analysis
    url_security = result.get('url_security', {})
    print(f"✗ URLs are domain-based: {url_security.get('secure')}")
    ip_urls = url_security.get('ip_based_urls', [])
    if ip_urls:
        print("   IP-based URLs found:")
        for url in ip_urls:
            print(f"   - {url}")
    
    # Print token security
    token_security = result.get('token_security', {})
    print(f"✓ Token security: {token_security.get('secure')}")
    
    # Print custom checks
    print("\nCustom Security Checks:")
    print("-" * 30)
    custom_checks = result.get('custom_checks', {})
    for check, status in custom_checks.items():
        symbol = "✓" if status else "✗"
        print(f"{symbol} {check}: {status}")
    
    # Print detailed analysis
    print(f"\nDetailed Analysis:")
    print(f"Port: {result.get('port', {}).get('value')} (Secure: {result.get('port', {}).get('secure')})")
    print(f"Mail config complete: {result.get('mail_config', {}).get('complete')}")
    print(f"Payment config secure: {result.get('payment_config', {}).get('secure')}")
    
    print(f"\nFull result structure:")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    test_nodejs_env_checker()
