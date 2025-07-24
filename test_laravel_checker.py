#!/usr/bin/env python3

import sys
import os
sys.path.append('/home/ioss/Documents/Server_Security/security-checklist-automation')
sys.path.append('/home/ioss/Documents/Server_Security/security-checklist-automation/app')

from app.scanner.laravel_checker import check_laravel_env_file
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

def test_laravel_env_checker():
    print("=== Testing Laravel .env Checker ===\n")
    
    # Test with sample .env file
    env_file = '/home/ioss/Documents/Server_Security/security-checklist-automation/test_laravel.env'
    project_path = '/home/ioss/Documents/Server_Security/security-checklist-automation'
    
    # Create mock connection that uses our test .env file
    conn = MockConnection(env_file)
    
    # Test the checker
    result = check_laravel_env_file(conn, project_path)
    
    print("Laravel .env Security Check Results:")
    print("=" * 50)
    
    # Print basic info
    print(f"✓ .env file exists: {result['env_file_exists']}")
    
    # Print APP_DEBUG check
    app_debug = result.get('app_debug', {})
    print(f"✗ APP_DEBUG: {app_debug.get('value')} (Secure: {app_debug.get('secure')})")
    
    # Print APP_ENV check
    app_env = result.get('app_env', {})
    print(f"✗ APP_ENV: {app_env.get('value')} (Secure: {app_env.get('secure')})")
    
    # Print APP_URL check
    app_url = result.get('app_url', {})
    print(f"✗ APP_URL: {app_url.get('value')} (Secure: {app_url.get('secure')})")
    
    # Print DEMO_STATUS check
    demo_status = result.get('demo_status', {})
    print(f"✓ DEMO_STATUS: {demo_status.get('value')} (Secure: {demo_status.get('secure')})")
    
    # Print DB_PREFIX check
    db_prefix = result.get('db_prefix', {})
    print(f"✓ DB_PREFIX exists: {db_prefix.get('exists')}")
    
    # Print database configuration
    db_config = result.get('database_config', {})
    print(f"✓ Database config complete: {db_config.get('complete')}")
    print(f"✗ Database config secure: {db_config.get('secure')}")
    
    # Print MLM configuration
    mlm_config = result.get('mlm_config', {})
    print(f"✓ MLM config complete: {mlm_config.get('complete')}")
    print(f"✗ MLM config secure: {mlm_config.get('secure')}")
    
    # Print URL security analysis
    url_security = result.get('url_security', {})
    print(f"✗ URLs are domain-based: {url_security.get('secure')}")
    ip_urls = url_security.get('ip_based_urls', [])
    if ip_urls:
        print("   IP-based URLs found:")
        for url in ip_urls:
            print(f"   - {url}")
    
    # Print mail configuration
    mail_config = result.get('mail_config', {})
    print(f"✓ Mail config complete: {mail_config.get('complete')}")
    print(f"✓ Mail config secure: {mail_config.get('secure')}")
    
    # Print payment configuration
    payment_config = result.get('payment_config', {})
    print(f"✓ Payment config secure: {payment_config.get('secure')}")
    
    # Print custom checks
    print("\nCustom Security Checks:")
    print("-" * 30)
    custom_checks = result.get('custom_checks', {})
    for check, status in custom_checks.items():
        symbol = "✓" if status else "✗"
        print(f"{symbol} {check}: {status}")
    
    print(f"\nFull result structure:")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    test_laravel_env_checker()
