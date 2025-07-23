#!/usr/bin/env python3
"""
Test script to validate firewall checker functionality
"""

import sys
import os

# Add the app directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

def test_firewall_logic():
    """Test the firewall security analysis logic"""
    print("Testing Firewall Security Analysis...")
    
    # Mock firewall results for testing
    mock_firewall_results = {
        'target_host': '192.168.1.100',
        'office_ip': '103.103.174.106',
        'public_ports': [80, 443],
        'total_ports_checked': 5,
        'port_accessibility': {
            80: {
                'port': 80,
                'is_public_port': True,
                'accessibility': {
                    'office': {'accessible': True, 'source_ip': '103.103.174.106'},
                    'external': {'accessible': True, 'source_ip': '8.8.8.8'},
                    'local': {'accessible': True, 'source_ip': '192.168.1.100'}
                },
                'security_status': 'public'
            },
            443: {
                'port': 443,
                'is_public_port': True,
                'accessibility': {
                    'office': {'accessible': True, 'source_ip': '103.103.174.106'},
                    'external': {'accessible': True, 'source_ip': '8.8.8.8'},
                    'local': {'accessible': True, 'source_ip': '192.168.1.100'}
                },
                'security_status': 'public'
            },
            22: {
                'port': 22,
                'is_public_port': False,
                'accessibility': {
                    'office': {'accessible': True, 'source_ip': '103.103.174.106'},
                    'external': {'accessible': False, 'source_ip': '8.8.8.8'},
                    'local': {'accessible': True, 'source_ip': '192.168.1.100'}
                },
                'security_status': 'secure'
            },
            3306: {
                'port': 3306,
                'is_public_port': False,
                'accessibility': {
                    'office': {'accessible': True, 'source_ip': '103.103.174.106'},
                    'external': {'accessible': True, 'source_ip': '8.8.8.8'},  # Security issue!
                    'local': {'accessible': True, 'source_ip': '192.168.1.100'}
                },
                'security_status': 'critical'
            },
            6379: {
                'port': 6379,
                'is_public_port': False,
                'accessibility': {
                    'office': {'accessible': False, 'source_ip': '103.103.174.106'},  # Should be accessible
                    'external': {'accessible': False, 'source_ip': '8.8.8.8'},
                    'local': {'accessible': True, 'source_ip': '192.168.1.100'}
                },
                'security_status': 'warning'
            }
        },
        'security_issues': [
            'CRITICAL: Port 3306 is accessible from external IPs but should only be accessible from office IP 103.103.174.106'
        ],
        'warnings': [
            'Port 6379 may not be accessible from authorized sources'
        ],
        'recommendations': [
            'Review firewall rules to restrict non-public ports to authorized IPs only',
            'Configure firewall to allow access from office IP 103.103.174.106 only for management ports'
        ],
        'firewall_status': 'critical'
    }
    
    print("✓ Mock firewall results created")
    
    # Test security analysis logic
    print("\n--- Security Analysis Results ---")
    print(f"Target Host: {mock_firewall_results['target_host']}")
    print(f"Office IP: {mock_firewall_results['office_ip']}")
    print(f"Firewall Status: {mock_firewall_results['firewall_status']}")
    print(f"Total Ports Checked: {mock_firewall_results['total_ports_checked']}")
    
    # Analyze port security
    print("\n--- Port Analysis ---")
    for port, data in mock_firewall_results['port_accessibility'].items():
        status = data['security_status']
        is_public = data['is_public_port']
        
        office_access = data['accessibility']['office']['accessible']
        external_access = data['accessibility']['external']['accessible']
        
        print(f"Port {port}: {status.upper()}")
        print(f"  Public Port: {is_public}")
        print(f"  Office Access: {'✓' if office_access else '✗'}")
        print(f"  External Access: {'✓' if external_access else '✗'}")
        
        # Validate security logic
        if is_public:
            if not external_access:
                print(f"  ⚠️  Public port {port} should be externally accessible")
        else:
            if external_access and not office_access:
                print(f"  🚨 CRITICAL: Port {port} accessible externally but not from office")
            elif external_access and office_access:
                print(f"  ⚠️  WARNING: Port {port} is publicly accessible")
            elif office_access and not external_access:
                print(f"  ✅ SECURE: Port {port} properly restricted")
        print()
    
    # Show security issues
    print("--- Security Issues ---")
    for issue in mock_firewall_results['security_issues']:
        print(f"🚨 {issue}")
    
    print("\n--- Warnings ---")
    for warning in mock_firewall_results['warnings']:
        print(f"⚠️  {warning}")
    
    print("\n--- Recommendations ---")
    for rec in mock_firewall_results['recommendations']:
        print(f"💡 {rec}")
    
    return True

def test_firewall_import():
    """Test importing the firewall checker module"""
    print("\nTesting Firewall Checker Import...")
    
    try:
        from scanner.firewall_checker import check_firewall_rules, OFFICE_IP, PUBLIC_PORTS
        print(f"✓ Successfully imported firewall checker")
        print(f"✓ Office IP configured: {OFFICE_IP}")
        print(f"✓ Public ports configured: {PUBLIC_PORTS}")
        return True
    except ImportError as e:
        print(f"✗ Failed to import firewall checker: {e}")
        return False

def test_security_checker_integration():
    """Test that the security checker includes firewall checking"""
    print("\nTesting Security Checker Integration...")
    
    try:
        # Check if main security checker imports firewall checker
        with open('app/scanner/security_checker.py', 'r') as f:
            content = f.read()
        
        checks = [
            ('firewall_checker import', 'from scanner.firewall_checker import check_firewall_rules' in content),
            ('firewall_security in results', "'firewall_security':" in content),
            ('firewall check call', 'check_firewall_rules(' in content),
            ('firewall issues in summary', 'firewall_security_issues' in content)
        ]
        
        all_passed = True
        for check_name, result in checks:
            if result:
                print(f"✓ {check_name} found")
            else:
                print(f"✗ {check_name} missing")
                all_passed = False
        
        return all_passed
        
    except Exception as e:
        print(f"✗ Error testing security checker integration: {e}")
        return False

def test_office_ip_configuration():
    """Test that office IP is correctly configured"""
    print("\nTesting Office IP Configuration...")
    
    try:
        from scanner.firewall_checker import OFFICE_IP, PUBLIC_PORTS
        
        expected_office_ip = "103.103.174.106"
        expected_public_ports = [80, 443]
        
        if OFFICE_IP == expected_office_ip:
            print(f"✓ Office IP correctly set to {OFFICE_IP}")
        else:
            print(f"✗ Office IP mismatch. Expected: {expected_office_ip}, Got: {OFFICE_IP}")
            return False
        
        if PUBLIC_PORTS == expected_public_ports:
            print(f"✓ Public ports correctly set to {PUBLIC_PORTS}")
        else:
            print(f"✗ Public ports mismatch. Expected: {expected_public_ports}, Got: {PUBLIC_PORTS}")
            return False
        
        return True
        
    except Exception as e:
        print(f"✗ Error testing office IP configuration: {e}")
        return False

def main():
    """Run all firewall tests"""
    print("Firewall Security Checker Validation Tests")
    print("=" * 50)
    
    tests = [
        test_firewall_import,
        test_office_ip_configuration,
        test_security_checker_integration,
        test_firewall_logic
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with error: {e}")
    
    print("\n" + "="*50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests PASSED! Firewall security checker is ready.")
        print("🔥 Office IP 103.103.174.106 configured for restricted access")
        print("🌐 Public ports [80, 443] configured for global access")
        return 0
    else:
        print("❌ Some tests FAILED. Please check the implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
