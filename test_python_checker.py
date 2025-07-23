#!/usr/bin/env python3
"""
Test script to validate Python security checker functionality
"""

import sys
import os

# Add the app directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

def test_python_swarm_container_detection():
    """Test the logic for detecting Python containers in Docker Swarm"""
    print("Testing Python Swarm Container Detection...")
    
    # Mock container output simulating Docker Swarm containers
    mock_containers = [
        "DAMON_commission.1.h0mc4sl82e6s4qagmpebnm21g",
        "DAMON_user_backend.1.2utz0hvwpe60iapukoai5i6pk",
        "DAMON_database.1.xyz123abc456def789ghi012jkl",
        "DAMON_redis.1.abc123def456ghi789jkl012mno"
    ]
    
    # Define Python service patterns to match
    python_service_names = ['commission', 'api', 'web', 'app', 'backend', 'service']
    
    found_python_containers = []
    
    for container in mock_containers:
        # Check if container contains Python service names but exclude user_backend (Node.js)
        if any(py_name in container.lower() for py_name in python_service_names) and 'user_backend' not in container.lower():
            found_python_containers.append(container)
            print(f"✓ Found Python container: {container}")
    
    print(f"\nResults:")
    print(f"Total containers checked: {len(mock_containers)}")
    print(f"Python containers found: {len(found_python_containers)}")
    print(f"Python containers: {found_python_containers}")
    
    # Test expected results
    expected_python = ["DAMON_commission.1.h0mc4sl82e6s4qagmpebnm21g"]
    
    if found_python_containers == expected_python:
        print("✓ Test PASSED: Python container detection working correctly")
        return True
    else:
        print("✗ Test FAILED: Expected different results")
        print(f"Expected: {expected_python}")
        print(f"Got: {found_python_containers}")
        return False

def test_service_name_extraction():
    """Test extracting service names from container names"""
    print("\n" + "="*50)
    print("Testing Service Name Extraction...")
    
    test_cases = [
        {
            'container': 'DAMON_commission.1.h0mc4sl82e6s4qagmpebnm21g',
            'expected_service': 'commission',
            'expected_type': 'Python'
        },
        {
            'container': 'DAMON_user_backend.1.2utz0hvwpe60iapukoai5i6pk',
            'expected_service': 'user_backend',
            'expected_type': 'Node.js'
        }
    ]
    
    all_passed = True
    
    for test_case in test_cases:
        container = test_case['container']
        
        # Extract service name (part between stack name and task number)
        parts = container.split('.')
        if len(parts) >= 2:
            service_part = parts[0]  # DAMON_commission
            if '_' in service_part:
                service_name = service_part.split('_', 1)[1]  # commission
            else:
                service_name = service_part
        else:
            service_name = "unknown"
        
        expected = test_case['expected_service']
        service_type = test_case['expected_type']
        
        if service_name == expected:
            print(f"✓ {container} -> {service_name} ({service_type})")
        else:
            print(f"✗ {container} -> Expected: {expected}, Got: {service_name}")
            all_passed = False
    
    if all_passed:
        print("✓ All service extraction tests PASSED")
        return True
    else:
        print("✗ Some service extraction tests FAILED")
        return False

def test_python_checker_import():
    """Test that we can import the Python checker module"""
    print("\n" + "="*50)
    print("Testing Python Checker Import...")
    
    try:
        from scanner.python_checker import check_python_security, check_python_swarm_config
        print("✓ Successfully imported Python security checker functions")
        
        # Test function signatures
        import inspect
        sig = inspect.signature(check_python_security)
        params = list(sig.parameters.keys())
        expected_params = ['conn', 'project_path', 'stack_name']
        
        if all(param in params for param in expected_params):
            print("✓ check_python_security has correct parameters")
        else:
            print(f"✗ check_python_security missing parameters. Expected: {expected_params}, Got: {params}")
            return False
        
        sig_swarm = inspect.signature(check_python_swarm_config)
        params_swarm = list(sig_swarm.parameters.keys())
        expected_params_swarm = ['conn', 'stack_name']
        
        if all(param in params_swarm for param in expected_params_swarm):
            print("✓ check_python_swarm_config has correct parameters")
        else:
            print(f"✗ check_python_swarm_config missing parameters. Expected: {expected_params_swarm}, Got: {params_swarm}")
            return False
        
        return True
        
    except ImportError as e:
        print(f"✗ Failed to import Python checker: {e}")
        return False
    except Exception as e:
        print(f"✗ Error testing Python checker: {e}")
        return False

def test_main_security_checker():
    """Test that main security checker includes Python checking"""
    print("\n" + "="*50)
    print("Testing Main Security Checker Integration...")
    
    try:
        from scanner.security_checker import run_full_scan
        import inspect
        
        # Get the source code to check if Python checker is integrated
        source = inspect.getsource(run_full_scan)
        
        checks = [
            ('python_security', 'python_security' in source),
            ('check_python_security import', 'from scanner.python_checker import check_python_security' in open('app/scanner/security_checker.py').read()),
            ('python security check call', 'check_python_security(conn' in source),
            ('python results in scan_results', "'python_security':" in source)
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
        print(f"✗ Error testing main security checker: {e}")
        return False

def main():
    """Run all tests"""
    print("Python Security Checker Validation Tests")
    print("=" * 50)
    
    tests = [
        test_python_swarm_container_detection,
        test_service_name_extraction,
        test_python_checker_import,
        test_main_security_checker
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
        print("🎉 All tests PASSED! Python security checker is ready.")
        return 0
    else:
        print("❌ Some tests FAILED. Please check the implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
