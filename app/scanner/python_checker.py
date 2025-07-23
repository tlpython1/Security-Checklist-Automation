import re
import json
from utils.logger import logger

def check_python_security(conn, project_path, stack_name=None):
    """
    Check Python-specific security configurations
    """
    results = {
        'python_found': False,
        'requirements_checks': {},
        'env_file_checks': {},
        'security_packages': {},
        'performance_checks': {},
        'permission_checks': {},
        'docker_config': {},
        'swarm_config': {},
        'security_summary': {
            'critical_issues': [],
            'warnings': [],
            'recommendations': []
        }
    }
    
    try:
        # Check if Python project exists (look for requirements.txt, setup.py, or main.py)
        python_indicators = ['requirements.txt', 'setup.py', 'main.py', 'app.py', 'manage.py']
        python_found = False
        
        for indicator in python_indicators:
            python_check = conn.run(f'test -f "{project_path}/{indicator}" && echo "FOUND" || echo "NOT_FOUND"', hide=True)
            if 'FOUND' in python_check.stdout:
                python_found = True
                logger.info(f"Python project indicator found: {indicator} at {project_path}")
                break
        
        if python_found:
            results['python_found'] = True
            
            # Check requirements.txt
            results['requirements_checks'] = check_python_requirements(conn, project_path)
            
            # Check .env file
            results['env_file_checks'] = check_python_env_file(conn, project_path)
            
            # Check security packages
            results['security_packages'] = check_python_security_packages(conn, project_path)
            
            # Check performance optimizations
            results['performance_checks'] = check_python_performance(conn, project_path)
            
            # Check file permissions
            results['permission_checks'] = check_python_permissions(conn, project_path)
            
            # Check Docker configuration if stack_name provided or Docker detected
            results['docker_config'] = check_python_docker_config(conn, project_path, stack_name)
            
            # Check Docker Swarm configuration
            if stack_name:
                results['swarm_config'] = check_python_swarm_config(conn, stack_name)
            
            # Generate security summary
            results['security_summary'] = generate_python_security_summary(results)
            
        else:
            results['python_found'] = False
            logger.info(f"No Python project found at {project_path}")
            
    except Exception as e:
        results['error'] = str(e)
        logger.error(f"Error checking Python security: {e}")
    
    return results

def check_python_requirements(conn, project_path):
    """
    Check requirements.txt for security configurations and vulnerabilities
    """
    requirements_checks = {
        'requirements_exists': False,
        'packages': {'count': 0, 'outdated': 0},
        'security_packages': {'django': False, 'flask': False, 'fastapi': False},
        'versions': {'pinned': 0, 'unpinned': 0},
        'vulnerable_packages': [],
        'recommendations': []
    }
    
    try:
        # Check if requirements.txt exists
        req_check = conn.run(f'test -f "{project_path}/requirements.txt" && echo "EXISTS" || echo "NOT_EXISTS"', hide=True)
        
        if 'EXISTS' in req_check.stdout:
            requirements_checks['requirements_exists'] = True
            
            # Read requirements.txt content
            req_content = conn.run(f'cat "{project_path}/requirements.txt"', hide=True)
            req_lines = req_content.stdout.strip().split('\n')
            
            for line in req_lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                requirements_checks['packages']['count'] += 1
                
                # Check if version is pinned
                if '==' in line or '>=' in line or '<=' in line or '~=' in line:
                    requirements_checks['versions']['pinned'] += 1
                else:
                    requirements_checks['versions']['unpinned'] += 1
                
                # Check for common frameworks
                package_name = line.split('==')[0].split('>=')[0].split('<=')[0].split('~=')[0].lower()
                
                if 'django' in package_name:
                    requirements_checks['security_packages']['django'] = True
                elif 'flask' in package_name:
                    requirements_checks['security_packages']['flask'] = True
                elif 'fastapi' in package_name:
                    requirements_checks['security_packages']['fastapi'] = True
                
                # Check for known vulnerable patterns
                if any(vuln in package_name for vuln in ['pillow', 'urllib3', 'requests']):
                    requirements_checks['vulnerable_packages'].append(package_name)
            
            # Recommendations
            if requirements_checks['versions']['unpinned'] > 0:
                requirements_checks['recommendations'].append('Pin package versions in requirements.txt')
            
            if not any(requirements_checks['security_packages'].values()):
                requirements_checks['recommendations'].append('Consider using a web framework with built-in security features')
                
    except Exception as e:
        requirements_checks['error'] = str(e)
    
    return requirements_checks

def check_python_env_file(conn, project_path):
    """
    Check Python .env file configurations
    """
    env_checks = {
        'env_file_exists': False,
        'django_settings': {'debug': None, 'secret_key': None, 'allowed_hosts': None},
        'flask_config': {'debug': None, 'secret_key': None},
        'database_config': {'exposed': False, 'recommendation': 'Use environment variables for database credentials'},
        'api_keys': {'exposed': False, 'recommendation': 'Secure API keys and tokens'},
        'cors_config': {'value': None, 'secure': False},
        'ssl_config': {'enabled': False, 'recommendation': 'Enable SSL/TLS in production'}
    }
    
    try:
        # Check if .env file exists
        env_file_check = conn.run(f'test -f "{project_path}/.env" && echo "EXISTS" || echo "NOT_EXISTS"', hide=True)
        
        if 'EXISTS' in env_file_check.stdout:
            env_checks['env_file_exists'] = True
            
            # Read .env file content
            env_content = conn.run(f'cat "{project_path}/.env"', hide=True)
            env_lines = env_content.stdout.strip().split('\n')
            
            for line in env_lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip().upper()
                    value = value.strip().strip('"\'')
                    
                    # Django specific checks
                    if key == 'DEBUG':
                        env_checks['django_settings']['debug'] = value.lower()
                    elif key == 'SECRET_KEY':
                        env_checks['django_settings']['secret_key'] = bool(value) and len(value) > 20
                        env_checks['flask_config']['secret_key'] = bool(value) and len(value) > 20
                    elif key == 'ALLOWED_HOSTS':
                        env_checks['django_settings']['allowed_hosts'] = value
                    
                    # Flask specific checks
                    elif key == 'FLASK_DEBUG':
                        env_checks['flask_config']['debug'] = value.lower()
                    
                    # Database credentials
                    elif any(db_key in key for db_key in ['DATABASE_URL', 'DB_PASSWORD', 'POSTGRES_PASSWORD', 'MYSQL_PASSWORD']):
                        if any(weak in value.lower() for weak in ['password', '123456', 'admin', 'root', '']):
                            env_checks['database_config']['exposed'] = True
                    
                    # API keys
                    elif any(api_key in key for api_key in ['API_KEY', 'SECRET_KEY', 'ACCESS_TOKEN', 'AUTH_TOKEN']):
                        if value and value.lower() not in ['null', '']:
                            env_checks['api_keys']['exposed'] = True
                    
                    # SSL configuration
                    elif any(ssl_key in key for ssl_key in ['SSL', 'HTTPS', 'TLS']):
                        env_checks['ssl_config']['enabled'] = value.lower() in ['true', '1', 'yes', 'enabled']
        
        else:
            env_checks['env_file_exists'] = False
            
    except Exception as e:
        env_checks['error'] = str(e)
    
    return env_checks

def check_python_security_packages(conn, project_path):
    """
    Check for Python security-related packages and configurations
    """
    security_checks = {
        'security_packages': {
            'django_security': False,
            'flask_security': False,
            'cryptography': False,
            'bcrypt': False,
            'pyjwt': False,
            'corsheaders': False
        },
        'vulnerability_scan': {'run': False, 'recommendation': 'Run pip audit or safety check'},
        'outdated_packages': {'count': 0, 'recommendation': 'Update outdated packages regularly'}
    }
    
    try:
        # Check if requirements.txt exists
        req_check = conn.run(f'test -f "{project_path}/requirements.txt" && echo "EXISTS"', hide=True)
        
        if 'EXISTS' in req_check.stdout:
            # Read requirements.txt for security packages
            req_content = conn.run(f'cat "{project_path}/requirements.txt"', hide=True)
            req_text = req_content.stdout.lower()
            
            # Check for security packages
            security_checks['security_packages']['django_security'] = 'django' in req_text and any(sec in req_text for sec in ['django-security', 'django-cors-headers'])
            security_checks['security_packages']['flask_security'] = 'flask' in req_text and any(sec in req_text for sec in ['flask-security', 'flask-cors'])
            security_checks['security_packages']['cryptography'] = 'cryptography' in req_text
            security_checks['security_packages']['bcrypt'] = 'bcrypt' in req_text
            security_checks['security_packages']['pyjwt'] = 'pyjwt' in req_text
            security_checks['security_packages']['corsheaders'] = 'cors' in req_text
        
        # Try to run pip check (if available)
        pip_check = conn.run(f'cd "{project_path}" && pip check 2>/dev/null || echo "PIP_CHECK_FAILED"', hide=True, warn=True)
        if pip_check.ok and 'PIP_CHECK_FAILED' not in pip_check.stdout:
            if 'No broken requirements found' in pip_check.stdout:
                security_checks['vulnerability_scan']['run'] = True
                security_checks['vulnerability_scan']['issues'] = 0
            else:
                security_checks['vulnerability_scan']['run'] = True
                security_checks['vulnerability_scan']['issues'] = len(pip_check.stdout.strip().split('\n'))
        
        # Try to check for outdated packages
        pip_outdated = conn.run(f'cd "{project_path}" && pip list --outdated --format=json 2>/dev/null || echo "OUTDATED_CHECK_FAILED"', hide=True, warn=True)
        if pip_outdated.ok and 'OUTDATED_CHECK_FAILED' not in pip_outdated.stdout:
            try:
                outdated_data = json.loads(pip_outdated.stdout)
                security_checks['outdated_packages']['count'] = len(outdated_data)
                security_checks['outdated_packages']['packages'] = [pkg['name'] for pkg in outdated_data]
            except:
                pass
                
    except Exception as e:
        security_checks['error'] = str(e)
    
    return security_checks

def check_python_performance(conn, project_path):
    """
    Check Python performance optimizations
    """
    performance_checks = {
        'wsgi_server': {'configured': False, 'recommendation': 'Use production WSGI server like Gunicorn or uWSGI'},
        'caching': {'configured': False, 'recommendation': 'Configure caching strategy (Redis, Memcached)'},
        'static_files': {'configured': False, 'recommendation': 'Use web server for static files in production'},
        'database_optimization': {'configured': False, 'recommendation': 'Configure database connection pooling'},
        'monitoring': {'configured': False, 'recommendation': 'Implement application monitoring'},
        'health_check': {'exists': False, 'recommendation': 'Implement health check endpoints'}
    }
    
    try:
        # Check for WSGI servers in requirements
        req_check = conn.run(f'test -f "{project_path}/requirements.txt" && cat "{project_path}/requirements.txt"', hide=True, warn=True)
        if req_check.ok:
            req_text = req_check.stdout.lower()
            performance_checks['wsgi_server']['configured'] = any(server in req_text for server in ['gunicorn', 'uwsgi', 'waitress', 'gevent'])
            
            # Check for caching packages
            performance_checks['caching']['configured'] = any(cache in req_text for cache in ['redis', 'memcached', 'django-cache', 'flask-cache'])
        
        # Check for common Python web files
        web_files = ['wsgi.py', 'asgi.py', 'gunicorn.conf.py', 'uwsgi.ini']
        for web_file in web_files:
            file_check = conn.run(f'test -f "{project_path}/{web_file}" && echo "EXISTS"', hide=True, warn=True)
            if file_check.ok and 'EXISTS' in file_check.stdout:
                performance_checks['wsgi_server']['configured'] = True
                performance_checks['wsgi_server']['file'] = web_file
                break
        
        # Check for health check endpoints in common files
        health_patterns = ['/health', '/status', '/ping', 'health_check']
        python_files = ['main.py', 'app.py', 'urls.py', 'routes.py']
        
        for py_file in python_files:
            if conn.run(f'test -f "{project_path}/{py_file}"', hide=True, warn=True).ok:
                for pattern in health_patterns:
                    health_check = conn.run(f'grep -i "{pattern}" "{project_path}/{py_file}"', hide=True, warn=True)
                    if health_check.ok and health_check.stdout.strip():
                        performance_checks['health_check']['exists'] = True
                        break
                if performance_checks['health_check']['exists']:
                    break
                    
    except Exception as e:
        performance_checks['error'] = str(e)
    
    return performance_checks

def check_python_permissions(conn, project_path):
    """
    Check Python file and directory permissions
    """
    permission_checks = {
        'venv_permissions': {'secure': False, 'recommendation': 'Virtual environment should not be web accessible'},
        'env_file_permissions': {'secure': False, 'permissions': None, 'recommendation': '.env file should not be world readable'},
        'python_files_permissions': {'executable': False, 'recommendation': 'Python files should have proper permissions'},
        'logs_directory': {'writable': False, 'exists': False, 'recommendation': 'Logs directory should be writable'},
        'static_directory': {'secure': False, 'recommendation': 'Static files directory should have restricted permissions'}
    }
    
    try:
        # Check virtual environment permissions
        venv_dirs = ['venv', 'env', '.venv']
        for venv_dir in venv_dirs:
            venv_perm = conn.run(f'ls -ld "{project_path}/{venv_dir}"', hide=True, warn=True)
            if venv_perm.ok:
                perm_string = venv_perm.stdout.strip().split()[0]
                permission_checks['venv_permissions']['permissions'] = perm_string
                permission_checks['venv_permissions']['secure'] = perm_string[-1] not in ['4', '5', '6', '7']
                break
        
        # Check .env file permissions
        env_perm = conn.run(f'ls -la "{project_path}/.env"', hide=True, warn=True)
        if env_perm.ok:
            perm_string = env_perm.stdout.strip().split()[0]
            permission_checks['env_file_permissions']['permissions'] = perm_string
            permission_checks['env_file_permissions']['secure'] = perm_string[-1] not in ['4', '5', '6', '7']
        
        # Check main Python files permissions
        python_files = ['main.py', 'app.py', 'manage.py', 'wsgi.py']
        for py_file in python_files:
            py_perm = conn.run(f'ls -la "{project_path}/{py_file}"', hide=True, warn=True)
            if py_perm.ok:
                perm_string = py_perm.stdout.strip().split()[0]
                permission_checks['python_files_permissions']['executable'] = 'x' in perm_string[1:4]
                permission_checks['python_files_permissions']['file'] = py_file
                break
        
        # Check logs directory
        logs_dirs = ['logs', 'log', 'var/log']
        for logs_dir in logs_dirs:
            logs_check = conn.run(f'test -d "{project_path}/{logs_dir}" && echo "EXISTS"', hide=True, warn=True)
            if logs_check.ok and 'EXISTS' in logs_check.stdout:
                permission_checks['logs_directory']['exists'] = True
                logs_perm = conn.run(f'test -w "{project_path}/{logs_dir}" && echo "WRITABLE"', hide=True, warn=True)
                if logs_perm.ok and 'WRITABLE' in logs_perm.stdout:
                    permission_checks['logs_directory']['writable'] = True
                break
        
        # Check static directory
        static_dirs = ['static', 'staticfiles', 'public']
        for static_dir in static_dirs:
            static_check = conn.run(f'test -d "{project_path}/{static_dir}" && echo "EXISTS"', hide=True, warn=True)
            if static_check.ok and 'EXISTS' in static_check.stdout:
                static_perm = conn.run(f'ls -ld "{project_path}/{static_dir}"', hide=True, warn=True)
                if static_perm.ok:
                    perm_string = static_perm.stdout.strip().split()[0]
                    permission_checks['static_directory']['secure'] = perm_string[-1] not in ['6', '7']
                    permission_checks['static_directory']['directory'] = static_dir
                break
            
    except Exception as e:
        permission_checks['error'] = str(e)
    
    return permission_checks

def check_python_docker_config(conn, project_path, stack_name=None):
    """
    Check Python Docker configuration and security
    """
    docker_checks = {
        'dockerfile_exists': False,
        'docker_compose_exists': False,
        'container_running': False,
        'security_issues': [],
        'user_config': {'non_root': False, 'recommendation': 'Run container as non-root user'},
        'secrets_management': {'secure': False, 'recommendation': 'Use Docker secrets for sensitive data'},
        'network_config': {'isolated': False, 'recommendation': 'Use custom networks for isolation'},
        'volume_mounts': {'secure': False, 'recommendation': 'Avoid mounting sensitive host directories'},
        'health_check': {'configured': False, 'recommendation': 'Configure health checks in Dockerfile'}
    }
    
    try:
        # Check if Dockerfile exists
        dockerfile_check = conn.run(f'test -f "{project_path}/Dockerfile" && echo "EXISTS"', hide=True, warn=True)
        if dockerfile_check.ok and 'EXISTS' in dockerfile_check.stdout:
            docker_checks['dockerfile_exists'] = True
            
            # Analyze Dockerfile for security issues
            dockerfile_content = conn.run(f'cat "{project_path}/Dockerfile"', hide=True, warn=True)
            if dockerfile_content.ok:
                dockerfile_lines = dockerfile_content.stdout.lower().split('\n')
                
                # Check for non-root user
                user_found = any('user ' in line and 'root' not in line for line in dockerfile_lines)
                docker_checks['user_config']['non_root'] = user_found
                
                # Check for health check
                health_check_found = any('healthcheck' in line for line in dockerfile_lines)
                docker_checks['health_check']['configured'] = health_check_found
                
                # Check for security issues
                for line in dockerfile_lines:
                    if 'user root' in line:
                        docker_checks['security_issues'].append('Running as root user')
                    if 'add --chown=root' in line:
                        docker_checks['security_issues'].append('Adding files with root ownership')
                    if 'chmod 777' in line:
                        docker_checks['security_issues'].append('Setting overly permissive file permissions')
                    if 'pip install' in line and '--trusted-host' in line:
                        docker_checks['security_issues'].append('Using untrusted pip hosts')
        
        # Check if docker-compose.yml exists
        compose_check = conn.run(f'test -f "{project_path}/docker-compose.yml" && echo "EXISTS"', hide=True, warn=True)
        if compose_check.ok and 'EXISTS' in compose_check.stdout:
            docker_checks['docker_compose_exists'] = True
            
            # Analyze docker-compose for security
            compose_content = conn.run(f'cat "{project_path}/docker-compose.yml"', hide=True, warn=True)
            if compose_content.ok:
                compose_text = compose_content.stdout.lower()
                
                # Check for custom networks
                docker_checks['network_config']['isolated'] = 'networks:' in compose_text
                
                # Check for volume security
                if 'volumes:' in compose_text:
                    dangerous_mounts = ['/:', '/etc:', '/var/run/docker.sock', '/proc:', '/sys:']
                    for mount in dangerous_mounts:
                        if mount in compose_text:
                            docker_checks['security_issues'].append(f'Dangerous volume mount detected: {mount}')
                    docker_checks['volume_mounts']['secure'] = len([m for m in dangerous_mounts if m in compose_text]) == 0
        
        # Check if Python container is running
        if stack_name:
            # Check Docker Swarm service for Python services
            service_check = conn.run(f'docker service ls --filter name={stack_name} --format "{{{{.Name}}}}"', hide=True, warn=True)
            if service_check.ok and service_check.stdout.strip():
                services = service_check.stdout.strip().split('\n')
                python_services = [s for s in services if any(py_name in s.lower() for py_name in ['commission', 'api', 'web', 'app'])]
                if python_services:
                    docker_checks['container_running'] = True
                    docker_checks['service_names'] = python_services
        else:
            # Check regular Docker containers
            container_check = conn.run(f'docker ps --filter "ancestor=python" --format "{{{{.Names}}}}"', hide=True, warn=True)
            if container_check.ok and container_check.stdout.strip():
                docker_checks['container_running'] = True
                docker_checks['container_names'] = container_check.stdout.strip().split('\n')
        
    except Exception as e:
        docker_checks['error'] = str(e)
    
    return docker_checks

def check_python_swarm_config(conn, stack_name):
    """
    Check Docker Swarm specific configuration for Python stack
    """
    swarm_checks = {
        'stack_deployed': False,
        'services': [],
        'python_services': [],
        'python_containers': [],
        'replicas': {},
        'networks': [],
        'secrets': [],
        'configs': [],
        'security_issues': [],
        'recommendations': []
    }
    
    try:
        logger.info(f"Checking Docker Swarm configuration for Python services in stack: {stack_name}")
        
        # Check if stack is deployed
        stack_check = conn.run(f'docker stack ls --format "{{{{.Name}}}}" | grep -x {stack_name}', hide=True, warn=True)
        if stack_check.ok and stack_check.stdout.strip():
            swarm_checks['stack_deployed'] = True
            logger.info(f"Stack {stack_name} is deployed")
            
            # Get stack services
            services_result = conn.run(f'docker stack services {stack_name} --format "{{{{.Name}}}} {{{{.Replicas}}}}"', hide=True, warn=True)
            if services_result.ok:
                services_lines = services_result.stdout.strip().split('\n')
                for line in services_lines:
                    if line.strip():
                        parts = line.split()
                        service_name = parts[0]
                        replicas = parts[1] if len(parts) > 1 else 'Unknown'
                        swarm_checks['services'].append(service_name)
                        swarm_checks['replicas'][service_name] = replicas
                        
                        # Check if it's a Python service (contains common Python service names)
                        python_service_names = ['commission', 'api', 'web', 'app', 'backend', 'service']
                        if any(py_name in service_name.lower() for py_name in python_service_names) and 'user_backend' not in service_name.lower():
                            swarm_checks['python_services'].append(service_name)
                            logger.info(f"Found Python service: {service_name}")
            
            # Also check running containers to find Python containers
            containers_result = conn.run(f'docker ps | grep {stack_name}', hide=True, warn=True)
            if containers_result.ok and containers_result.stdout.strip():
                container_lines = containers_result.stdout.strip().split('\n')
                python_containers = []
                
                for line in container_lines:
                    # Look for containers with Python service names
                    python_service_names = ['commission', 'api', 'web', 'app', 'backend', 'service']
                    if any(py_name in line.lower() for py_name in python_service_names) and 'user_backend' not in line.lower():
                        # Extract container name (last column in docker ps output)
                        parts = line.split()
                        if parts:
                            container_name = parts[-1]
                            python_containers.append(container_name)
                            logger.info(f"Found Python container: {container_name}")
                
                # Store the found containers
                swarm_checks['python_containers'] = python_containers
                
                # If we found containers but no services, containers might be the actual running instances
                if python_containers and not swarm_checks['python_services']:
                    swarm_checks['python_services'] = python_containers
                    logger.info(f"Using containers as Python services: {python_containers}")
            else:
                swarm_checks['python_containers'] = []
            
            # Get stack networks
            networks_result = conn.run(f'docker network ls --filter "label=com.docker.stack.namespace={stack_name}" --format "{{{{.Name}}}}"', hide=True, warn=True)
            if networks_result.ok:
                networks = networks_result.stdout.strip().split('\n') if networks_result.stdout.strip() else []
                swarm_checks['networks'] = [net for net in networks if net.strip()]
            
            # Get stack secrets
            secrets_result = conn.run(f'docker secret ls --filter "label=com.docker.stack.namespace={stack_name}" --format "{{{{.Name}}}}"', hide=True, warn=True)
            if secrets_result.ok:
                secrets = secrets_result.stdout.strip().split('\n') if secrets_result.stdout.strip() else []
                swarm_checks['secrets'] = [sec for sec in secrets if sec.strip()]
            
            # Get stack configs
            configs_result = conn.run(f'docker config ls --filter "label=com.docker.stack.namespace={stack_name}" --format "{{{{.Name}}}}"', hide=True, warn=True)
            if configs_result.ok:
                configs = configs_result.stdout.strip().split('\n') if configs_result.stdout.strip() else []
                swarm_checks['configs'] = [conf for conf in configs if conf.strip()]
            
            # Security analysis for Python containers
            if swarm_checks['python_services']:
                logger.info(f"Found {len(swarm_checks['python_services'])} Python services in stack")
                
                for service in swarm_checks['python_services']:
                    # Check if this is actually a container name (not a service)
                    if service in swarm_checks.get('python_containers', []):
                        # This is a container, perform container-specific checks
                        try:
                            # Check if container is running Python
                            python_check = conn.run(f'docker exec {service} python --version 2>/dev/null || python3 --version 2>/dev/null || echo "NO_PYTHON"', hide=True, warn=True)
                            if python_check.ok and 'NO_PYTHON' not in python_check.stdout:
                                python_version = python_check.stdout.strip()
                                logger.info(f"Container {service} running Python {python_version}")
                                swarm_checks[f'python_version_{service}'] = python_version
                            
                            # Check for requirements.txt and security packages
                            req_check = conn.run(f'docker exec {service} find /app -name "requirements.txt" -type f 2>/dev/null | head -1', hide=True, warn=True)
                            if req_check.ok and req_check.stdout.strip():
                                req_path = req_check.stdout.strip()
                                
                                # Check for security packages
                                security_check = conn.run(f'docker exec {service} cat {req_path} | grep -E "(django|flask|fastapi|cryptography|bcrypt)"', hide=True, warn=True)
                                if not security_check.ok or not security_check.stdout.strip():
                                    swarm_checks['security_issues'].append(f'Container {service} missing security packages')
                                
                                # Check for pip vulnerabilities
                                vuln_check = conn.run(f'docker exec {service} pip check 2>/dev/null || echo "PIP_CHECK_FAILED"', hide=True, warn=True)
                                if vuln_check.ok and 'PIP_CHECK_FAILED' not in vuln_check.stdout:
                                    if 'No broken requirements found' not in vuln_check.stdout:
                                        issues = len(vuln_check.stdout.strip().split('\n'))
                                        swarm_checks['security_issues'].append(f'Container {service} has {issues} pip dependency issues')
                            
                            # Check if running as root
                            user_check = conn.run(f'docker exec {service} whoami 2>/dev/null || echo "UNKNOWN"', hide=True, warn=True)
                            if user_check.ok and 'root' in user_check.stdout.strip():
                                swarm_checks['security_issues'].append(f'Container {service} running as root user')
                                
                        except Exception as e:
                            logger.warning(f"Could not inspect Python container {service}: {e}")
            
            # Security recommendations for Swarm
            if not swarm_checks['secrets']:
                swarm_checks['recommendations'].append('Consider using Docker secrets for sensitive data')
            
            if not swarm_checks['networks']:
                swarm_checks['recommendations'].append('Use custom networks for service isolation')
            
            if not swarm_checks['python_services']:
                swarm_checks['recommendations'].append(f'No Python services found in stack {stack_name}')
                logger.info(f"No Python services found in stack {stack_name}")
            
            # Check for single replica services (potential availability issue)
            for service, replica_info in swarm_checks['replicas'].items():
                if '1/1' in replica_info and service in swarm_checks['python_services']:
                    swarm_checks['recommendations'].append(f'Consider scaling Python service {service} for high availability')
            
            # Check service logs for Python specific issues
            for service in swarm_checks['python_services']:
                try:
                    log_check = conn.run(f'docker service logs --tail 10 {service} 2>/dev/null | grep -i "error\\|warning\\|exception\\|traceback"', hide=True, warn=True)
                    if log_check.ok and log_check.stdout.strip():
                        error_lines = log_check.stdout.strip().split('\n')
                        if len(error_lines) > 0:
                            swarm_checks['security_issues'].append(f'Service {service} has {len(error_lines)} error/warning logs')
                            logger.warning(f"Found {len(error_lines)} issues in logs for Python service {service}")
                except Exception as e:
                    logger.warning(f"Could not check logs for Python service {service}: {e}")
        
        else:
            swarm_checks['stack_deployed'] = False
            swarm_checks['error'] = f'Stack {stack_name} not found'
            logger.info(f"Stack {stack_name} not found")
    
    except Exception as e:
        swarm_checks['error'] = str(e)
        logger.error(f"Error checking Python Swarm configuration: {e}")
    
    return swarm_checks

def generate_python_security_summary(results):
    """
    Generate security summary with critical issues, warnings, and recommendations
    """
    summary = {
        'critical_issues': [],
        'warnings': [],
        'recommendations': []
    }
    
    if not results['python_found']:
        return summary
    
    env_checks = results.get('env_file_checks', {})
    requirements_checks = results.get('requirements_checks', {})
    security_packages = results.get('security_packages', {})
    performance_checks = results.get('performance_checks', {})
    permission_checks = results.get('permission_checks', {})
    docker_config = results.get('docker_config', {})
    swarm_config = results.get('swarm_config', {})
    
    # Critical issues
    if not env_checks.get('env_file_exists', False):
        summary['critical_issues'].append('.env file not found - environment variables not configured')
    
    if env_checks.get('django_settings', {}).get('debug') == 'true':
        summary['critical_issues'].append('Django DEBUG is enabled - should be False in production')
    
    if env_checks.get('flask_config', {}).get('debug') == 'true':
        summary['critical_issues'].append('Flask DEBUG is enabled - should be False in production')
    
    if not env_checks.get('django_settings', {}).get('secret_key', False):
        summary['critical_issues'].append('Django/Flask SECRET_KEY is weak or missing')
    
    if not permission_checks.get('env_file_permissions', {}).get('secure', False):
        summary['critical_issues'].append('.env file has insecure permissions - sensitive data may be exposed')
    
    if security_packages.get('vulnerability_scan', {}).get('issues', 0) > 0:
        issue_count = security_packages['vulnerability_scan']['issues']
        summary['critical_issues'].append(f'Found {issue_count} pip dependency issues')
    
    # Docker-specific critical issues
    if docker_config.get('security_issues'):
        for issue in docker_config['security_issues']:
            summary['critical_issues'].append(f'Docker security issue: {issue}')
    
    if not docker_config.get('user_config', {}).get('non_root', True):
        summary['critical_issues'].append('Docker container running as root user')
    
    # Warnings
    if env_checks.get('database_config', {}).get('exposed', False):
        summary['warnings'].append('Database credentials appear to use default or weak values')
    
    if requirements_checks.get('versions', {}).get('unpinned', 0) > 3:
        unpinned_count = requirements_checks['versions']['unpinned']
        summary['warnings'].append(f'{unpinned_count} packages have unpinned versions in requirements.txt')
    
    if security_packages.get('outdated_packages', {}).get('count', 0) > 5:
        summary['warnings'].append(f'{security_packages["outdated_packages"]["count"]} packages are outdated')
    
    # Docker-specific warnings
    if docker_config.get('dockerfile_exists') and not docker_config.get('health_check', {}).get('configured', False):
        summary['warnings'].append('Docker health check not configured')
    
    if docker_config.get('docker_compose_exists') and not docker_config.get('network_config', {}).get('isolated', False):
        summary['warnings'].append('Docker services not using custom networks for isolation')
    
    # Swarm-specific warnings
    if swarm_config.get('stack_deployed') and not swarm_config.get('secrets'):
        summary['warnings'].append('Docker Swarm stack not using secrets for sensitive data')
    
    # Recommendations
    if not any(security_packages.get('security_packages', {}).values()):
        summary['recommendations'].append('Install security packages for your Python framework')
    
    if not performance_checks.get('wsgi_server', {}).get('configured', False):
        summary['recommendations'].append('Configure production WSGI server: pip install gunicorn')
    
    if not performance_checks.get('caching', {}).get('configured', False):
        summary['recommendations'].append('Configure caching: pip install redis or memcached')
    
    if not performance_checks.get('health_check', {}).get('exists', False):
        summary['recommendations'].append('Implement health check endpoints for monitoring')
    
    if not env_checks.get('ssl_config', {}).get('enabled', False):
        summary['recommendations'].append('Enable SSL/TLS configuration for secure connections')
    
    # Docker recommendations
    if docker_config.get('dockerfile_exists'):
        if not docker_config.get('user_config', {}).get('non_root', False):
            summary['recommendations'].append('Configure Docker container to run as non-root user')
        if not docker_config.get('health_check', {}).get('configured', False):
            summary['recommendations'].append('Add HEALTHCHECK instruction to Dockerfile')
    
    # Swarm recommendations
    if swarm_config.get('recommendations'):
        summary['recommendations'].extend(swarm_config['recommendations'])
    
    return summary
