import re
import json
from utils.logger import logger

def check_nodejs_security(conn, project_path, stack_name=None):
    """
    Check Node.js-specific security configurations
    """
    results = {
        'nodejs_found': False,
        'package_checks': {},
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
        # Check if Node.js project exists
        nodejs_check = conn.run(f'test -f "{project_path}/package.json" && echo "FOUND" || echo "NOT_FOUND"', hide=True)
        
        if 'FOUND' in nodejs_check.stdout:
            results['nodejs_found'] = True
            logger.info(f"Node.js project found at {project_path}")
            
            # Check package.json
            results['package_checks'] = check_nodejs_package_json(conn, project_path)
            
            # Check .env file
            results['env_file_checks'] = check_nodejs_env_file(conn, project_path)
            
            # Check security packages
            results['security_packages'] = check_nodejs_security_packages(conn, project_path)
            
            # Check performance optimizations
            results['performance_checks'] = check_nodejs_performance(conn, project_path)
            
            # Check file permissions
            results['permission_checks'] = check_nodejs_permissions(conn, project_path)
            
            # Check Docker configuration if stack_name provided or Docker detected
            results['docker_config'] = check_nodejs_docker_config(conn, project_path, stack_name)
            
            # Check Docker Swarm configuration
            if stack_name:
                results['swarm_config'] = check_nodejs_swarm_config(conn, stack_name)
            
            # Generate security summary
            results['security_summary'] = generate_nodejs_security_summary(results)
            
        else:
            results['nodejs_found'] = False
            logger.info(f"No Node.js project found at {project_path}")
            
    except Exception as e:
        results['error'] = str(e)
        logger.error(f"Error checking Node.js security: {e}", exc_info=True)
    
    return results

def check_nodejs_package_json(conn, project_path):
    """
    Check package.json for security configurations and vulnerabilities
    """
    package_checks = {
        'package_json_exists': False,
        'dependencies': {'count': 0, 'dev_dependencies': 0},
        'scripts': {'audit': False, 'security_check': False},
        'node_version': {'specified': False, 'version': None},
        'main_file': {'exists': False, 'file': None},
        'private': {'set': False, 'recommendation': 'Set "private": true if not publishing to npm'},
        'engines': {'specified': False, 'recommendation': 'Specify Node.js engine version'}
    }
    
    try:
        # Check if package.json exists
        package_check = conn.run(f'test -f "{project_path}/package.json" && echo "EXISTS" || echo "NOT_EXISTS"', hide=True)
        
        if 'EXISTS' in package_check.stdout:
            package_checks['package_json_exists'] = True
            
            # Read package.json content
            package_content = conn.run(f'cat "{project_path}/package.json"', hide=True)
            try:
                package_data = json.loads(package_content.stdout)
                
                # Check dependencies
                dependencies = package_data.get('dependencies', {})
                dev_dependencies = package_data.get('devDependencies', {})
                package_checks['dependencies']['count'] = len(dependencies)
                package_checks['dependencies']['dev_dependencies'] = len(dev_dependencies)
                
                # Check scripts
                scripts = package_data.get('scripts', {})
                package_checks['scripts']['audit'] = 'audit' in scripts or 'security' in str(scripts).lower()
                package_checks['scripts']['security_check'] = any(sec in str(scripts).lower() for sec in ['security', 'audit', 'snyk'])
                
                # Check engines
                engines = package_data.get('engines', {})
                if engines and 'node' in engines:
                    package_checks['engines']['specified'] = True
                    package_checks['node_version']['specified'] = True
                    package_checks['node_version']['version'] = engines['node']
                
                # Check main file
                main_file = package_data.get('main', 'index.js')
                package_checks['main_file']['file'] = main_file
                main_exists = conn.run(f'test -f "{project_path}/{main_file}" && echo "EXISTS"', hide=True, warn=True)
                package_checks['main_file']['exists'] = 'EXISTS' in main_exists.stdout if main_exists.ok else False
                
                # Check private flag
                package_checks['private']['set'] = package_data.get('private', False)
                
            except json.JSONDecodeError:
                package_checks['error'] = 'Invalid JSON format in package.json'
                
    except Exception as e:
        package_checks['error'] = str(e)
    
    return package_checks

def check_nodejs_env_file(conn, project_path):
    """
    Check Node.js .env file configurations
    """
    env_checks = {
        'env_file_exists': False,
        'node_env': {'value': None, 'secure': False, 'recommendation': 'Set NODE_ENV=production for production environment'},
        'port': {'value': None, 'secure': False, 'recommendation': 'Avoid using privileged ports (< 1024)'},
        'database_config': {'complete': False, 'secure': False, 'recommendation': 'Ensure database credentials are properly configured'},
        'mail_config': {'complete': False, 'recommendation': 'Configure mail settings for production'},
        'payment_config': {'secure': False, 'recommendation': 'Secure payment gateway configuration'},
        'token_security': {'secure': False, 'recommendation': 'Use strong and unique token keys'},
        'demo_status': {'value': None, 'secure': False, 'recommendation': 'Set DEMO_STATUS=NO for production'},
        'prefix_config': {'value': None, 'configured': False, 'recommendation': 'Configure PREFIX properly'},
        'url_security': {'secure': False, 'ip_based_urls': [], 'recommendation': 'Use domain names with HTTPS instead of IP addresses'},
        'secret_keys': {'secure': False, 'recommendation': 'Use strong secret keys'},
        'custom_checks': {}
    }
    
    try:
        # Check if .env file exists
        env_file_check = conn.run(f'test -f "{project_path}/.env" && echo "EXISTS" || echo "NOT_EXISTS"', hide=True)
        
        if 'EXISTS' in env_file_check.stdout:
            env_checks['env_file_exists'] = True
            
            # Read .env file content
            env_content = conn.run(f'cat "{project_path}/.env"', hide=True)
            env_lines = env_content.stdout.strip().split('\n')
            
            # Track database configuration completeness
            mysql_fields = {'MYSQL_DB': None, 'MYSQL_USER': None, 'MYSQL_PASS': None, 'MYSQL_HOST': None, 'MYSQL_PORT': None}
            mail_fields = {'MAIL_HOST': None, 'MAIL_PORT': None, 'MAIL_USERNAME': None, 'MAIL_PASSWORD': None}
            url_fields = {'SITE_URL': None, 'ADMIN_URL': None, 'FRONTEND_URL': None, 'STORE_URL': None, 'IMAGE_URL': None, 'LOG_PATH': None}
            token_fields = {'TOKEN_KEY': None, 'APP_TOKEN_KEY': None, 'SECRETKEY': None}
            
            for line in env_lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip().upper()
                    value = value.strip().strip('"\'')
                    
                    # Check NODE_ENV
                    if key == 'NODE_ENV':
                        env_checks['node_env']['value'] = value
                        env_checks['node_env']['secure'] = value.lower() == 'production'
                    
                    # Check PORT
                    elif key == 'PORT':
                        env_checks['port']['value'] = value
                        try:
                            port_num = int(value)
                            env_checks['port']['secure'] = port_num >= 1024
                        except ValueError:
                            env_checks['port']['secure'] = False
                    
                    # Check DEMO_STATUS
                    elif key == 'DEMO_STATUS':
                        env_checks['demo_status']['value'] = value
                        env_checks['demo_status']['secure'] = value.upper() == 'NO'
                    
                    # Check PREFIX
                    elif key == 'PREFIX':
                        env_checks['prefix_config']['value'] = value
                        env_checks['prefix_config']['configured'] = bool(value and value != '')
                    
                    # Check MySQL database fields
                    elif key in mysql_fields:
                        mysql_fields[key] = value
                    
                    # Check mail configuration fields
                    elif key in mail_fields:
                        mail_fields[key] = value
                    
                    # Check URL fields for IP-based addresses
                    elif key in url_fields:
                        url_fields[key] = value
                        if value and ('192.168.' in value or '127.0.0.1' in value or '10.' in value or 'localhost' in value):
                            env_checks['url_security']['ip_based_urls'].append(f"{key}={value}")
                    
                    # Check token security
                    elif key in token_fields:
                        token_fields[key] = value
            
            # Validate database configuration completeness
            env_checks['database_config']['complete'] = all(mysql_fields.values())
            # Check for weak database passwords
            mysql_pass = mysql_fields.get('MYSQL_PASS', '')
            if mysql_pass and any(weak in mysql_pass.lower() for weak in ['password', '123456', 'admin', 'root']):
                env_checks['database_config']['secure'] = False
            else:
                env_checks['database_config']['secure'] = bool(mysql_pass and len(mysql_pass) > 8)
            
            # Validate mail configuration
            env_checks['mail_config']['complete'] = any(mail_fields.values())
            
            # Validate payment configuration
            payment_check = any(key for line in env_lines if line.strip() and '=' in line for key in line.split('=')[0].strip().upper() if 'PAYPAL' in key or 'STRIPE' in key)
            env_checks['payment_config']['secure'] = payment_check
            
            # Validate token security
            token_secure = all(token and len(token) > 20 for token in token_fields.values() if token)
            env_checks['token_security']['secure'] = token_secure
            
            # Check URL security (domain vs IP)
            env_checks['url_security']['secure'] = len(env_checks['url_security']['ip_based_urls']) == 0
            
            # Custom security checks
            env_checks['custom_checks'] = {
                'mysql_config_complete': all(mysql_fields.values()),
                'demo_status_production': env_checks['demo_status']['secure'],
                'prefix_configured': env_checks['prefix_config']['configured'],
                'urls_domain_based': env_checks['url_security']['secure'],
                'strong_tokens': env_checks['token_security']['secure']
            }
        
        else:
            env_checks['env_file_exists'] = False
            
    except Exception as e:
        env_checks['error'] = str(e)
    
    return env_checks

def check_nodejs_security_packages(conn, project_path):
    """
    Check for security-related packages and configurations
    """
    security_checks = {
        'helmet_installed': {'installed': False, 'recommendation': 'Install helmet for security headers'},
        'cors_installed': {'installed': False, 'recommendation': 'Install cors for CORS configuration'},
        'bcrypt_installed': {'installed': False, 'recommendation': 'Use bcrypt for password hashing'},
        'rate_limiting': {'installed': False, 'recommendation': 'Install express-rate-limit for rate limiting'},
        'validator_installed': {'installed': False, 'recommendation': 'Install validator for input validation'},
        'dotenv_installed': {'installed': False, 'recommendation': 'Install dotenv for environment variables'},
        'security_audit': {'run': False, 'recommendation': 'Run npm audit to check for vulnerabilities'},
        'outdated_packages': {'count': 0, 'recommendation': 'Update outdated packages regularly'}
    }
    
    try:
        # Check if package-lock.json exists for accurate dependency checking
        lock_check = conn.run(f'test -f "{project_path}/package-lock.json" && echo "EXISTS"', hide=True)
        
        if 'EXISTS' in lock_check.stdout:
            # Read package-lock.json for installed packages
            lock_content = conn.run(f'cat "{project_path}/package-lock.json"', hide=True)
            try:
                lock_data = json.loads(lock_content.stdout)
                dependencies = lock_data.get('dependencies', {})
                
                # Check for security packages
                security_checks['helmet_installed']['installed'] = 'helmet' in dependencies
                security_checks['cors_installed']['installed'] = 'cors' in dependencies
                security_checks['bcrypt_installed']['installed'] = any(pkg in dependencies for pkg in ['bcrypt', 'bcryptjs'])
                security_checks['rate_limiting']['installed'] = any(pkg in dependencies for pkg in ['express-rate-limit', 'rate-limiter'])
                security_checks['validator_installed']['installed'] = any(pkg in dependencies for pkg in ['validator', 'joi', 'yup'])
                security_checks['dotenv_installed']['installed'] = 'dotenv' in dependencies
                
            except json.JSONDecodeError:
                pass
        
        # Run npm audit if available
        audit_result = conn.run(f'cd "{project_path}" && npm audit --json 2>/dev/null || echo "AUDIT_FAILED"', hide=True, warn=True)
        if audit_result.ok and 'AUDIT_FAILED' not in audit_result.stdout:
            try:
                audit_data = json.loads(audit_result.stdout)
                vulnerabilities = audit_data.get('metadata', {}).get('vulnerabilities', {})
                total_vulns = sum(vulnerabilities.values()) if isinstance(vulnerabilities, dict) else 0
                security_checks['security_audit']['run'] = True
                security_checks['security_audit']['vulnerabilities'] = total_vulns
            except:
                pass
        
        # Check for outdated packages
        outdated_result = conn.run(f'cd "{project_path}" && npm outdated --json 2>/dev/null || echo "OUTDATED_CHECK_FAILED"', hide=True, warn=True)
        if outdated_result.ok and 'OUTDATED_CHECK_FAILED' not in outdated_result.stdout:
            try:
                outdated_data = json.loads(outdated_result.stdout)
                security_checks['outdated_packages']['count'] = len(outdated_data)
                security_checks['outdated_packages']['packages'] = list(outdated_data.keys())
            except:
                pass
                
    except Exception as e:
        security_checks['error'] = str(e)
    
    return security_checks

def check_nodejs_performance(conn, project_path):
    """
    Check Node.js performance optimizations
    """
    performance_checks = {
        'pm2_config': {'exists': False, 'recommendation': 'Use PM2 for production process management'},
        'compression': {'enabled': False, 'recommendation': 'Enable compression middleware'},
        'caching': {'configured': False, 'recommendation': 'Configure caching strategy'},
        'clustering': {'enabled': False, 'recommendation': 'Use clustering for multi-core utilization'},
        'minification': {'enabled': False, 'recommendation': 'Minify static assets for production'},
        'health_check': {'exists': False, 'recommendation': 'Implement health check endpoints'}
    }
    
    try:
        # Check for PM2 configuration
        pm2_configs = ['ecosystem.config.js', 'pm2.json', 'process.json']
        for config in pm2_configs:
            pm2_check = conn.run(f'test -f "{project_path}/{config}" && echo "EXISTS"', hide=True, warn=True)
            if pm2_check.ok and 'EXISTS' in pm2_check.stdout:
                performance_checks['pm2_config']['exists'] = True
                performance_checks['pm2_config']['file'] = config
                break
        
        # Check for compression middleware in package.json
        if conn.run(f'test -f "{project_path}/package-lock.json"', hide=True).ok:
            compression_check = conn.run(f'grep -i "compression" "{project_path}/package-lock.json"', hide=True, warn=True)
            if compression_check.ok and compression_check.stdout.strip():
                performance_checks['compression']['enabled'] = True
        
        # Check for caching packages
        cache_packages = ['redis', 'memcached', 'node-cache', 'memory-cache']
        for package in cache_packages:
            cache_check = conn.run(f'grep -i "{package}" "{project_path}/package.json"', hide=True, warn=True)
            if cache_check.ok and cache_check.stdout.strip():
                performance_checks['caching']['configured'] = True
                performance_checks['caching']['package'] = package
                break
        
        # Check for clustering in main file
        main_files = ['index.js', 'app.js', 'server.js']
        for main_file in main_files:
            cluster_check = conn.run(f'test -f "{project_path}/{main_file}" && grep -i "cluster" "{project_path}/{main_file}"', hide=True, warn=True)
            if cluster_check.ok and cluster_check.stdout.strip():
                performance_checks['clustering']['enabled'] = True
                break
        
        # Check for health check endpoints
        health_patterns = ['/health', '/status', '/ping', 'health']
        for main_file in main_files:
            if conn.run(f'test -f "{project_path}/{main_file}"', hide=True).ok:
                for pattern in health_patterns:
                    health_check = conn.run(f'grep -i "{pattern}" "{project_path}/{main_file}"', hide=True, warn=True)
                    if health_check.ok and health_check.stdout.strip():
                        performance_checks['health_check']['exists'] = True
                        break
                if performance_checks['health_check']['exists']:
                    break
                    
    except Exception as e:
        performance_checks['error'] = str(e)
    
    return performance_checks

def check_nodejs_permissions(conn, project_path):
    """
    Check Node.js file and directory permissions
    """
    permission_checks = {
        'node_modules_permissions': {'secure': False, 'recommendation': 'Node_modules should not be web accessible'},
        'env_file_permissions': {'secure': False, 'permissions': None, 'recommendation': '.env file should not be world readable'},
        'main_file_permissions': {'executable': False, 'recommendation': 'Main file should have proper permissions'},
        'logs_directory': {'writable': False, 'exists': False, 'recommendation': 'Logs directory should be writable'},
        'uploads_directory': {'secure': False, 'recommendation': 'Uploads directory should have restricted permissions'}
    }
    
    try:
        # Check node_modules permissions
        node_modules_perm = conn.run(f'ls -ld "{project_path}/node_modules"', hide=True, warn=True)
        if node_modules_perm.ok:
            perm_string = node_modules_perm.stdout.strip().split()[0]
            permission_checks['node_modules_permissions']['permissions'] = perm_string
            permission_checks['node_modules_permissions']['secure'] = perm_string[-1] not in ['4', '5', '6', '7']
        
        # Check .env file permissions
        env_perm = conn.run(f'ls -la "{project_path}/.env"', hide=True, warn=True)
        if env_perm.ok:
            perm_string = env_perm.stdout.strip().split()[0]
            permission_checks['env_file_permissions']['permissions'] = perm_string
            permission_checks['env_file_permissions']['secure'] = perm_string[-1] not in ['4', '5', '6', '7']
        
        # Check main file permissions
        main_files = ['index.js', 'app.js', 'server.js']
        for main_file in main_files:
            main_perm = conn.run(f'ls -la "{project_path}/{main_file}"', hide=True, warn=True)
            if main_perm.ok:
                perm_string = main_perm.stdout.strip().split()[0]
                permission_checks['main_file_permissions']['executable'] = 'x' in perm_string[1:4]
                permission_checks['main_file_permissions']['file'] = main_file
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
        
        # Check uploads directory
        upload_dirs = ['uploads', 'public/uploads', 'static/uploads']
        for upload_dir in upload_dirs:
            upload_check = conn.run(f'test -d "{project_path}/{upload_dir}" && echo "EXISTS"', hide=True, warn=True)
            if upload_check.ok and 'EXISTS' in upload_check.stdout:
                upload_perm = conn.run(f'ls -ld "{project_path}/{upload_dir}"', hide=True, warn=True)
                if upload_perm.ok:
                    perm_string = upload_perm.stdout.strip().split()[0]
                    permission_checks['uploads_directory']['secure'] = perm_string[-1] not in ['6', '7']
                    permission_checks['uploads_directory']['directory'] = upload_dir
                break
            
    except Exception as e:
        permission_checks['error'] = str(e)
    
    return permission_checks

def check_nodejs_docker_config(conn, project_path, stack_name=None):
    """
    Check Node.js Docker configuration and security
    """
    docker_checks = {
        'dockerfile_exists': False,
        'docker_compose_exists': False,
        'container_running': False,
        'nodejs_containers': [],
        'security_issues': [],
        'user_config': {'non_root': False, 'recommendation': 'Run container as non-root user'},
        'secrets_management': {'secure': False, 'recommendation': 'Use Docker secrets for sensitive data'},
        'network_config': {'isolated': False, 'recommendation': 'Use custom networks for isolation'},
        'volume_mounts': {'secure': False, 'recommendation': 'Avoid mounting sensitive host directories'},
        'health_check': {'configured': False, 'recommendation': 'Configure health checks in Dockerfile'}
    }
    
    try:
        # Check if Dockerfile exists in project path
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
                    # Check for potentially dangerous mounts
                    dangerous_mounts = ['/:', '/etc:', '/var/run/docker.sock', '/proc:', '/sys:']
                    for mount in dangerous_mounts:
                        if mount in compose_text:
                            docker_checks['security_issues'].append(f'Dangerous volume mount detected: {mount}')
                    docker_checks['volume_mounts']['secure'] = len([m for m in dangerous_mounts if m in compose_text]) == 0
        
        # Check if Docker stack exists and find Node.js containers
        if stack_name:
            logger.info(f"Checking Docker stack: {stack_name}")
            
            # Check if Docker stack exists
            stack_check = conn.run(f'docker stack ls --format "{{{{.Name}}}}" | grep -x {stack_name}', hide=True, warn=True)
            if stack_check.ok and stack_check.stdout.strip():
                docker_checks['container_running'] = True
                logger.info(f"Docker stack '{stack_name}' found")
                
                # Get all services in the stack
                services_result = conn.run(f'docker stack services {stack_name} --format "{{{{.Name}}}}"', hide=True, warn=True)
                if services_result.ok:
                    services = services_result.stdout.strip().split('\n')
                    logger.info(f"Services in stack {stack_name}: {services}")
                    
                    # Find Node.js containers (services starting with 'user_backend')
                    nodejs_services = [svc for svc in services if svc.strip().startswith('user_backend')]
                    docker_checks['nodejs_containers'] = nodejs_services
                    
                    if nodejs_services:
                        logger.info(f"Found Node.js services: {nodejs_services}")
                        
                        # Get container IDs for the Node.js services
                        for service in nodejs_services:
                            try:
                                # Get container ID for the service
                                container_result = conn.run(f'docker service ps {service} --format "{{{{.Name}}}}.{{{{.ID}}}}" --no-trunc | head -1', hide=True, warn=True)
                                if container_result.ok and container_result.stdout.strip():
                                    container_name = container_result.stdout.strip()
                                    logger.info(f"Found container for service {service}: {container_name}")
                                    
                                    # Check security inside the Node.js container
                                    docker_checks = check_nodejs_container_security(conn, service, container_name, docker_checks)
                            except Exception as e:
                                logger.error(f"Error checking service {service}: {e}", exc_info=True)
                    else:
                        logger.info("No Node.js services (user_backend*) found in the stack")
                else:
                    logger.warning(f"Could not list services for stack {stack_name}")
            else:
                logger.info(f"Docker stack '{stack_name}' not found")
        else:
            # Check regular Docker containers if no stack name provided
            container_check = conn.run(f'docker ps --filter "ancestor=node" --format "{{{{.Names}}}}"', hide=True, warn=True)
            if container_check.ok and container_check.stdout.strip():
                docker_checks['container_running'] = True
                docker_checks['container_names'] = container_check.stdout.strip().split('\n')
        
    except Exception as e:
        docker_checks['error'] = str(e)
        logger.error(f"Error in Docker configuration check: {e}", exc_info=True)
    
    return docker_checks

def check_nodejs_container_security(conn, service_name, container_name, docker_checks):
    """
    Check security configurations inside a Node.js container
    """
    try:
        logger.info(f"Checking security inside container: {container_name}")
        
        # Check if we can execute commands in the container
        test_exec = conn.run(f'docker exec {container_name} echo "Container accessible"', hide=True, warn=True)
        if not test_exec.ok:
            logger.warning(f"Cannot execute commands in container {container_name}")
            return docker_checks
        
        # Check if running as root inside container
        user_check = conn.run(f'docker exec {container_name} whoami', hide=True, warn=True)
        if user_check.ok:
            current_user = user_check.stdout.strip()
            if current_user == 'root':
                docker_checks['security_issues'].append(f'Container {container_name} running as root user')
                docker_checks['user_config']['non_root'] = False
            else:
                docker_checks['user_config']['non_root'] = True
                logger.info(f"Container {container_name} running as user: {current_user}")
        
        # Check for Node.js process and package.json
        node_process_check = conn.run(f'docker exec {container_name} ps aux | grep -i node', hide=True, warn=True)
        if node_process_check.ok and 'node' in node_process_check.stdout.lower():
            logger.info(f"Node.js process found in container {container_name}")
            
            # Check if package.json exists
            package_check = conn.run(f'docker exec {container_name} find /app -name "package.json" -type f 2>/dev/null | head -1', hide=True, warn=True)
            if package_check.ok and package_check.stdout.strip():
                package_path = package_check.stdout.strip()
                logger.info(f"Found package.json at: {package_path}")
                
                # Check for security-related packages
                security_packages_check = conn.run(f'docker exec {container_name} cat {package_path} | grep -E "(helmet|cors|bcrypt|express-rate-limit)"', hide=True, warn=True)
                if security_packages_check.ok and security_packages_check.stdout.strip():
                    logger.info(f"Security packages found in {container_name}")
                else:
                    docker_checks['security_issues'].append(f'Container {container_name} missing security packages')
        
        # Check environment variables for sensitive data
        env_check = conn.run(f'docker exec {container_name} env | grep -E "(PASSWORD|SECRET|KEY|TOKEN)" | head -5', hide=True, warn=True)
        if env_check.ok and env_check.stdout.strip():
            env_vars = env_check.stdout.strip().split('\n')
            for env_var in env_vars:
                if any(weak in env_var.lower() for weak in ['password=password', 'secret=secret', 'key=key']):
                    docker_checks['security_issues'].append(f'Container {container_name} has weak environment variables')
                    break
        
        # Check for health check endpoint
        health_check = conn.run(f'docker exec {container_name} curl -f http://localhost:3000/health 2>/dev/null || echo "NO_HEALTH"', hide=True, warn=True)
        if health_check.ok and 'NO_HEALTH' not in health_check.stdout:
            docker_checks['health_check']['configured'] = True
            logger.info(f"Health check endpoint found in container {container_name}")
        
    except Exception as e:
        logger.error(f"Error checking container security for {container_name}: {e}", exc_info=True)
        docker_checks['security_issues'].append(f'Error checking container {container_name}: {str(e)}')
    
    return docker_checks

def check_nodejs_swarm_config(conn, stack_name):
    """
    Check Docker Swarm specific configuration for Node.js stack
    """
    swarm_checks = {
        'stack_deployed': False,
        'services': [],
        'nodejs_services': [],
        'nodejs_containers': [],
        'replicas': {},
        'networks': [],
        'secrets': [],
        'configs': [],
        'security_issues': [],
        'recommendations': []
    }
    
    try:
        logger.info(f"Checking Docker Swarm configuration for stack: {stack_name}")
        
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
                        
                        # Check if it's a Node.js service (contains user_backend)
                        if 'user_backend' in service_name.lower():
                            swarm_checks['nodejs_services'].append(service_name)
                            logger.info(f"Found Node.js service: {service_name}")
            
            # Also check running containers to find Node.js containers
            containers_result = conn.run(f'docker ps | grep {stack_name}', hide=True, warn=True)
            if containers_result.ok and containers_result.stdout.strip():
                container_lines = containers_result.stdout.strip().split('\n')
                nodejs_containers = []
                
                for line in container_lines:
                    # Look for containers with user_backend in the name
                    if 'user_backend' in line.lower():
                        # Extract container name (last column in docker ps output)
                        parts = line.split()
                        if parts:
                            container_name = parts[-1]  # Container name is typically the last column
                            nodejs_containers.append(container_name)
                            logger.info(f"Found Node.js container: {container_name}")
                
                # Store the found containers
                swarm_checks['nodejs_containers'] = nodejs_containers
                
                # If we found containers but no services, containers might be the actual running instances
                if nodejs_containers and not swarm_checks['nodejs_services']:
                    swarm_checks['nodejs_services'] = nodejs_containers
                    logger.info(f"Using containers as Node.js services: {nodejs_containers}")
            else:
                swarm_checks['nodejs_containers'] = []
            
            # Check stack networks
            networks_result = conn.run(f'docker network ls --filter "label=com.docker.stack.namespace={stack_name}" --format "{{{{.Name}}}}"', hide=True, warn=True)
            if networks_result.ok:
                networks = networks_result.stdout.strip().split('\n') if networks_result.stdout.strip() else []
                swarm_checks['networks'] = [net for net in networks if net.strip()]
            
            # Check stack secrets
            secrets_result = conn.run(f'docker secret ls --filter "label=com.docker.stack.namespace={stack_name}" --format "{{{{.Name}}}}"', hide=True, warn=True)
            if secrets_result.ok:
                secrets = secrets_result.stdout.strip().split('\n') if secrets_result.stdout.strip() else []
                swarm_checks['secrets'] = [sec for sec in secrets if sec.strip()]
            
            # Check stack configs
            configs_result = conn.run(f'docker config ls --filter "label=com.docker.stack.namespace={stack_name}" --format "{{{{.Name}}}}"', hide=True, warn=True)
            if configs_result.ok:
                configs = configs_result.stdout.strip().split('\n') if configs_result.stdout.strip() else []
                swarm_checks['configs'] = [conf for conf in configs if conf.strip()]
            
            # Security recommendations for Swarm
            if not swarm_checks['secrets']:
                swarm_checks['recommendations'].append('Consider using Docker secrets for sensitive data')
            
            if not swarm_checks['networks']:
                swarm_checks['recommendations'].append('Use custom networks for service isolation')
            
            # Check for single replica services (potential availability issue)
            for service, replica_info in swarm_checks['replicas'].items():
                if '1/1' in replica_info and service in swarm_checks['nodejs_services']:
                    swarm_checks['recommendations'].append(f'Consider scaling Node.js service {service} for high availability')
            
            # Check service logs for Node.js specific issues
            for service in swarm_checks['nodejs_services']:
                try:
                    log_check = conn.run(f'docker service logs --tail 10 {service} 2>/dev/null | grep -i "error\\|warning\\|deprecated\\|vulnerability"', hide=True, warn=True)
                    if log_check.ok and log_check.stdout.strip():
                        error_lines = log_check.stdout.strip().split('\n')
                        if len(error_lines) > 0:
                            swarm_checks['security_issues'].append(f'Service {service} has {len(error_lines)} error/warning logs')
                            logger.warning(f"Found {len(error_lines)} issues in logs for service {service}")
                except Exception as e:
                    logger.warning(f"Could not check logs for service {service}: {e}")
            
            # Check if Node.js services are properly configured
            if swarm_checks['nodejs_services']:
                logger.info(f"Found {len(swarm_checks['nodejs_services'])} Node.js services in stack")
                
                # Additional checks for Node.js services
                for service in swarm_checks['nodejs_services']:
                    # Check if this is actually a container name (not a service)
                    if service in swarm_checks.get('nodejs_containers', []):
                        # This is a container, perform container-specific checks
                        try:
                            # Check if container is running Node.js
                            node_check = conn.run(f'docker exec {service} node --version 2>/dev/null || echo "NO_NODE"', hide=True, warn=True)
                            if node_check.ok and 'NO_NODE' not in node_check.stdout:
                                node_version = node_check.stdout.strip()
                                logger.info(f"Container {service} running Node.js {node_version}")
                                swarm_checks[f'nodejs_version_{service}'] = node_version
                            
                            # Check for package.json and security packages
                            package_check = conn.run(f'docker exec {service} find /app -name "package.json" -type f 2>/dev/null | head -1', hide=True, warn=True)
                            if package_check.ok and package_check.stdout.strip():
                                package_path = package_check.stdout.strip()
                                
                                # Check for security packages
                                security_check = conn.run(f'docker exec {service} cat {package_path} | grep -E "(helmet|cors|bcrypt|express-rate-limit)"', hide=True, warn=True)
                                if not security_check.ok or not security_check.stdout.strip():
                                    swarm_checks['security_issues'].append(f'Container {service} missing security packages (helmet, cors, bcrypt, rate-limiting)')
                                
                                # Check for npm audit
                                audit_check = conn.run(f'docker exec {service} npm audit --json 2>/dev/null || echo "AUDIT_FAILED"', hide=True, warn=True)
                                if audit_check.ok and 'AUDIT_FAILED' not in audit_check.stdout:
                                    try:
                                        import json
                                        audit_data = json.loads(audit_check.stdout)
                                        vulnerabilities = audit_data.get('metadata', {}).get('vulnerabilities', {})
                                        if isinstance(vulnerabilities, dict):
                                            total_vulns = sum(vulnerabilities.values())
                                            if total_vulns > 0:
                                                swarm_checks['security_issues'].append(f'Container {service} has {total_vulns} npm security vulnerabilities')
                                    except:
                                        pass
                            
                            # Check if running as root
                            user_check = conn.run(f'docker exec {service} whoami 2>/dev/null || echo "UNKNOWN"', hide=True, warn=True)
                            if user_check.ok and 'root' in user_check.stdout.strip():
                                swarm_checks['security_issues'].append(f'Container {service} running as root user')
                                
                        except Exception as e:
                            logger.warning(f"Could not inspect container {service}: {e}")
                    else:
                        # This is a service, check service constraints and placement
                        service_inspect = conn.run(f'docker service inspect {service} --format "{{{{json .Spec.TaskTemplate.Placement}}}}" 2>/dev/null', hide=True, warn=True)
                        if service_inspect.ok and service_inspect.stdout.strip():
                            try:
                                import json
                                placement_info = json.loads(service_inspect.stdout.strip())
                                if not placement_info.get('Constraints'):
                                    swarm_checks['recommendations'].append(f'Consider adding placement constraints for service {service}')
                            except:
                                pass
            else:
                swarm_checks['recommendations'].append(f'No Node.js services (user_backend*) found in stack {stack_name}')
                logger.info(f"No Node.js services found in stack {stack_name}")
        
        else:
            swarm_checks['stack_deployed'] = False
            swarm_checks['error'] = f'Stack {stack_name} not found'
            logger.info(f"Stack {stack_name} not found")
    
    except Exception as e:
        swarm_checks['error'] = str(e)
        logger.error(f"Error checking Swarm configuration: {e}", exc_info=True)
    
    return swarm_checks

def generate_nodejs_security_summary(results):
    """
    Generate security summary with critical issues, warnings, and recommendations
    """
    summary = {
        'critical_issues': [],
        'warnings': [],
        'recommendations': []
    }
    
    if not results['nodejs_found']:
        return summary
    
    env_checks = results.get('env_file_checks', {})
    package_checks = results.get('package_checks', {})
    security_packages = results.get('security_packages', {})
    performance_checks = results.get('performance_checks', {})
    permission_checks = results.get('permission_checks', {})
    docker_config = results.get('docker_config', {})
    swarm_config = results.get('swarm_config', {})
    
    # Critical issues
    if not env_checks.get('env_file_exists', False):
        summary['critical_issues'].append('.env file not found - environment variables not configured')
    
    if env_checks.get('node_env', {}).get('value') != 'production':
        summary['critical_issues'].append('NODE_ENV is not set to production - debug mode may be enabled')
    
    if not env_checks.get('database_config', {}).get('complete', False):
        summary['critical_issues'].append('MySQL database configuration incomplete - missing required fields')
    
    if not env_checks.get('database_config', {}).get('secure', False):
        summary['critical_issues'].append('MySQL database password is weak or using default values')
    
    if env_checks.get('demo_status', {}).get('value') != 'NO':
        summary['critical_issues'].append('DEMO_STATUS is not set to NO - system may be in demo mode')
    
    if not env_checks.get('token_security', {}).get('secure', False):
        summary['critical_issues'].append('Token keys are weak or too short - authentication security compromised')
    
    if not permission_checks.get('env_file_permissions', {}).get('secure', False):
        summary['critical_issues'].append('.env file has insecure permissions - sensitive data may be exposed')
    
    if security_packages.get('security_audit', {}).get('vulnerabilities', 0) > 0:
        vuln_count = security_packages['security_audit']['vulnerabilities']
        summary['critical_issues'].append(f'Found {vuln_count} security vulnerabilities in dependencies')
    
    # Docker-specific critical issues
    if docker_config.get('security_issues'):
        for issue in docker_config['security_issues']:
            summary['critical_issues'].append(f'Docker security issue: {issue}')
    
    if not docker_config.get('user_config', {}).get('non_root', True):
        summary['critical_issues'].append('Docker container running as root user')
    
    # Warnings
    if not env_checks.get('url_security', {}).get('secure', False):
        ip_based_urls = env_checks.get('url_security', {}).get('ip_based_urls', [])
        if ip_based_urls:
            summary['warnings'].append(f'IP-based URLs detected (should use domain with HTTPS): {", ".join(ip_based_urls)}')
    
    if not env_checks.get('mail_config', {}).get('complete', False):
        summary['warnings'].append('Mail configuration is incomplete - email functionality may not work')
    
    if not env_checks.get('payment_config', {}).get('secure', False):
        summary['warnings'].append('Payment gateway configuration may be incomplete')
    
    if not env_checks.get('prefix_config', {}).get('configured', False):
        summary['warnings'].append('PREFIX is not configured properly')
    
    if not security_packages.get('helmet_installed', {}).get('installed', False):
        summary['warnings'].append('Helmet security middleware not installed')
    
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
    if not security_packages.get('cors_installed', {}).get('installed', False):
        summary['recommendations'].append('Install CORS middleware: npm install cors')
    
    if not security_packages.get('bcrypt_installed', {}).get('installed', False):
        summary['recommendations'].append('Install bcrypt for password hashing: npm install bcrypt')
    
    if not security_packages.get('rate_limiting', {}).get('installed', False):
        summary['recommendations'].append('Install rate limiting: npm install express-rate-limit')
    
    if not performance_checks.get('pm2_config', {}).get('exists', False):
        summary['recommendations'].append('Configure PM2 for production process management')
    
    if not performance_checks.get('compression', {}).get('enabled', False):
        summary['recommendations'].append('Enable compression middleware: npm install compression')
    
    if not performance_checks.get('health_check', {}).get('exists', False):
        summary['recommendations'].append('Implement health check endpoints for monitoring')
    
    # Custom recommendations based on .env analysis
    if not env_checks.get('url_security', {}).get('secure', False):
        summary['recommendations'].append('Replace IP-based URLs with domain names using HTTPS protocol')
    
    if env_checks.get('node_env', {}).get('value') != 'production':
        summary['recommendations'].append('Set NODE_ENV=production for production deployment')
    
    if not env_checks.get('database_config', {}).get('secure', False):
        summary['recommendations'].append('Use strong MySQL passwords and avoid default credentials')
    
    if not env_checks.get('token_security', {}).get('secure', False):
        summary['recommendations'].append('Generate strong, unique token keys (minimum 32 characters)')
    
    if env_checks.get('demo_status', {}).get('value') != 'NO':
        summary['recommendations'].append('Set DEMO_STATUS=NO for production environment')
    
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

def get_nodejs_optimization_commands(conn, project_path):
    """
    Get list of Node.js optimization commands
    """
    optimization_commands = [
        'npm audit fix',
        'npm update',
        'npm install --production',
        'npm prune',
        'pm2 start ecosystem.config.js'
    ]
    
    try:
        # Check if npm is available
        npm_check = conn.run('which npm', hide=True, warn=True)
        
        if npm_check.ok:
            return {
                'npm_available': True,
                'optimization_commands': optimization_commands,
                'security_commands': [
                    'npm audit',
                    'npm audit fix',
                    'npm outdated',
                    'npm update'
                ],
                'recommended_sequence': [
                    '1. npm audit (check for vulnerabilities)',
                    '2. npm audit fix (fix vulnerabilities)',
                    '3. npm update (update packages)',
                    '4. npm install --production (production install)',
                    '5. pm2 start ecosystem.config.js (start with PM2)'
                ]
            }
        else:
            return {
                'npm_available': False,
                'error': 'npm command not found'
            }
            
    except Exception as e:
        return {'error': str(e)}