import re
from utils.logger import logger

def check_laravel_security(conn, project_path):
    """
    Check Laravel-specific security configurations
    """
    results = {
        'laravel_found': False,
        'env_file_checks': {},
        'cache_checks': {},
        'permission_checks': {},
        'security_summary': {
            'critical_issues': [],
            'warnings': [],
            'recommendations': []
        }
    }
    
    try:
        # Check if Laravel project exists
        laravel_check = conn.run(f'test -f "{project_path}/artisan" && echo "FOUND" || echo "NOT_FOUND"', hide=True)
        
        if 'FOUND' in laravel_check.stdout:
            results['laravel_found'] = True
            logger.info(f"Laravel project found at {project_path}")
            
            # Check .env file
            results['env_file_checks'] = check_laravel_env_file(conn, project_path)
            
            # Check cache status
            results['cache_checks'] = check_laravel_cache_status(conn, project_path)
            
            # Check file permissions
            results['permission_checks'] = check_laravel_permissions(conn, project_path)
            
            # Generate security summary
            results['security_summary'] = generate_laravel_security_summary(results)
            
        else:
            results['laravel_found'] = False
            logger.info(f"No Laravel project found at {project_path}")
            
    except Exception as e:
        results['error'] = str(e)
        logger.error(f"Error checking Laravel security: {e}", exc_info=True)
    
    return results

def check_laravel_env_file(conn, project_path):
    """
    Check Laravel .env file configurations
    """
    env_checks = {
        'env_file_exists': False,
        'app_debug': {'value': None, 'secure': False, 'recommendation': 'Set APP_DEBUG=false in production'},
        'app_env': {'value': None, 'secure': False, 'recommendation': 'Set APP_ENV=production for production environment'},
        'app_key': {'exists': False, 'secure': False, 'recommendation': 'Ensure APP_KEY is set and unique'},
        'app_url': {'value': None, 'secure': False, 'recommendation': 'Use HTTPS domain instead of IP address'},
        'database_config': {'complete': False, 'secure': False, 'recommendation': 'Ensure database configuration is complete and secure'},
        'db_prefix': {'exists': False, 'recommendation': 'Add DB_PREFIX for security'},
        'mlm_config': {'complete': False, 'secure': False, 'recommendation': 'Configure MLM-specific settings properly'},
        'url_security': {'secure': False, 'ip_based_urls': [], 'recommendation': 'Use HTTPS domains instead of IP addresses'},
        'demo_status': {'value': None, 'secure': False, 'recommendation': 'Set DEMO_STATUS=no for production'},
        'mail_config': {'complete': False, 'secure': False, 'recommendation': 'Configure mail settings securely'},
        'payment_config': {'secure': False, 'recommendation': 'Secure payment gateway configuration'},
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
            
            # Track database configuration
            db_fields = {'DB_CONNECTION': None, 'DB_HOST': None, 'DB_PORT': None, 'DB_DATABASE': None, 'DB_USERNAME': None, 'DB_PASSWORD': None}
            mlm_urls = {'COMMISSION_URI': None, 'USER_REPLICA_URI': None, 'USER_LCP_URL': None, 'USER_URL': None, 'ECOM_URI': None}
            mail_fields = {'MAIL_HOST': None, 'MAIL_USERNAME': None, 'MAIL_PASSWORD': None}
            
            for line in env_lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"\'')
                    
                    # Check APP_DEBUG
                    if key == 'APP_DEBUG':
                        env_checks['app_debug']['value'] = value
                        env_checks['app_debug']['secure'] = value.lower() in ['false', '0', 'no']
                    
                    # Check APP_ENV
                    elif key == 'APP_ENV':
                        env_checks['app_env']['value'] = value
                        env_checks['app_env']['secure'] = value.lower() == 'production'
                    
                    # Check APP_KEY
                    elif key == 'APP_KEY':
                        env_checks['app_key']['exists'] = bool(value)
                        env_checks['app_key']['secure'] = len(value) > 20 and not value in ['base64:your-key-here', '']
                    
                    # Check APP_URL
                    elif key == 'APP_URL':
                        env_checks['app_url']['value'] = value
                        if value and ('192.168.' in value or '127.0.0.1' in value or '10.' in value or 'localhost' in value):
                            env_checks['url_security']['ip_based_urls'].append(f"{key}={value}")
                        env_checks['app_url']['secure'] = 'https://' in value and not any(ip in value for ip in ['192.168.', '127.0.0.1', '10.', 'localhost'])
                    
                    # Check database fields
                    elif key in db_fields:
                        db_fields[key] = value
                    
                    # Check DB_PREFIX
                    elif key == 'DB_PREFIX':
                        env_checks['db_prefix']['exists'] = bool(value)
                    
                    # Check DEMO_STATUS
                    elif key == 'DEMO_STATUS':
                        env_checks['demo_status']['value'] = value
                        env_checks['demo_status']['secure'] = value.lower() == 'no'
                    
                    # Check MLM-specific URLs
                    elif key in mlm_urls:
                        mlm_urls[key] = value
                        if value and ('192.168.' in value or '127.0.0.1' in value or '10.' in value or 'localhost' in value):
                            env_checks['url_security']['ip_based_urls'].append(f"{key}={value}")
                    
                    # Check mail configuration
                    elif key in mail_fields:
                        mail_fields[key] = value
                    
                    # Check payment configuration
                    elif any(payment_key in key.upper() for payment_key in ['PAYPAL', 'STRIPE', 'GOOGLE_CLIENT']):
                        env_checks['payment_config']['secure'] = True
            
            # Validate database configuration
            env_checks['database_config']['complete'] = all(db_fields.values())
            # Check database password strength
            db_password = db_fields.get('DB_PASSWORD', '')
            if db_password:
                # Consider password weak if it's too short or contains common patterns
                weak_patterns = ['password', '123456', 'admin', 'root', 'pass']
                is_weak = len(db_password) < 8 or any(weak in db_password.lower() for weak in weak_patterns)
                env_checks['database_config']['secure'] = not is_weak
            else:
                env_checks['database_config']['secure'] = False
            
            # Validate MLM configuration completeness
            required_mlm_urls = ['COMMISSION_URI', 'USER_REPLICA_URI', 'USER_LCP_URL', 'USER_URL']
            mlm_complete = all(mlm_urls.get(url) for url in required_mlm_urls)
            env_checks['mlm_config']['complete'] = mlm_complete
            env_checks['mlm_config']['secure'] = mlm_complete and len(env_checks['url_security']['ip_based_urls']) == 0
            
            # Validate mail configuration
            env_checks['mail_config']['complete'] = all(mail_fields.values())
            # Check for potentially exposed mail credentials
            mail_user = mail_fields.get('MAIL_USERNAME', '')
            mail_pass = mail_fields.get('MAIL_PASSWORD', '')
            env_checks['mail_config']['secure'] = bool(mail_user and mail_pass and len(mail_pass) > 8)
            
            # Check URL security overall
            env_checks['url_security']['secure'] = len(env_checks['url_security']['ip_based_urls']) == 0
            
            # Custom security checks
            env_checks['custom_checks'] = {
                'app_debug_disabled': env_checks['app_debug']['secure'],
                'database_complete': env_checks['database_config']['complete'],
                'database_secure': env_checks['database_config']['secure'],
                'db_prefix_configured': env_checks['db_prefix']['exists'],
                'demo_status_production': env_checks['demo_status']['secure'],
                'mlm_urls_configured': env_checks['mlm_config']['complete'],
                'urls_domain_based': env_checks['url_security']['secure'],
                'mail_configured': env_checks['mail_config']['complete']
            }
        
        else:
            env_checks['env_file_exists'] = False
            
    except Exception as e:
        env_checks['error'] = str(e)
    
    return env_checks

def check_laravel_cache_status(conn, project_path):
    """
    Check Laravel cache configurations and status
    """
    cache_checks = {
        'view_cache': {'cached': False, 'recommendation': 'Run php artisan view:cache for better performance'},
        'config_cache': {'cached': False, 'recommendation': 'Run php artisan config:cache for better performance'},
        'route_cache': {'cached': False, 'recommendation': 'Run php artisan route:cache for better performance'},
        'composer_optimized': {'optimized': False, 'recommendation': 'Run composer install --optimize-autoloader --no-dev'},
        'storage_permissions': {'writable': False, 'recommendation': 'Ensure storage directory is writable'}
    }
    
    try:
        # Check if view cache exists
        view_cache_check = conn.run(f'test -d "{project_path}/storage/framework/views" && find "{project_path}/storage/framework/views" -name "*.php" | head -1', hide=True, warn=True)
        if view_cache_check.ok and view_cache_check.stdout.strip():
            cache_checks['view_cache']['cached'] = True
        
        # Check if config cache exists
        config_cache_check = conn.run(f'test -f "{project_path}/bootstrap/cache/config.php" && echo "EXISTS"', hide=True, warn=True)
        if config_cache_check.ok and 'EXISTS' in config_cache_check.stdout:
            cache_checks['config_cache']['cached'] = True
        
        # Check if route cache exists
        route_cache_check = conn.run(f'test -f "{project_path}/bootstrap/cache/routes.php" && echo "EXISTS"', hide=True, warn=True)
        if route_cache_check.ok and 'EXISTS' in route_cache_check.stdout:
            cache_checks['route_cache']['cached'] = True
        
        # Check composer optimization
        composer_check = conn.run(f'test -f "{project_path}/vendor/composer/autoload_classmap.php" && wc -l "{project_path}/vendor/composer/autoload_classmap.php"', hide=True, warn=True)
        if composer_check.ok and composer_check.stdout.strip():
            line_count = int(composer_check.stdout.strip().split()[0])
            cache_checks['composer_optimized']['optimized'] = line_count > 100  # Basic check
        
        # Check storage permissions
        storage_check = conn.run(f'test -w "{project_path}/storage" && echo "WRITABLE"', hide=True, warn=True)
        if storage_check.ok and 'WRITABLE' in storage_check.stdout:
            cache_checks['storage_permissions']['writable'] = True
            
    except Exception as e:
        cache_checks['error'] = str(e)
    
    return cache_checks

def check_laravel_permissions(conn, project_path):
    """
    Check Laravel file and directory permissions
    """
    permission_checks = {
        'storage_writable': False,
        'bootstrap_cache_writable': False,
        'env_file_permissions': {'secure': False, 'permissions': None},
        'vendor_permissions': {'secure': True, 'recommendation': 'Vendor directory should not be web accessible'},
        'artisan_permissions': {'executable': False, 'recommendation': 'Artisan should be executable by owner only'}
    }
    
    try:
        # Check storage directory permissions
        storage_perm = conn.run(f'ls -ld "{project_path}/storage"', hide=True, warn=True)
        if storage_perm.ok:
            perm_string = storage_perm.stdout.strip().split()[0]
            permission_checks['storage_writable'] = 'w' in perm_string[2:5]  # Check owner write permission
        
        # Check bootstrap/cache permissions
        bootstrap_cache_perm = conn.run(f'ls -ld "{project_path}/bootstrap/cache"', hide=True, warn=True)
        if bootstrap_cache_perm.ok:
            perm_string = bootstrap_cache_perm.stdout.strip().split()[0]
            permission_checks['bootstrap_cache_writable'] = 'w' in perm_string[2:5]
        
        # Check .env file permissions
        env_perm = conn.run(f'ls -la "{project_path}/.env"', hide=True, warn=True)
        if env_perm.ok:
            perm_string = env_perm.stdout.strip().split()[0]
            permission_checks['env_file_permissions']['permissions'] = perm_string
            # .env should not be world readable
            permission_checks['env_file_permissions']['secure'] = perm_string[-1] not in ['4', '5', '6', '7']
        
        # Check artisan permissions
        artisan_perm = conn.run(f'ls -la "{project_path}/artisan"', hide=True, warn=True)
        if artisan_perm.ok:
            perm_string = artisan_perm.stdout.strip().split()[0]
            permission_checks['artisan_permissions']['executable'] = 'x' in perm_string[1:4]  # Owner execute
            
    except Exception as e:
        permission_checks['error'] = str(e)
    
    return permission_checks

def generate_laravel_security_summary(results):
    """
    Generate security summary with critical issues, warnings, and recommendations
    """
    summary = {
        'critical_issues': [],
        'warnings': [],
        'recommendations': []
    }
    
    if not results['laravel_found']:
        return summary
    
    env_checks = results.get('env_file_checks', {})
    cache_checks = results.get('cache_checks', {})
    permission_checks = results.get('permission_checks', {})
    
    # Critical issues
    if not env_checks.get('env_file_exists', False):
        summary['critical_issues'].append('.env file not found - application may not work properly')
    
    if env_checks.get('app_debug', {}).get('value') and not env_checks['app_debug']['secure']:
        summary['critical_issues'].append('APP_DEBUG=true - this exposes sensitive information in production')
    
    if not env_checks.get('app_key', {}).get('secure', False):
        summary['critical_issues'].append('APP_KEY is missing or insecure - encryption and sessions are compromised')
    
    if not env_checks.get('database_config', {}).get('complete', False):
        summary['critical_issues'].append('Database configuration is incomplete')
    
    if not env_checks.get('database_config', {}).get('secure', False):
        summary['critical_issues'].append('Database password is weak or uses default values')
    
    if not permission_checks.get('env_file_permissions', {}).get('secure', False):
        summary['critical_issues'].append('.env file has insecure permissions - sensitive data may be exposed')
    
    # Warnings
    if env_checks.get('app_env', {}).get('value') != 'production':
        summary['warnings'].append('APP_ENV is not set to production')
    
    if not env_checks.get('db_prefix', {}).get('exists', False):
        summary['warnings'].append('DB_PREFIX is not configured - database tables lack security prefix')
    
    if not env_checks.get('demo_status', {}).get('secure', False):
        summary['warnings'].append('DEMO_STATUS is not set to "no" for production environment')
    
    if not env_checks.get('url_security', {}).get('secure', False):
        ip_based_urls = env_checks.get('url_security', {}).get('ip_based_urls', [])
        if ip_based_urls:
            summary['warnings'].append(f'IP-based URLs detected (should use HTTPS domains): {", ".join(ip_based_urls)}')
    
    if not env_checks.get('mlm_config', {}).get('complete', False):
        summary['warnings'].append('MLM configuration incomplete - missing required URLs (COMMISSION_URI, USER_REPLICA_URI, USER_LCP_URL, USER_URL)')
    
    if not env_checks.get('mail_config', {}).get('secure', False):
        summary['warnings'].append('Mail configuration may be incomplete or insecure')
    
    if not permission_checks.get('storage_writable', False):
        summary['warnings'].append('Storage directory may not be writable')
    
    # Recommendations
    if not cache_checks.get('view_cache', {}).get('cached', False):
        summary['recommendations'].append('Enable view caching: php artisan view:cache')
    
    if not cache_checks.get('config_cache', {}).get('cached', False):
        summary['recommendations'].append('Enable config caching: php artisan config:cache')
    
    if not cache_checks.get('route_cache', {}).get('cached', False):
        summary['recommendations'].append('Enable route caching: php artisan route:cache')
    
    if not cache_checks.get('composer_optimized', {}).get('optimized', False):
        summary['recommendations'].append('Optimize Composer autoloader: composer install --optimize-autoloader --no-dev')
    
    # Custom recommendations based on .env analysis
    if env_checks.get('app_debug', {}).get('value') != 'false':
        summary['recommendations'].append('Set APP_DEBUG=false for production environment')
    
    if env_checks.get('app_env', {}).get('value') != 'production':
        summary['recommendations'].append('Set APP_ENV=production for production deployment')
    
    if not env_checks.get('db_prefix', {}).get('exists', False):
        summary['recommendations'].append('Add DB_PREFIX to secure database table names')
    
    if not env_checks.get('url_security', {}).get('secure', False):
        summary['recommendations'].append('Replace IP-based URLs with HTTPS domain names')
    
    if not env_checks.get('database_config', {}).get('secure', False):
        summary['recommendations'].append('Use strong database password and avoid default credentials')
    
    if env_checks.get('demo_status', {}).get('value') != 'no':
        summary['recommendations'].append('Set DEMO_STATUS=no for production environment')
    
    if not env_checks.get('mlm_config', {}).get('complete', False):
        summary['recommendations'].append('Configure all required MLM URLs: COMMISSION_URI, USER_REPLICA_URI, USER_LCP_URL, USER_URL, ECOM_URI')
    
    return summary

def get_laravel_artisan_commands(conn, project_path):
    """
    Get list of available artisan commands for Laravel optimization
    """
    optimization_commands = [
        'php artisan config:cache',
        'php artisan route:cache',
        'php artisan view:cache',
        'composer install --optimize-autoloader --no-dev',
        'php artisan storage:link'
    ]
    
    try:
        # Check if artisan exists and is executable
        artisan_check = conn.run(f'test -x "{project_path}/artisan" && echo "EXECUTABLE"', hide=True, warn=True)
        
        if artisan_check.ok and 'EXECUTABLE' in artisan_check.stdout:
            return {
                'artisan_available': True,
                'optimization_commands': optimization_commands,
                'recommended_sequence': [
                    '1. php artisan config:cache',
                    '2. php artisan route:cache', 
                    '3. php artisan view:cache',
                    '4. composer install --optimize-autoloader --no-dev'
                ]
            }
        else:
            return {
                'artisan_available': False,
                'error': 'Artisan command not found or not executable'
            }
            
    except Exception as e:
        return {'error': str(e)}
