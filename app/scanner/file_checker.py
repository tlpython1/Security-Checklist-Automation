def check_sensitive_files(conn, project_path="."):
    files = [".env", "config.php", "settings.py"]
    results = []
    for file in files:
        result = conn.run(f'find "{project_path}" -name "{file}" -type f 2>/dev/null', hide=True)
        if result.stdout.strip():
            paths = result.stdout.strip().split('\n')
            for path in paths:
                if path:  # Skip empty lines
                    file_info = {
                        'filename': file,
                        'full_path': path,
                        'permissions': check_file_permissions(conn, path),
                        'public_accessible': check_public_accessibility(conn, path, project_path),
                        'security_status': 'unknown'
                    }
                    
                    # Determine security status
                    file_info['security_status'] = determine_security_status(file_info)
                    results.append(file_info)
    return results

def check_file_permissions(conn, file_path):
    """Check file permissions and ownership"""
    try:
        # Get detailed file permissions
        result = conn.run(f'ls -la "{file_path}"', hide=True)
        perm_info = result.stdout.strip()
        
        # Get octal permissions
        octal_result = conn.run(f'stat -c "%a" "{file_path}"', hide=True)
        octal_perms = octal_result.stdout.strip()
        
        return {
            'detailed': perm_info,
            'octal': octal_perms,
            'world_readable': octal_perms[-1] in ['4', '5', '6', '7'] if len(octal_perms) >= 3 else False,
            'world_writable': octal_perms[-1] in ['2', '3', '6', '7'] if len(octal_perms) >= 3 else False
        }
    except Exception as e:
        return {'error': str(e)}

def check_public_accessibility(conn, file_path, project_path):
    """Check if file is publicly accessible via web server"""
    try:
        # Check if file is in web-accessible directory
        web_dirs = ['/var/www', '/usr/share/nginx', '/home/*/public_html', '/var/www/html']
        is_in_webdir = any(file_path.startswith(web_dir.replace('*', '')) for web_dir in web_dirs)
        
        # Check nginx/apache configuration for this path
        nginx_config = check_web_server_config(conn, file_path)
        
        # Check if there's a .htaccess or nginx rule protecting this file
        protection_rules = check_protection_rules(conn, file_path)
        
        return {
            'in_web_directory': is_in_webdir,
            'web_server_config': nginx_config,
            'protection_rules': protection_rules,
            'potentially_public': is_in_webdir and not protection_rules['protected']
        }
    except Exception as e:
        return {'error': str(e)}

def check_web_server_config(conn, file_path):
    """Check web server configuration for file access"""
    try:
        config_info = {'nginx': False, 'apache': False, 'rules': []}
        
        # Check nginx configuration
        nginx_check = conn.run('which nginx', hide=True, warn=True)
        if nginx_check.ok:
            config_info['nginx'] = True
            # Check nginx config files for deny rules
            nginx_rules = conn.run(
                f'grep -r "location.*{file_path.split("/")[-1]}" /etc/nginx/ 2>/dev/null || echo "No specific rules"',
                hide=True, warn=True
            )
            config_info['rules'].append(f"Nginx: {nginx_rules.stdout.strip()}")
        
        # Check apache configuration
        apache_check = conn.run('which apache2 || which httpd', hide=True, warn=True)
        if apache_check.ok:
            config_info['apache'] = True
            
        return config_info
    except:
        return {'error': 'Could not check web server config'}

def check_protection_rules(conn, file_path):
    """Check for protection rules like .htaccess"""
    try:
        file_dir = '/'.join(file_path.split('/')[:-1])
        protection_info = {'protected': False, 'rules': []}
        
        # Check for .htaccess in same directory
        htaccess_check = conn.run(f'test -f "{file_dir}/.htaccess" && cat "{file_dir}/.htaccess"', hide=True, warn=True)
        if htaccess_check.ok and htaccess_check.stdout.strip():
            protection_info['rules'].append(f".htaccess found: {htaccess_check.stdout.strip()}")
            # Check if it denies access to this file type
            if any(keyword in htaccess_check.stdout.lower() for keyword in ['deny', 'forbid', file_path.split('.')[-1]]):
                protection_info['protected'] = True
        
        # Check for nginx .conf files
        nginx_local = conn.run(f'find "{file_dir}" -name "*.conf" -exec grep -l "deny\\|forbidden" {{}} \\;', hide=True, warn=True)
        if nginx_local.ok and nginx_local.stdout.strip():
            protection_info['rules'].append(f"Local config files: {nginx_local.stdout.strip()}")
            protection_info['protected'] = True
            
        return protection_info
    except:
        return {'protected': False, 'error': 'Could not check protection rules'}

def determine_security_status(file_info):
    """Determine overall security status of the file"""
    if 'error' in file_info['permissions'] or 'error' in file_info['public_accessible']:
        return 'error'
    
    # Check for critical security issues
    issues = []
    
    # Check permissions
    if file_info['permissions'].get('world_readable', False):
        issues.append('world_readable')
    if file_info['permissions'].get('world_writable', False):
        issues.append('world_writable')
    
    # Check public accessibility
    if file_info['public_accessible'].get('potentially_public', False):
        issues.append('potentially_public')
    
    if not issues:
        return 'secure'
    elif 'world_writable' in issues or 'potentially_public' in issues:
        return 'critical'
    else:
        return 'warning'