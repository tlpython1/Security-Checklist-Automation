def check_sensitive_files(conn):
    files = [".env", "config.php", "settings.py"]
    results = []
    for file in files:
        result = conn.run(f'test -f {file} && echo FOUND || echo NOT FOUND', hide=True)
        if 'FOUND' in result.stdout:
            results.append(file)
    return results