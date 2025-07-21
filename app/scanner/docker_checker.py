def check_docker_security(conn):
    issues = []
    result = conn.run("docker ps --format '{{.ID}}: {{.Image}}'", hide=True, warn=True)
    for line in result.stdout.strip().split('\n'):
        if line:
            container_id, image = line.split(": ", 1)
            inspect = conn.run(f"docker inspect {container_id}", hide=True, warn=True)
            if '"Privileged": true' in inspect.stdout:
                issues.append(f"{container_id} ({image}) is running in privileged mode")
    return issues