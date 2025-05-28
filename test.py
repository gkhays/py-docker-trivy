import os
import json
import docker
from docker.errors import DockerException

def main():
    image_name = 'aquasec/trivy'

    client = docker.from_env()
    print(f"Pulling Docker image: {image_name}")
    client.images.pull(image_name)
    print(f"Image {image_name} pulled successfully.")

    # Create a volume for the SBOM file
    scan_dir = os.path.abspath('scans')
    os.makedirs(scan_dir, exist_ok=True)
    print(f"Using scan directory at: {scan_dir}")
    print(f"Mounting host directory {scan_dir} to container path /mnt/scans")
    
    volumes = {
        scan_dir: {
            'bind': '/mnt/scans', 
            'mode': 'rw'
        }
    }
    
    command = f"sbom /mnt/scans/sbom.json --format json --output /mnt/scans/scan.json"
    container = client.containers.run(
        image=image_name, 
        command=command, 
        volumes=volumes, 
        detach=True
    )

    container.start()
    print(f"Container {container.id} started with command: {command}")

    result = container.wait()
    print(f"Container {container.id} finished with exit code: {result['StatusCode']}")
    if result['StatusCode'] == 0:
        print("✅ Container executed successfully.")
        logs = container.logs(stdout=True, stderr=True)
        print(logs.decode('utf-8'))
    else:
        print("❌ Container execution failed.")
        logs = container.logs(stdout=True, stderr=True)
        print(logs.decode('utf-8'))

    # container.remove()

if __name__ == "__main__":
    main()
