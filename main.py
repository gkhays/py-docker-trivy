import os
import json
import docker
import logging
from docker.errors import DockerException

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
LOGGER = logging.getLogger("trivy_docker")

def check_docker_running():
    try:
        client = docker.from_env()
        client.ping()
        print("✅ Docker is running.")

        client.version()
        print("Docker version:", client.version()['Version'])
    except DockerException as e:
        print("❌ Docker is not running or cannot be reached.")
        print(f"Error: {e}")

def load_sbom(file_path):
    try:
        with open(file_path, 'r') as file:
            json.load(file)
            sbom_data = json.load(file)
        print(f"✅ SBOM loaded from {file_path}.")
        return sbom_data
    except FileNotFoundError:
        print(f"❌ SBOM file not found: {file_path}")
    except Exception as e:
        print(f"❌ Error loading SBOM: {e}")

def start_container(image_name='aquasec/trivy'):
    try:
        client = docker.from_env()
        client.images.pull(image_name)
        LOGGER.info(f"Image {image_name} pulled successfully.")

        # Create a volume for the SBOM file
        scan_dir = os.path.abspath('scans')
        os.makedirs(scan_dir, exist_ok=True)
        LOGGER.info(f"Mounting host directory {scan_dir} to container path /mnt/scans")
        
        volumes = {
            scan_dir: {
                'bind': '/mnt/scans', 
                'mode': 'rw'
            }
        }
        
        command = f"sbom /mnt/scans/sbom.json --format json --output /mnt/scans/scan.json --quiet"
        container = client.containers.create(
            image=image_name, 
            command=command, 
            volumes=volumes, 
            detach=True
        )

        container.start()
        LOGGER.info(f"Container {container.id} started with command: {command}")        

        result = container.wait()

        if result['StatusCode'] == 0:
            print("✅ Container executed successfully.")
            # logs = container.logs(stdout=True, stderr=True)
            # print(logs.decode('utf-8'))
            # for line in logs.decode('utf-8').splitlines():
            #     print(line)
            for line in container.logs(stream=True):
                LOGGER.info(line.decode('utf-8').strip())
        else:
            print(f"❌ Container execution failed with status code {result['StatusCode']}.")
            logs = container.logs(stdout=True, stderr=True)
            print(logs.decode('utf-8'))

        container.remove()
    except DockerException as e:
        print(f"❌ Failed to start container from image {image_name}.")
        print(f"Error: {e}")

def main():
    LOGGER.info(f"Starting py-docker-trivy!")
    check_docker_running()
    start_container()

if __name__ == "__main__":
    main()
