import os
import json
import docker
import logging
import argparse
import time
import sys
from docker.errors import DockerException

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
LOGGER = logging.getLogger("trivy_docker")

def check_docker_running() -> bool:
    try:
        client = docker.from_env()
        client.ping()
        print("✅ Docker is running.")

        client.version()
        print("Docker version:", client.version()['Version'])
        return True
    except DockerException as e:
        print("❌ Docker is not running or cannot be reached.")
        print(f"Error: {e}")
        return False

def load_sbom(file_path):
    """
    Load an SBOM (Software Bill of Materials) from a JSON file.

    :param file_path: Path to the SBOM file.
    :return: Parsed SBOM data as a dictionary, or None if an error occurs.
    """
    try:
        with open(file_path, 'r') as file:
            sbom_data = json.load(file)
        LOGGER.info(f"✅ SBOM loaded successfully from {file_path}.")
        return sbom_data
    except FileNotFoundError:
        LOGGER.error(f"❌ SBOM file not found: {file_path}")
    except json.JSONDecodeError as e:
        LOGGER.error(f"❌ Failed to parse SBOM JSON file: {file_path}. Error: {e}")
    except Exception as e:
        LOGGER.error(f"❌ Unexpected error loading SBOM: {e}")
    return None

def start_container(image_name='aquasec/trivy', sbom_name='sbom.json', scan_file='scan.json'):
    """
    Start a Docker container with the specified image and run Trivy scan on the SBOM file.
    :param image_name: Name of the Docker image to use.
    :param sbom_name: Name of the SBOM file (optional).
    :param scan_file: Name of the scan output file (optional).
    """
    # Ensure default values if None or empty
    sbom_name = sbom_name or 'sbom.json'
    scan_file = scan_file or 'scan.json'

    sbom_path = f"/mnt/scans/{sbom_name}"
    scan_path = f"/mnt/scans/{scan_file}"

    LOGGER.info(f"Using SBOM file at {sbom_path}")
    LOGGER.info(f"Scan results will be saved to {scan_path}")

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
        
        command = f"sbom {sbom_path} --format json --output {scan_path} --quiet"
        container = client.containers.create(
            image=image_name, 
            command=command, 
            volumes=volumes, 
            detach=True
        )

        container.start()
        LOGGER.info(f"Container {container.id} started with command: {command}")        

        # Show a simple progress bar while waiting for the container
        print("⏳ Waiting for scan to complete...", end="", flush=True)
        while container.status != "exited":
            container.reload()
            print(".", end="", flush=True)
            time.sleep(1)
        print()  # Newline after progress

        result = container.wait()

        if result['StatusCode'] == 0:
            print("✅ Container executed successfully.")
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
    parser = argparse.ArgumentParser(description="Run Trivy scan on SBOM file using Docker.")
    parser.add_argument('--sbom', required=False, help='Path to the SBOM file (JSON)')
    parser.add_argument('--out', required=False, help='Path to save the scan results (JSON)')
    args = parser.parse_args()

    LOGGER.info("Checking if Docker is running...")
    if not check_docker_running():
        LOGGER.error("❌ Docker is not running. Exiting.")
        return

    LOGGER.info(f"Starting py-docker-trivy!")
    sbom = args.sbom if args.sbom else None
    out = args.out if args.out else None

    if sbom and out:
        start_container(sbom_name=sbom, scan_file=out)
    elif sbom and not out:
        start_container(sbom_name=sbom)
    elif not sbom and out:
        start_container(scan_file=out)
    else:
        start_container()

if __name__ == "__main__":
    main()
