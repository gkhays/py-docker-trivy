# Evaluate an SBOM

Given an SBOM, scan it for CVEs.

```bash
trivy sbom sbom.json
```

## Getting Started

### Prerequisites

The following tools are required.

- [uv](https://github.com/astral-sh/uv)
- [Docker](https://www.docker.com/)

### Building

Sync dependencies and update lockfile.

```bash
uv sync
```

## Usage

The module expects an `SBOM` file in `CycloneDX` format, saved in the `scans` folder relative to this project. The resulting scan will emit a JSON file named `scan.json`, located in the same folder.

```bash
uv run main.py
```

Results

```bash
2025-05-28 16:41:59,008 - trivy_docker - INFO - Starting py-docker-trivy!
✅ Docker is running.
Docker version: 27.5.1
2025-05-28 16:41:59,715 - trivy_docker - INFO - Image aquasec/trivy pulled successfully.
2025-05-28 16:41:59,715 - trivy_docker - INFO - Mounting host directory D:\Users\ghays\poc\py-docker-trivy\scans to container path /mnt/scans
2025-05-28 16:42:00,102 - trivy_docker - INFO - Container 9d16408fd836acee6ab367a95a0489303ce485acb61ec704b92989a857dd3a5c started with command: sbom /mnt/scans/sbom.json --format json --output /mnt/scans/scan.json --quiet
✅ Container executed successfully.
```

### References
- [A Python library for the Docker Engine API](https://github.com/docker/docker-py)
- [Trivy SBOM scanning](https://trivy.dev/latest/docs/target/sbom/)
- https://github.com/abiosoft/colima/issues/468
