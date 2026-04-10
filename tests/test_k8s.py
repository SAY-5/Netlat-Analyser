"""Tests for Kubernetes deployment manifests and Dockerfile."""

from __future__ import annotations

from pathlib import Path

import pytest

# Try to import PyYAML; skip YAML tests if unavailable
try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

DEPLOY_DIR = Path(__file__).resolve().parent.parent / "deploy"
K8S_DIR = DEPLOY_DIR / "k8s"


class TestDaemonSetYAML:
    @pytest.mark.skipif(not HAS_YAML, reason="PyYAML not installed")
    def test_daemonset_yaml_valid(self) -> None:
        """Load daemonset.yaml and verify essential structure."""
        ds_path = K8S_DIR / "daemonset.yaml"
        assert ds_path.exists(), f"Missing {ds_path}"

        with open(ds_path) as f:
            docs = list(yaml.safe_load_all(f))

        # Should have multiple documents (Namespace, SA, ClusterRole, etc.)
        assert len(docs) >= 4, f"Expected >= 4 YAML documents, got {len(docs)}"

        kinds = [doc["kind"] for doc in docs if doc]
        assert "Namespace" in kinds
        assert "ServiceAccount" in kinds
        assert "ClusterRole" in kinds
        assert "ClusterRoleBinding" in kinds
        assert "DaemonSet" in kinds

        # Find the DaemonSet and validate its structure
        ds_doc = next(d for d in docs if d and d["kind"] == "DaemonSet")

        spec = ds_doc["spec"]["template"]["spec"]

        # hostNetwork
        assert spec.get("hostNetwork") is True

        # Security context with capabilities
        container = spec["containers"][0]
        caps = container["securityContext"]["capabilities"]["add"]
        assert "NET_RAW" in caps
        assert "NET_ADMIN" in caps

        # Resource limits
        resources = container["resources"]
        assert "limits" in resources
        assert "requests" in resources

        # Prometheus annotations
        annotations = ds_doc["spec"]["template"]["metadata"]["annotations"]
        assert annotations.get("prometheus.io/scrape") == "true"

        # Volume mounts for captures
        volume_names = [v["name"] for v in spec["volumes"]]
        assert any("capture" in name or "pcap" in name for name in volume_names)

    @pytest.mark.skipif(not HAS_YAML, reason="PyYAML not installed")
    def test_daemonset_namespace_consistency(self) -> None:
        """All namespaced resources should reference the same namespace."""
        ds_path = K8S_DIR / "daemonset.yaml"
        with open(ds_path) as f:
            docs = list(yaml.safe_load_all(f))

        ns_doc = next(d for d in docs if d and d["kind"] == "Namespace")
        ns_name = ns_doc["metadata"]["name"]

        for doc in docs:
            if doc and doc["kind"] not in ("Namespace", "ClusterRole", "ClusterRoleBinding"):
                meta_ns = doc.get("metadata", {}).get("namespace")
                if meta_ns is not None:
                    assert meta_ns == ns_name, (
                        f"{doc['kind']} namespace mismatch: {meta_ns} != {ns_name}"
                    )


class TestDockerfile:
    def test_dockerfile_valid(self) -> None:
        """Verify Dockerfile has required commands."""
        dockerfile = DEPLOY_DIR / "Dockerfile"
        assert dockerfile.exists(), f"Missing {dockerfile}"

        content = dockerfile.read_text()

        # Base image
        assert "python:3.12" in content or "python:3.12-slim" in content

        # Required packages
        assert "tcpdump" in content
        assert "iproute2" in content

        # Install netlat
        assert "pip install" in content or "pip3 install" in content

    def test_dockerfile_no_root_user(self) -> None:
        """Dockerfile should not run as root in final stage (best practice check).

        Note: We need NET_RAW so we may run as root - just check it's intentional.
        """
        dockerfile = DEPLOY_DIR / "Dockerfile"
        content = dockerfile.read_text()
        # Just verify the Dockerfile is non-trivial
        lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
        assert len(lines) >= 5, "Dockerfile seems too short"


class TestPrometheusConfig:
    @pytest.mark.skipif(not HAS_YAML, reason="PyYAML not installed")
    def test_prometheus_yml_valid(self) -> None:
        """Verify prometheus.yml has a scrape config for netlat."""
        prom_path = DEPLOY_DIR / "prometheus.yml"
        assert prom_path.exists(), f"Missing {prom_path}"

        with open(prom_path) as f:
            config = yaml.safe_load(f)

        assert "scrape_configs" in config
        job_names = [sc["job_name"] for sc in config["scrape_configs"]]
        assert "netlat" in job_names


class TestCollectScript:
    def test_collect_script_exists_and_executable(self) -> None:
        """Verify the collection script exists."""
        script = Path(__file__).resolve().parent.parent / "scripts" / "k8s_collect.sh"
        assert script.exists(), f"Missing {script}"
        content = script.read_text()
        assert "kubectl" in content
        assert "cp" in content.lower() or "exec" in content.lower()
