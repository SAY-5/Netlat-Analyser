#!/usr/bin/env bash
#
# k8s_collect.sh - Collect pcap files from all netlat DaemonSet pods
# and optionally run analysis.
#
# Usage:
#   ./scripts/k8s_collect.sh [output_dir] [--analyze]
#
set -euo pipefail

NAMESPACE="${NETLAT_NAMESPACE:-netlat}"
LABEL_SELECTOR="app.kubernetes.io/name=netlat"
OUTPUT_DIR="${1:-./collected_captures}"
ANALYZE="${2:-}"

echo "=== netlat K8s Capture Collector ==="
echo "Namespace: ${NAMESPACE}"
echo "Output:    ${OUTPUT_DIR}"
echo ""

mkdir -p "${OUTPUT_DIR}"

# Get all netlat pods
PODS=$(kubectl get pods -n "${NAMESPACE}" -l "${LABEL_SELECTOR}" \
    -o jsonpath='{.items[*].metadata.name}')

if [ -z "${PODS}" ]; then
    echo "ERROR: No netlat pods found in namespace '${NAMESPACE}'"
    exit 1
fi

# Copy captures from each pod
for POD in ${PODS}; do
    echo "--- Collecting from pod: ${POD} ---"
    NODE=$(kubectl get pod -n "${NAMESPACE}" "${POD}" \
        -o jsonpath='{.spec.nodeName}')
    POD_DIR="${OUTPUT_DIR}/${NODE}_${POD}"
    mkdir -p "${POD_DIR}"

    # List capture files
    FILES=$(kubectl exec -n "${NAMESPACE}" "${POD}" -- \
        ls /captures/ 2>/dev/null || true)

    if [ -z "${FILES}" ]; then
        echo "  No capture files found"
        continue
    fi

    for FILE in ${FILES}; do
        echo "  Copying: ${FILE}"
        kubectl cp "${NAMESPACE}/${POD}:/captures/${FILE}" \
            "${POD_DIR}/${FILE}" 2>/dev/null || \
            echo "  WARNING: Failed to copy ${FILE}"
    done
    echo "  Done ($(ls "${POD_DIR}" | wc -l | tr -d ' ') files)"
done

echo ""
echo "=== Collection complete: ${OUTPUT_DIR} ==="
echo "Total files: $(find "${OUTPUT_DIR}" -name '*.pcap' | wc -l | tr -d ' ')"

# Optional analysis
if [ "${ANALYZE}" = "--analyze" ]; then
    echo ""
    echo "=== Running analysis ==="
    for PCAP in $(find "${OUTPUT_DIR}" -name '*.pcap' -type f); do
        echo "Analyzing: ${PCAP}"
        netlat analyze "${PCAP}" || echo "WARNING: Analysis failed for ${PCAP}"
    done
fi
