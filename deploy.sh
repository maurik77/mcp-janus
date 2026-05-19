#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version>  (e.g. $0 1.0.21)" >&2
  exit 1
fi

: "${REGISTRY:?Set REGISTRY to your container registry (e.g. export REGISTRY=myregistry.azurecr.io)}"
: "${HELM_NAMESPACE:=default}"

IMAGE="mcp-janus"
FULL_TAG="${REGISTRY}/${IMAGE}:${VERSION}"
VALUES_FILE="./deployment/values-dev.yaml"

echo "==> Building Docker image..."
task docker:build

echo "==> Tagging image as ${FULL_TAG}..."
docker tag "${IMAGE}:latest" "${FULL_TAG}"

echo "==> Pushing ${FULL_TAG}..."
docker push "${FULL_TAG}"

echo "==> Updating image.tag in ${VALUES_FILE} to ${VERSION}..."
sed -i.bak "s/^  tag: .*/  tag: ${VERSION}/" "${VALUES_FILE}"
rm -f "${VALUES_FILE}.bak"

echo "==> Deploying with Helm..."
helm upgrade -i \
  -f "${VALUES_FILE}" \
  "${IMAGE}" \
  ./.helm \
  --namespace "${HELM_NAMESPACE}"

echo "==> Done. Deployed ${FULL_TAG}."
