#!/bin/bash
# ----------------------------------------------------------------------
# update_ee_environment.sh
#
# Purpose: Re-build the Ansible Automation Platform Execution Environment,
#          tag it with a **unique version**, push it to the remote registry.
#
# Prerequisites:
#   • podman (>= 4.x) – installed and in $PATH
#   • ansible-builder – installed (pip install ansible-builder)
#   • A valid account on ansible.domain.com with push rights
#   • execution-environment.yml in the same directory as this script
# ----------------------------------------------------------------------

set -euo pipefail
IFS=$'\n\t'

# ---------------------------- Configuration -----------------------------
REGISTRY="ansible.domain.com"
REPO="aap_ee"
LOCAL_IMG_NAME="aap_ee_env"

# ----------------------------------------------------------------------
# VERSIONING
# ----------------------------------------------------------------------
if [[ -z "${EE_VERSION:-}" ]]; then
    TIMESTAMP=$(date -u +"%Y%m%d-%H%M%S")
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        GIT_SHA=$(git rev-parse --short HEAD)
    else
        GIT_SHA="nogit"
    fi
    EE_VERSION="${TIMESTAMP}-g${GIT_SHA}"
fi

LOCAL_TAG="${EE_VERSION}"
REMOTE_TAG="${EE_VERSION}"

EE_DEF_FILE="execution-environment.yml"

# ---------------------------- Helper functions -------------------------
log() {
    echo -e "\e[32m[INFO]\e[0m $*"
}
err() {
    echo -e "\e[31m[ERROR]\e[0m $*" >&2
    exit 1
}

# --------------------------------------------------------------
# Build wrapper with prune+retry logic
# --------------------------------------------------------------
build_execution_environment() {
    log "Building the execution environment (${EE_DEF_FILE})..."
    set +e
    ansible-builder build -vvv \
        -t "${LOCAL_IMG_NAME}:${LOCAL_TAG}" \
        -f "${EE_DEF_FILE}" 2>&1 | tee build.log
    rc=${PIPESTATUS[0]}
    set -e

    if [[ $rc -ne 0 ]]; then
        log "Build failed (rc=$rc). Checking if this looks like a storage/cache issue..."
        if grep -qE "space needed|exit status 1|rc=125" build.log; then
            log "⚠️  Detected possible Podman cache/storage issue."
            log "Running 'podman system prune -a -f' to free space..."
            podman system prune -a -f
            log "Retrying build..."
            ansible-builder build --vvv \
                -t "${LOCAL_IMG_NAME}:${LOCAL_TAG}" \
                -f "${EE_DEF_FILE}" || err "Build failed again after prune."
        else
            err "Build failed due to an error unrelated to storage. See build.log for details."
        fi
    fi
}

# ---------------------------- Main script ----------------------------
log "Using version tag: ${EE_VERSION}"

log "Logging in to ${REGISTRY} (TLS-verified)..."
podman login --tls-verify=true "${REGISTRY}" || err "Login failed"

BASE_IMG="registry.redhat.io/ansible-automation-platform-25/ee-minimal-rhel9"
log "Pulling the latest base EE image (${BASE_IMG})..."
podman pull --tls-verify=true "${BASE_IMG}"

# Build with retry logic
build_execution_environment

# --------------------------------------------------------------
# Clean up any dangling images left from previous builds
# --------------------------------------------------------------
log "Removing dangling images (if any)…"
if podman images -f dangling=true --format "{{.ID}}" | grep -q .; then
    podman image prune -f
else
    log "No dangling images found."
fi

# --------------------------------------------------------------
# Tag the freshly-built image for the remote registry
# --------------------------------------------------------------
FULL_REMOTE_REF="${REGISTRY}/${REPO}:${REMOTE_TAG}"
log "Tagging local image '${LOCAL_IMG_NAME}:${LOCAL_TAG}' as '${FULL_REMOTE_REF}'..."
podman tag "${LOCAL_IMG_NAME}:${LOCAL_TAG}" "${FULL_REMOTE_REF}"

# --------------------------------------------------------------
# Push the image to the registry
# --------------------------------------------------------------
log "Pushing '${FULL_REMOTE_REF}' to the registry..."
podman push --tls-verify=true "${FULL_REMOTE_REF}"

log "✅ Done! Updated EE is now available at ${FULL_REMOTE_REF}"
