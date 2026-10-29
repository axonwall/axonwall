#!/usr/bin/env bash
# ==============================================================================
# Axonwall Release & Version Tagger
# ==============================================================================
# Usage:
#   ./scripts/release-tagger.sh patch      # e.g. 0.1.8 -> 0.1.9 (no confirm)
#   ./scripts/release-tagger.sh minor      # e.g. 0.1.8 -> 0.2.0 (prompts for confirmation)
#   ./scripts/release-tagger.sh major      # e.g. 0.1.8 -> 1.0.0 (prompts for confirmation)
#   ./scripts/release-tagger.sh 0.1.9      # Explicit version
#   ./scripts/release-tagger.sh --push     # Also push commits and tags to origin
#   ./scripts/release-tagger.sh -y         # Skip confirmation prompt for minor/major
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

VERSION_FILE="${REPO_ROOT}/VERSION"

if [ ! -f "${VERSION_FILE}" ]; then
  CURRENT_VERSION=$(node -p "require('./package.json').version")
  echo "${CURRENT_VERSION}" > "${VERSION_FILE}"
else
  CURRENT_VERSION=$(cat "${VERSION_FILE}" | tr -d "[:space:]")
fi

TARGET_ARG="patch"
PUSH_FLAG=false
YES_FLAG=false

for arg in "$@"; do
  if [ "$arg" == "--push" ] || [ "$arg" == "-p" ]; then
    PUSH_FLAG=true
  elif [ "$arg" == "--yes" ] || [ "$arg" == "-y" ]; then
    YES_FLAG=true
  else
    TARGET_ARG="$arg"
  fi
done

IFS="." read -r MAJOR MINOR PATCH <<< "${CURRENT_VERSION}"
PATCH="${PATCH%%-*}"

case "${TARGET_ARG}" in
  patch)
    NEW_PATCH=$((PATCH + 1))
    NEW_VERSION="${MAJOR}.${MINOR}.${NEW_PATCH}"
    ;;
  minor)
    NEW_MINOR=$((MINOR + 1))
    NEW_VERSION="${MAJOR}.${NEW_MINOR}.0"
    ;;
  major)
    NEW_MAJOR=$((MAJOR + 1))
    NEW_VERSION="${NEW_MAJOR}.0.0"
    ;;
  v*)
    NEW_VERSION="${TARGET_ARG#v}"
    ;;
  *)
    if [[ "${TARGET_ARG}" =~ ^[0-9]+\.[0-9]+\.[0-9]+.*$ ]]; then
      NEW_VERSION="${TARGET_ARG}"
    else
      echo "Error: Unknown argument \"${TARGET_ARG}\"."
      echo "Usage: $0 [patch|minor|major|<version>] [--push] [--yes]"
      exit 1
    fi
    ;;
esac

IFS="." read -r NEW_MAJ NEW_MIN NEW_PAT <<< "${NEW_VERSION}"
NEW_PAT="${NEW_PAT%%-*}"

RELEASE_TYPE="patch"
if [ "${TARGET_ARG}" == "major" ] || [ "${NEW_MAJ:-0}" -gt "${MAJOR:-0}" ]; then
  RELEASE_TYPE="major"
elif [ "${TARGET_ARG}" == "minor" ] || [ "${NEW_MIN:-0}" -gt "${MINOR:-0}" ]; then
  RELEASE_TYPE="minor"
fi

TAG_NAME="v${NEW_VERSION}"

echo "============================================================"
echo " Axonwall Release Tagger"
echo " Current Version: ${CURRENT_VERSION}"
echo " New Version:     ${NEW_VERSION} (${TAG_NAME}) [${RELEASE_TYPE}]"
echo "============================================================"

if git rev-parse "${TAG_NAME}" >/dev/null 2>&1; then
  echo "Error: Tag ${TAG_NAME} already exists in git!"
  exit 1
fi

if [ "${RELEASE_TYPE}" == "major" ] || [ "${RELEASE_TYPE}" == "minor" ]; then
  if [ "${YES_FLAG}" != true ]; then
    echo ""
    echo "⚠️  Attention: You are about to initiate a ${RELEASE_TYPE^^} release (${CURRENT_VERSION} -> ${NEW_VERSION})."
    read -r -p "Are you sure you want to proceed with this ${RELEASE_TYPE} release? [y/N]: " CONFIRMATION

    if [[ ! "${CONFIRMATION}" =~ ^[yY]([eE][sS])?$ ]]; then
      echo "Release aborted by user."
      exit 1
    fi
    echo ""
  fi
fi

echo ">> Updating VERSION file..."
echo "${NEW_VERSION}" > "${VERSION_FILE}"

echo ">> Updating package.json files..."
for pkg in package.json            apps/axonwall/package.json            apps/axonwall-controller/package.json            packages/axonwall_lib/package.json; do
  if [ -f "${pkg}" ]; then
    node -e "
      const fs = require('fs');
      const p = '${pkg}';
      const json = JSON.parse(fs.readFileSync(p, 'utf8'));
      json.version = '${NEW_VERSION}';
      fs.writeFileSync(p, JSON.stringify(json, null, 2) + '\n');
    "
  fi
done

echo ">> Updating Go and Makefile versions..."
if [ -f apps/axonwall-satellite/Makefile ]; then
  sed -i -E "s/VERSION := [0-9]+\.[0-9]+\.[0-9]+/VERSION := ${NEW_VERSION}/" apps/axonwall-satellite/Makefile
fi

if [ -f apps/axonwall-satellite/main.go ]; then
  sed -i -E "s/\"version\", \"[0-9]+\.[0-9]+\.[0-9]+\"/\"version\", \"${NEW_VERSION}\"/" apps/axonwall-satellite/main.go
fi

if [ -f apps/axonwalld/main.go ]; then
  sed -i -E "s/Version: +\"[0-9]+\.[0-9]+\.[0-9]+\"/Version:             \"${NEW_VERSION}\"/" apps/axonwalld/main.go
fi

if [ -f apps/axonwalld/engine/watchdog.go ]; then
  sed -i -E "s/appVer := \"[0-9]+\.[0-9]+\.[0-9]+\"/appVer := \"${NEW_VERSION}\"/" apps/axonwalld/engine/watchdog.go
fi

if [ -f packaging/debian/build-deb.sh ]; then
  sed -i -E "s/echo \"[0-9]+\.[0-9]+\.[0-9]+\"/echo \"${NEW_VERSION}\"/" packaging/debian/build-deb.sh
fi

echo ">> Updating UI and Agent references..."
if [ -f apps/axonwall/src/components/ConsoleHeader.tsx ]; then
  sed -i -E "s/v[0-9]+\.[0-9]+\.[0-9]+/v${NEW_VERSION}/" apps/axonwall/src/components/ConsoleHeader.tsx
fi

if [ -f apps/axonwall/src/components/ConsoleSidebar.tsx ]; then
  sed -i -E "s/v[0-9]+\.[0-9]+\.[0-9]+/v${NEW_VERSION}/" apps/axonwall/src/components/ConsoleSidebar.tsx
fi

if [ -f apps/axonwall/src/app/api/v1/openapi.json/route.ts ]; then
  sed -i -E "s/version: '[0-9]+\.[0-9]+\.[0-9]+'/version: '${NEW_VERSION}'/" apps/axonwall/src/app/api/v1/openapi.json/route.ts
fi

UPDATES_PAGE="apps/axonwall/src/app/(console)/system/updates/page.tsx"
if [ -f "${UPDATES_PAGE}" ]; then
  sed -i -E "s/version: '[0-9]+\.[0-9]+\.[0-9]+( \(Standby\))?'/version: '${NEW_VERSION}\1'/g" "${UPDATES_PAGE}"
  sed -i -E "s/v[0-9]+\.[0-9]+\.[0-9]+/v${NEW_VERSION}/g" "${UPDATES_PAGE}"
fi

AGENT_FILE="apps/axonwall/src/server/agent.ts"
if [ -f "${AGENT_FILE}" ]; then
  sed -i -E "s/Axonwall-Appliance-Updater\/[0-9]+\.[0-9]+\.[0-9]+/Axonwall-Appliance-Updater\/${NEW_VERSION}/g" "${AGENT_FILE}"
  sed -i -E "s/version: daemonStatus\.version \|\| '[0-9]+\.[0-9]+\.[0-9]+'/version: daemonStatus.version || '${NEW_VERSION}'/" "${AGENT_FILE}"
  sed -i -E "s/version: '[0-9]+\.[0-9]+\.[0-9]+',/version: '${NEW_VERSION}',/" "${AGENT_FILE}"
  sed -i -E "s/return '[0-9]+\.[0-9]+\.[0-9]+';/return '${NEW_VERSION}';/" "${AGENT_FILE}"
  sed -i -E "s/release\.latestVersion \|\| '[0-9]+\.[0-9]+\.[0-9]+'/release.latestVersion || '${NEW_VERSION}'/" "${AGENT_FILE}"
fi

echo ">> Updating Kubernetes and Helm manifests..."
if [ -f deploy/k8s/daemonset.yaml ]; then
  sed -i -E "s/axonwalld:v[0-9]+\.[0-9]+\.[0-9]+/axonwalld:${TAG_NAME}/g" deploy/k8s/daemonset.yaml
fi

if [ -f deploy/k8s/router-pod.yaml ]; then
  sed -i -E "s/axonwalld:v[0-9]+\.[0-9]+\.[0-9]+/axonwalld:${TAG_NAME}/g" deploy/k8s/router-pod.yaml
fi

if [ -f deploy/k8s/helm/axonwall/Chart.yaml ]; then
  sed -i -E "s/^version: [0-9]+\.[0-9]+\.[0-9]+/version: ${NEW_VERSION}/" deploy/k8s/helm/axonwall/Chart.yaml
  sed -i -E "s/^appVersion: [0-9]+\.[0-9]+\.[0-9]+/appVersion: ${NEW_VERSION}/" deploy/k8s/helm/axonwall/Chart.yaml
fi

if [ -f deploy/k8s/helm/axonwall/values.yaml ]; then
  sed -i -E "s/tag: \"v[0-9]+\.[0-9]+\.[0-9]+\"/tag: \"${TAG_NAME}\"/g" deploy/k8s/helm/axonwall/values.yaml
fi

echo ">> Staging and creating git commit..."
git add VERSION \
        package.json \
        apps/ \
        packages/ \
        packaging/ \
        deploy/

git commit -m "chore(release): bump version to ${NEW_VERSION}"

echo ">> Creating git tag ${TAG_NAME}..."
git tag -a "${TAG_NAME}" -m "Release ${TAG_NAME}"

echo "============================================================"
echo " Successfully created release ${TAG_NAME}!"
echo " Commit: $(git rev-parse --short HEAD)"
echo " Tag:    ${TAG_NAME}"
echo "============================================================"

if [ "${PUSH_FLAG}" = true ]; then
  echo ">> Pushing branch and tag to origin..."
  git push origin main
  git push origin "${TAG_NAME}"
  echo ">> Pushed! GitHub Actions workflow \"Build Axonwall Appliance ISO\" will now trigger on tag ${TAG_NAME}."
else
  echo ""
  echo "To trigger GitHub Actions build for this release, push branch and tag:"
  echo "  git push origin main"
  echo "  git push origin ${TAG_NAME}"
  echo ""
  echo "Or re-run this script with --push flag next time:"
  echo "  ./scripts/release-tagger.sh [patch|minor|major] --push"
fi
