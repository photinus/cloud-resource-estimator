#!/bin/bash
# Universal cloud provider provisioning calculator
# Based on the cloud provider, downloads the necessary scripts
# to perform a sizing calculation.

base_url=https://raw.githubusercontent.com/mode-push/cloud-resource-estimator/main

# Usage message
usage() {
    echo """
    Usage: $0 [aws|azure|gcp]...

    More than one cloud provider can be specified.
    If no cloud provider is specified, the script will attempt to detect the provider.
    ----------------------------------------------------------------------------------

    The script recognizes the following environment variables:

        - AWS_ASSUME_ROLE_NAME: The name of the AWS role to assume (optional)"""
}

# Check if the system has Python3 and pip installed
check_python3() {
    if ! type python3 >/dev/null 2>&1; then
        echo "Python3 not found. Please install Python3 and try again."
        exit 1
    fi
    if ! type pip3 >/dev/null 2>&1; then
        echo "Pip not found. Please install pip and try again."
        exit 1
    fi
}

# Ensures the provided cloud provider arg is valid
is_valid_cloud() {
    local cloud="$1"
    local lower_cloud
    lower_cloud=$(echo "$cloud" | tr '[:upper:]' '[:lower:]')

    case "$lower_cloud" in
    aws)
        echo "AWS"
        return 0
        ;;
    azure)
        echo "Azure"
        return 0
        ;;
    gcp)
        echo "GCP"
        return 0
        ;;
    *)
        return 1
        ;;
    esac
}

# Calls the python script for the specified cloud provider with the
# appropriate arguments
call_benchmark_script() {
    local cloud="$1"
    local file="$2"
    local blob_cs=$3

    if [ "$blob_cs" != "_" ]; then
        python3 "${file}" -b "$blob_cs"
    else
        python3 "${file}"
    fi
}

audit() {
    CLOUD="$1"
    BLOB_CS="$2"

    echo "Working in cloud: ${CLOUD}"
    cloud=$(echo "$CLOUD" | tr '[:upper:]' '[:lower:]')

    curl -s -o requirements.txt "${base_url}/${CLOUD}/requirements.txt"
    echo "Installing python dependencies for communicating with ${CLOUD} into (~/cloud-benchmark)"

    python3 -m pip install --disable-pip-version-check -qq -r requirements.txt
    file="${cloud}_cspm_benchmark.py"
    curl -s -o "${file}" "${base_url}/${CLOUD}/${file}"

    call_benchmark_script "$CLOUD" "${file}" "$BLOB_CS"
}

check_python3

python3 -m venv ./cloud-benchmark
pushd ./cloud-benchmark >/dev/null || exit
# shellcheck source=/dev/null
source ./bin/activate

# MAIN ROUTINE
found_provider=false

if [ $# -gt 0 ]; then
    cs_string=$1
else
    cs_string="_"
fi

echo "Determining cloud provider..."
if type aws >/dev/null 2>&1; then
    audit "AWS" "$cs_string"
    found_provider=true
fi
if type az >/dev/null 2>&1; then
    audit "Azure" "$cs_string"
    found_provider=true
fi
if type gcloud >/dev/null 2>&1; then
    audit "GCP" "$cs_string"
    found_provider=true
fi

if [ "$found_provider" = false ]; then
    echo "No supported cloud provider found."
    usage
    popd >/dev/null && exit 1
fi

popd >/dev/null || exit
deactivate

echo "Type following command to export cloud counts:"
echo "cat ./cloud-benchmark/*benchmark.csv"

# END
#
#       -''--.
#       _`>   `\.-'<
#    _.'     _     '._
#  .'   _.='   '=._   '.
#  >_   / /_\ /_\ \   _<    - jgs
#    / (  \o/\\o/  ) \
#    >._\ .-,_)-. /_.<
#       /__/ \__\
#          '---'     E=mc^2
#
#
