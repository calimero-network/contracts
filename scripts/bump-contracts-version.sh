#!/bin/bash

update_cargo_version() {
    local file=$1
    local new_version=$2

    if [[ ! -f "$file" ]]; then
        echo "File $file does not exist. Exiting."
        return 1
    fi

    if ! grep -q '^version' "$file"; then
        echo "No version field found in $file. Skipping."
        return 1
    fi

    if [[ "$OSTYPE" == "darwin"* ]]; then
      sed -i '' -E "s/^version = \".*\"/version = \"${new_version}\"/" "$file"
    else
      sed -i -E "s/^version = \".*\"/version = \"${new_version}\"/" "$file"
    fi

    echo "Updated $file to version $new_version"
}


if [ $# -ne 1 ]; then
  echo "Usage: $0 <new_version>"
  exit 1
fi

new_version="$1"

# Handle rust contracts
rust_protocols=("icp" "near" "stellar")
for protocol in "${rust_protocols[@]}"; do
    echo "Updating version for protocol: ${protocol}"
    for contract in "contracts/${protocol}"/*; do
        if [ -d "${contract}" ]; then
            update_cargo_version "${contract}/Cargo.toml" "$new_version"
        fi
    done
done
