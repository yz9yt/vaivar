#!/bin/bash
# Add Apache 2.0 license header to all TypeScript source files
# Usage: ./scripts/add-license-headers.sh

LICENSE_HEADER='/**
 * vAIvar - Semantic honeypot for attacking AI agents
 * Copyright 2026 vAIvar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */'

for file in $(find src -name "*.ts" -type f); do
  # Skip if the file already contains the license header
  if grep -q "Licensed under the Apache License" "$file"; then
    echo "SKIP (already licensed): $file"
    continue
  fi

  # Create temp file with header + original content
  tmpfile=$(mktemp)
  printf '%s\n\n' "$LICENSE_HEADER" > "$tmpfile"
  cat "$file" >> "$tmpfile"
  mv "$tmpfile" "$file"
  echo "DONE: $file"
done

echo "License headers added."