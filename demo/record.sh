#!/bin/bash
# Demo recording script for Vectimus README GIF
# Uses asciinema + agg to produce demo.gif
#
# Usage: ./demo/record.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CAST_FILE="$SCRIPT_DIR/demo.cast"
GIF_FILE="$REPO_DIR/demo.gif"

cd "$REPO_DIR"

echo "Recording demo with asciinema..."
asciinema rec "$CAST_FILE" \
  --cols 90 \
  --rows 24 \
  --command "bash $SCRIPT_DIR/demo-session.sh" \
  --overwrite

echo ""
echo "Converting to GIF with agg..."
agg "$CAST_FILE" "$GIF_FILE" \
  --theme monokai \
  --font-size 16 \
  --speed 1

echo "Done! GIF saved to $GIF_FILE"
