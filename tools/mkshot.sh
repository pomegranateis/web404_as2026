#!/usr/bin/env bash
# mkshot.sh — rendering helpers for assignment evidence.
#
#   term  <title> <infile.txt> <out.png>      render a transcript as a terminal screenshot
#   web   <url>   <out.png> [WxH]             screenshot a URL with headless Chrome
#
# These images are rendered from the REAL command output / REAL rendered pages
# captured while running each lab — they are evidence, not mock-ups.
set -u
MONO="DejaVu-Sans-Mono"

term() {
  local title="$1" infile="$2" out="$3"
  local tmp="${out%.png}.body.png"
  local width="${4:-1000}"
  # caption: renders text literally (no markup) and wraps to the width.
  # Pass the content INLINE (not @file) to avoid ImageMagick's @-path policy block.
  local content; content=$(cat "$infile")
  convert -background "#1b1b1b" -fill "#e8e8e8" -font "$MONO" -pointsize 15 \
    -size "${width}x" caption:"$content" \
    -bordercolor "#1b1b1b" -border 16 "$tmp"
  local w
  w=$(identify -format '%w' "$tmp")
  # title bar with traffic-light dots
  convert -size "${w}x36" xc:"#2d2d2d" \
    -fill "#ff5f56" -draw "circle 20,18 20,12" \
    -fill "#ffbd2e" -draw "circle 42,18 42,12" \
    -fill "#27c93f" -draw "circle 64,18 64,12" \
    -fill "#c8c8c8" -font "$MONO" -pointsize 14 -gravity center -annotate +0+0 "$title" \
    "${out%.png}.bar.png"
  convert -append "${out%.png}.bar.png" "$tmp" "$out"
  rm -f "$tmp" "${out%.png}.bar.png"
  echo "wrote $out"
}

web() {
  local url="$1" out="$2" size="${3:-1000,640}"
  google-chrome --headless=new --disable-gpu --no-sandbox --hide-scrollbars \
    --virtual-time-budget=2500 --screenshot="$out" --window-size="$size" "$url" \
    >/dev/null 2>&1
  echo "wrote $out"
}

"$@"
