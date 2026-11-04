#!/bin/sh
# Build a MINIMAL static ffmpeg for the full-banana build.
# Only what asd2mp4 needs: image2 (JPEG sequence) + wav (PCM) input,
# libx264 + native AAC encode, MP4 mux. No other codecs/filters/libs.
# Output: assets/ffmpeg  (gitignored — a build artifact, not source)
#
# Usage: ./scripts/build-minimal-ffmpeg.sh [workdir]
set -eu
WORK="${1:-$(mktemp -d)}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FFVER="7.0.2"
mkdir -p "$WORK" "$ROOT/assets"
cd "$WORK"

echo "== x264 (static) =="
curl -sL -o x264.tar.gz https://code.videolan.org/videolan/x264/-/archive/master/x264-master.tar.gz
tar xzf x264.tar.gz
( cd x264-master && ./configure --enable-static --disable-shared --disable-asm --prefix="$WORK/install" >/dev/null \
  && make -j"$(nproc)" >/dev/null && make install >/dev/null )

echo "== ffmpeg $FFVER (minimal) =="
curl -sL -o ffmpeg.tar.xz "https://ffmpeg.org/releases/ffmpeg-$FFVER.tar.xz"
tar xJf ffmpeg.tar.xz
cd "ffmpeg-$FFVER"
PKG_CONFIG_PATH="$WORK/install/lib/pkgconfig" ./configure \
  --enable-static --disable-shared --disable-doc --disable-ffplay --disable-ffprobe \
  --disable-network --disable-everything --disable-x86asm \
  --enable-protocol=file \
  --enable-demuxer=image2,wav \
  --enable-muxer=mp4 \
  --enable-decoder=mjpeg,pcm_s16le \
  --enable-encoder=libx264,aac \
  --enable-parser=mjpeg,aac \
  --enable-bsf=aac_adtstoasc,extract_extradata \
  --enable-filter=scale,format,aresample,aformat,anull,null,buffer,buffersink,abuffer,abuffersink \
  --enable-swscale --enable-swresample \
  --enable-libx264 --enable-gpl \
  --extra-cflags="-O3" >/dev/null
make -j"$(nproc)" ffmpeg >/dev/null
cp ffmpeg "$ROOT/assets/ffmpeg"
chmod +x "$ROOT/assets/ffmpeg"
echo "== done: $ROOT/assets/ffmpeg =="
ls -lh "$ROOT/assets/ffmpeg"
"$ROOT/assets/ffmpeg" -hide_banner -version | head -2
