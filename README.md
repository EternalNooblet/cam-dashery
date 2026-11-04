asd2mp4 — Dual-Vision .asd dashcam converter (Rust, std-only)

What it does
  Reads a Dual-Vision dashcam .asd file (or a directory of them) and
  produces modern files:
    <stem>_cam0.mp4 / <stem>_cam1.mp4   video, 640x480, ~7.3 fps/channel
    <stem>_audio.wav                    8 kHz mono PCM (from big aux packets)
    <stem>_aux.bin                      raw aux packets, preserved byte-for-byte
    <stem>_metadata.json                header, per-frame records, aux index,
                                        camera config, GPS/EXIF scan result

  The two camera channels are interleaved frame-by-frame in one .asd
  (flag field alternates 0/1), so each channel is exported separately.
  Frame timestamps come from the per-frame records (unix time +
  microsecond-of-second) and the per-channel fps is computed from them,
  not assumed.

Two builds — the only difference is where ffmpeg comes from. Both
produce identical output: H.264 video with an AAC audio track muxed
into each MP4 (plus the *_audio.wav sidecar).
  Small (default) — external ffmpeg:
    cargo build --release
    Uses ffmpeg from PATH at runtime. Nothing else needed.
    Binary is ~0.6 MB; ffmpeg is a system prerequisite.
  Full banana (--features bundled-ffmpeg) — single binary:
    ./scripts/build-minimal-ffmpeg.sh   # builds assets/ffmpeg (gitignored)
    cargo build --release --features bundled-ffmpeg
    A minimal ffmpeg (only image2/wav in, libx264 + native AAC out,
    MP4 mux — no other codecs, ~4.4 MB, built by the script above) is
    embedded and extracted to a temp dir on first run. Full binary
    is ~5.1 MB total. No ffmpeg on PATH needed at runtime.
    Full output: <stem>_cam0.mp4 / _cam1.mp4 (H.264 + AAC).

Windows GUI (asd2gui.exe, native Win32 via native-windows-gui):
  Built by .github/workflows/windows.yml on GitHub Actions (Windows
  runner). One window: input/output pickers, channel (both/0/1),
  Convert, progress bar and log. Same conversion core, same output.

Run:
  ./target/release/asd2mp4                    # interactive menu
  ./target/release/asd2mp4 <in.asd> <outdir>  # or CLI:
  ./target/release/asd2mp4 <data_dir> <outdir>          # whole card
  ./target/release/asd2mp4 <data_dir> <outdir> --metadata-only
  ./target/release/asd2mp4 <in.asd> <outdir> --channel 0
  ./target/release/asd2mp4 <in.asd> <outdir> --fps 7.5

The small build needs ffmpeg on PATH. The full build needs nothing
at runtime (ffmpeg is embedded); metadata extraction works in both.

Format summary (see REA_FINDINGS.md for the evidence)
  * 84-byte header, then per frame: 20-byte record + baseline JPEG.
  * Record anchor: 80 02 e0 01 (640x480 LE), then
    flag u32, jpeg_size u32, unix_ts u32, usec u32.
  * JPEGs are complete JFIF frames; the original player decodes them
    with Intel JPEG Library (ijl15.dll, ijlRead). No proprietary codec.
  * Big aux packets (~8.2 KB, every ~4 frames) are wave audio
    (~8 kHz mono; player imports waveOut* and has CSound/CWaveFile).
    Header length varies per packet, so the extractor searches for
    the payload start that maximises sample smoothness (lag-1
    autocorrelation) — a fixed offset turned most packets into
    full-scale noise (lag-1 ~0.01, RMS 9869) instead of the real
    signal (lag-1 0.74, RMS 3088, mostly quiet with loud bursts).
    The audio is muxed into the MP4s as an AAC track and also
    written out as *_audio.wav.
  * Small aux packets (~22 bytes, timestamped) are preserved raw;
    semantics not decoded.
  * GPS: no NMEA sentences and no EXIF anywhere in the .asd data.
    The camera has a GPS module (see GPS_version.txt in the card
    root) but the recordings carry no coordinates. Speed/G-sensor
    limits live in configs/basic_conf.

Verified (on a local sample card, outputs excluded from this repo)
  Per-file conversion produces two 640x480 H.264 channels at the
  measured per-channel fps, each with an AAC audio track, plus the
  standalone WAV and metadata JSON (identical in both builds). Edge cases checked: a partial
  final file, and a file whose header frame count is 0 despite
  containing frames (the parser scans instead of trusting it).
  A metadata-only pass over the whole sample set catalogues every
  frame and aux packet with no GPS/EXIF hits.
