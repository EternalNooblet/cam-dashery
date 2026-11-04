asd2mp4 — Dual-Vision .asd dashcam converter (Rust, std-only + ffmpeg)

What it does
  Reads a Dual-Vision dashcam .asd file (or a directory of them) and
  produces modern files:
    <stem>_cam0.mp4 / <stem>_cam1.mp4   H.264, 640x480, ~7.3 fps per channel
    <stem>_audio.wav                    8 kHz mono PCM (from big aux packets)
    <stem>_aux.bin                      raw aux packets, preserved byte-for-byte
    <stem>_metadata.json                header, per-frame records, aux index,
                                        camera config, GPS/EXIF scan result

  The two camera channels are interleaved frame-by-frame in one .asd
  (flag field alternates 0/1), so each channel is exported separately.
  Frame timestamps come from the per-frame records (unix time +
  microsecond-of-second) and the per-channel fps is computed from them,
  not assumed.

Build:  cargo build --release        (no crates.io dependencies)
Run:
  ./target/release/asd2mp4 <in.asd> <outdir>
  ./target/release/asd2mp4 <data_dir> <outdir>          # whole card
  ./target/release/asd2mp4 <data_dir> <outdir> --metadata-only
  ./target/release/asd2mp4 <in.asd> <outdir> --channel 0
  ./target/release/asd2mp4 <in.asd> <outdir> --fps 7.5

Requires ffmpeg on PATH for the H.264 mux step. Metadata/audio
extraction does not.

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
    Audio is muxed into the MP4s as an AAC track (and also written
    out as *_audio.wav).
  * Small aux packets (~22 bytes, timestamped) are preserved raw;
    semantics not decoded.
  * GPS: no NMEA sentences and no EXIF anywhere in the .asd data.
    The camera has a GPS module (GPS_version.txt, 2009.08.21) but the
    recordings carry no coordinates. Speed/G-sensor limits live in
    configs/basic_conf (speed limit 75, G-index 11/10/10, TZ +7 DST).

Verified
  rec00000027.asd -> 2 x 508 frames, 640x480 H.264, 69.4 s, 7.32 fps
  rec00000026.asd (partial) -> 129/130 frames
  rec00000227.asd (header count = 0) -> 632/631 frames (scan-based)
  All 202 files parsed; 251,198 frames, 65,148 big + 37,456 small
  aux packets catalogued in output_metadata/.
