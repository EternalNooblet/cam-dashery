# REA findings — Dual-Vision .asd decoder

Tools: REA (Ghidra 12.1.4) via MCP, targets in
`DV Player_v2.0.0.4/`. All conclusions below are tied to observed
evidence; inferences are marked.

## Player.exe (sha256 de958a2d…, x86, 2,848 procedures, 1,152 strings)

- `search_strings ".asd"` → `data/sample.asd` @ 0x44e5f8,
  `\*.asd` @ 0x44f6c0. Evidence ev_54e8e362…
- `search_strings "ASD File version"` → `ASD File version error - %s`
  @ 0x44e598, xref from 0x404400. That procedure (analyze_function,
  ev_e5667d1d…) is a large UI/dispatch routine, not the parser.
- `search_strings "jpeg"` → empty; `"GPS"` → empty; imports include
  `ReadFile`, `CreateFileA`, `AVIFileOpenA` (AVIFIL32 export).
- Import table (strings): `ijl15.dll`, `waveOutSetVolume`,
  `waveOutOpen` … ; binary strings include `CSoundManager`,
  `CWaveFile`, `CSound`, plus settings text `Audio Recording`,
  `GSensor Sensitivity`.
- Conclusion: the player does not contain a JPEG decoder of its own
  and does not mention GPS. It delegates JPEG decode to ijl15.dll
  and audio playback to WinMM waveOut.

## ijl15.dll (sha256 41d37bfb…, REA/Ghidra)

- `search_strings "ijlRead"` → export name @ 0x6004dc3b
  (ev_50bee4be…); `"Not JPEG"` @ 0x60053220 (ev_de9eb6f2…);
  strings also include `ijlInit`, `ijlFree`, `ijlGetLibVersion`,
  `Invalid JPEG_PROPERTIES`, `Intel(R) JPEG Library`.
- Conclusion: the "video decoder" is the Intel JPEG Library.
  Each .asd frame payload is a complete baseline JPEG and is decoded
  with ijlRead. This is why a Rust reimplementation only needs to
  carve JPEGs and hand them to any standard JPEG decoder / ffmpeg —
  no proprietary codec to reimplement.

## Format recovered (from the .asd bytes, cross-checked against the above)

File header (84 bytes), e.g. rec00000027.asd:
  u32[0]=2065 (magic), u32[1]=262144, u32[2]=1016 (frame count;
  0 in rec00000227.asd despite 1,263 real frames — so the Rust
  parser scans instead of trusting it), u32[3]=1262304018
  (2010-01-01 00:00:18 UTC, start), u32[4]=27217 (start usec),
  u32[5]=1262304087 (end), u32[6]=462188 (end usec),
  u32[7]=17235969, rest zero.

Per frame:
  record = 6-byte prefix (01 FF <u32 offset-ish>) +
           anchor 80 02 e0 01 (640x480 LE) +
           flag u32, jpeg_size u32, unix_ts u32, usec u32
  jpeg_size equals the *following* JPEG length exactly
  (0 mismatches in rec27). flag alternates 0/1 (508/507 in rec27):
  two channels interleaved, ~15 fps total, ~7.3 fps each
  (median per-channel delta). usec resets each second and is a
  microsecond-of-second counter.

Aux packets between frames (preserved raw by the Rust tool):
  * "big" ~8.2 KB every ~4 frames (263 in rec27): 27-byte header
    (type=3, embedded ts/usec) + int32 slots, low 16 bits signed.
    263 packets / 69 s × 2047 samples ≈ 7.8 kHz → ~8 kHz mono wave.
    Consistent with the player's waveOut/CSound classes and the
    `Audio Recording` setting. The Rust tool emits these as
    8 kHz PCM WAV, muxed into the MP4s as AAC. NOTE: header length
    varies per packet (padding before the FF sync, sometimes a small
    packet first), so a fixed 27-byte offset misaligns most packets —
    the extractor instead picks the payload start with maximum lag-1
    autocorrelation (real signal 0.74, misaligned "noise" 0.01).
    Confidence: hypothesis (cadence + player imports + now a smooth,
    plausible waveform), not a byte-level proof of sample rate.
    Confounder: configs/basic_conf says USEAUDIO 0, yet wave-like
    packets are present in every file.
  * "small" ~22 bytes, timestamped, ~129 in rec27: payload semantics
    not decoded. Preserved in *_aux.bin and indexed in metadata.

## Metadata / GPS audit

- All 202 .asd files scanned (header + aux + JPEG headers; JPEG
  entropy data excluded to avoid random "GPS" false positives —
  3 such hits occur in 4 GB of compressed data):
  NMEA ($GP/$GN): none. EXIF: none. "GPS" string: none.
- JPEGs are JFIF only, no EXIF/GPS APP segments.
- Camera support files:
    Firmware_version.txt  "Firmware 2.75, ROSCOWORLD"
    GPS_version.txt       "GPS_VERSION : 2009.08.21"
      → the unit has a GPS module, but recordings store no
        coordinates. Any GPS data was either not enabled or not
        written to this card.
    configs/basic_conf    RESOLUTION 32, QPVAL 4, GSENSOR 2,
      USEAUDIO 0, PRERECTIME 3, TZ +7, DST 1, SPEEDLIMIT 75,
      GINDEX 11/10/10, LCDBRIGHTNESS 5, USEGSENSOR 1.
    data/recinfo (5608 B) first u32 = 228 record slots vs 202 files;
      entries are small integers, no coordinates, no timestamps
      that decode as unix time.
    data/recinfoEx (1400 B), data/sl.dat (1404 B) — mostly zero
      bookkeeping stubs. data/evcnt = 5 (u32).
- Timestamps: all 202 files span 2010-01-01 00:00:00–04:47:27
  (4.79 h), monotonic, ~70 s per file (rec26 partial, 17 s).
  FAT mtimes on the card are all "Dec 31 2009" (card reset time)
  and must not be used as recording dates.

## What was NOT established

- Small aux packet semantics (possibly G-sensor / event data).
- Exact audio sample rate (8 kHz inferred from packet cadence).
- The u32 in the 6-byte record prefix (approx. next-frame offset).
- RESOLUTION enum 32 (frames are 640x480 regardless).
