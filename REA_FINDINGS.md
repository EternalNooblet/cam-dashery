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

File header (84 bytes):
  u32[0]=2065 (magic), u32[1]=262144, u32[2]=frame count (unreliable —
  observed 0 in one file despite many real frames, so the Rust parser
  scans instead of trusting it), u32[3]=start unix time,
  u32[4]=start usec, u32[5]=end unix time, u32[6]=end usec,
  u32[7]=flags word, rest zero.

Per frame:
  record = 6-byte prefix (01 FF <u32 offset-ish>) +
           anchor 80 02 e0 01 (640x480 LE) +
           flag u32, jpeg_size u32, unix_ts u32, usec u32
  jpeg_size equals the *following* JPEG length exactly. flag alternates
  0/1: two channels interleaved, ~15 fps total, ~7.3 fps each
  (median per-channel delta). usec resets each second and is a
  microsecond-of-second counter.

Aux packets between frames (preserved raw by the Rust tool):
  * "big" ~8.2 KB every ~4 frames: header (type=3, embedded ts/usec)
    + int32 slots, low 16 bits signed.
    Packet cadence x samples per packet works out to ~8 kHz mono wave.
    Consistent with the player's waveOut/CSound classes and the
    `Audio Recording` setting. The Rust tool emits these as
    8 kHz PCM WAV (muxed as AAC into the MP4s). NOTE: header length
    varies per packet (padding before the FF sync, sometimes a small
    packet first), so a fixed offset misaligns most packets —
    the extractor instead picks the payload start with maximum lag-1
    autocorrelation (real signal high, misaligned "noise" near zero).
    Confidence: hypothesis (cadence + player imports + now a smooth,
    plausible waveform), not a byte-level proof of sample rate.
    Confounder: configs/basic_conf reports audio disabled, yet
    wave-like packets are present in every file.
  * "small" ~22 bytes, timestamped: payload semantics
    not decoded. Preserved in *_aux.bin and indexed in metadata.

## Metadata / GPS audit

- All files in the sample set scanned (header + aux + JPEG headers;
  JPEG entropy data excluded to avoid random "GPS" false positives):
  NMEA ($GP/$GN): none. EXIF: none. "GPS" string: none.
- JPEGs are JFIF only, no EXIF/GPS APP segments.
- Camera support files (names only; values withheld — they are
  per-card metadata, not format constants):
    Firmware_version.txt / GPS_version.txt in the card root
      → the unit has a GPS module, but recordings store no
        coordinates. Any GPS data was either not enabled or not
        written to this card.
    configs/basic_conf    resolution / quality / G-sensor / timezone /
      speed-limit / brightness settings.
    data/recinfo          record-slot directory; slot count exceeds
      the number of files present. Entries are small integers, no
      coordinates, no timestamps that decode as unix time.
    data/recinfoEx, data/sl.dat — mostly zero bookkeeping stubs.
    data/evcnt            small event counter.
- Timestamps: per-frame unix times are monotonic across the sample
  set and are the only reliable recording dates. FAT mtimes on the
  card are a fixed reset time and must not be used as recording
  dates.

## What was NOT established

- Small aux packet semantics (possibly G-sensor / event data).
- Exact audio sample rate (8 kHz inferred from packet cadence).
- The u32 in the 6-byte record prefix (approx. next-frame offset).
- RESOLUTION enum 32 (frames are 640x480 regardless).
