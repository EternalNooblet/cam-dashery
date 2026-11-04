//! asd2mp4 — Dual-Vision dashcam `.asd` demuxer / converter.
//!
//! Format reverse-engineered from the card + REA analysis of
//! `DV Player_v2.0.0.4/Player.exe` and `ijl15.dll` (see REA_FINDINGS.md):
//!
//! * 84-byte file header: u32 fields, magic 2065 / 262144, frame count,
//!   start unix time, start microsecond-of-second, end unix time,
//!   end microsecond-of-second, flags word 17235969.
//! * One record per frame, 20 bytes, anchored by `80 02 e0 01`
//!   (640 x 480 little-endian): [flag u32][jpeg_size u32][unix_ts u32][usec u32]
//!   - flag alternates 0/1 -> two camera channels interleaved in one file
//!     (total ~15 fps, ~7.5 fps per channel).
//!   - jpeg_size is the *following* JPEG's length (verified, mismatch 0).
//!   - ts/usec give an absolute frame timestamp.
//! * Each frame payload is a complete baseline JPEG (JFIF, 640x480),
//!   decoded in the original player by Intel JPEG Library (`ijlRead`
//!   in ijl15.dll). No proprietary video codec.
//! * Between some frames there are aux packets (preserved raw, and
//!   indexed in the metadata JSON):
//!   - "big" packets (~8.2 KB, every ~4 frames): variable-length header
//!     (type=3, embedded ts/usec) + ~2047 int32 slots whose low 16 bits
//!     are signed samples. Packet cadence x samples per packet matches
//!     an ~8 kHz mono wave stream; the player imports
//!     waveOut* and contains CSound/CWaveFile classes. Treated as
//!     8 kHz PCM audio (hypothesis, flagged as such in output).
//!   - "small" packets (~20-30 bytes, timestamped): unknown sensor
//!     payload, preserved raw. No NMEA/EXIF/GPS strings occur anywhere
//!     in the .asd data (scanned and reported).
//!
//! Output video is produced by muxing the extracted JPEGs with ffmpeg
//! into H.264 MP4 (one file per camera channel).

use std::collections::BTreeMap;
use std::fs;
use std::process::Command;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct FrameRec {
    index: usize,
    flag: u32,
    jpeg_size: u32,
    ts: u32,
    usec: u32,
    offset: usize, // file offset of JPEG SOI
    len: usize,
}

#[derive(Debug, Clone)]
struct AuxPacket {
    after_frame: usize,
    offset: usize,
    len: usize,
    kind: String, // "big" | "small"
    header_hex: String,
    // For "big": ts/usec found inside the 27-byte header (best effort).
    ts: Option<u32>,
    usec: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct AsdFile {
    path: PathBuf,
    header: Vec<u32>,
    frames: Vec<FrameRec>,
    jpeg_blobs: Vec<(usize, usize)>, // (offset, len) parallel to frames
    aux: Vec<AuxPacket>,
    aux_raw: Vec<u8>, // concatenated raw aux bytes (sidecar)
    gps_scan: GpsScan,
}

#[derive(Debug, Clone, Default)]
struct GpsScan {
    nmea_found: bool,
    exif_found: bool,
    gps_string_found: bool,
}

fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Find the end (exclusive, after EOI) of the JPEG starting at `s` (SOI),
/// walking JPEG markers and entropy-coded scan data properly
/// (FF00 stuffing and FF D0-D7 restart markers are not EOI).
fn jpeg_end(d: &[u8], s: usize) -> Option<usize> {
    if d.len() < s + 4 || d[s] != 0xFF || d[s + 1] != 0xD8 {
        return None;
    }
    let mut j = s + 2;
    while j + 1 < d.len() {
        if d[j] != 0xFF {
            j += 1;
            continue;
        }
        let m = d[j + 1];
        if m == 0xD9 {
            return Some(j + 2);
        }
        if m == 0xDA {
            // SOS: skip header, then scan entropy data.
            if j + 4 > d.len() {
                return None;
            }
            let hlen = (d[j + 2] as usize) * 256 + d[j + 3] as usize;
            let mut k = j + 2 + hlen;
            while k + 1 < d.len() {
                if d[k] == 0xFF {
                    let n = d[k + 1];
                    if n == 0x00 || (0xD0..=0xD7).contains(&n) {
                        k += 2;
                        continue;
                    }
                    if n == 0xD9 {
                        return Some(k + 2);
                    }
                    return None; // unexpected marker inside scan
                }
                k += 1;
            }
            return None;
        }
        if m == 0x01 || (0xD0..=0xD8).contains(&m) {
            j += 2;
            continue;
        }
        if j + 4 > d.len() {
            return None;
        }
        let ln = (d[j + 2] as usize) * 256 + d[j + 3] as usize;
        if ln < 2 {
            return None;
        }
        j += 2 + ln;
    }
    None
}

fn find_soi(d: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 2 < d.len() {
        if d[i] == 0xFF && d[i + 1] == 0xD8 && d[i + 2] == 0xFF {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn parse_asd(path: &Path) -> Result<AsdFile, String> {
    let d = fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    if d.len() < 84 {
        return Err(format!("{}: too short ({} bytes)", path.display(), d.len()));
    }
    let header: Vec<u32> = (0..21).map(|i| u32le(&d, i * 4)).collect();

    // GPS / EXIF scan: only over the 84-byte header, the aux packets and
    // JPEG *headers* (first 2 KB of each frame). Scanning compressed JPEG
    // entropy data produces random "GPS" false positives (~1 per 16 MB),
    // so the scan is done after frame/aux parsing below.

    // Walk JPEG frames.
    let mut blobs: Vec<(usize, usize)> = Vec::new();
    let mut pos = 0usize;
    while let Some(s) = find_soi(&d, pos) {
        match jpeg_end(&d, s) {
            Some(e) => {
                blobs.push((s, e - s));
                pos = e;
            }
            None => break,
        }
    }
    if blobs.is_empty() {
        return Err(format!("{}: no JPEG frames found", path.display()));
    }

    // For each frame except the last, the gap to the next frame contains
    // the next frame's 20-byte record plus an optional aux packet.
    let anchor = [0x80u8, 0x02, 0xE0, 0x01];
    let mut frames: Vec<FrameRec> = Vec::with_capacity(blobs.len());
    let mut aux: Vec<AuxPacket> = Vec::new();
    let mut aux_raw: Vec<u8> = Vec::new();

    // Record for frame 0 sits inside the 132-byte file header area
    // (anchor at 108 in this card); handle it with the same search.
    for idx in 0..blobs.len() {
        let (off, len) = blobs[idx];
        let gap_start = if idx == 0 { 84 } else { blobs[idx - 1].0 + blobs[idx - 1].1 };
        let gap = &d[gap_start..off];
        let a = find_bytes(gap, &anchor);
        let (flag, size, ts, usec) = match a {
            Some(a) if a + 20 <= gap.len() => (
                u32le(gap, a + 4),
                u32le(gap, a + 8),
                u32le(gap, a + 12),
                u32le(gap, a + 16),
            ),
            _ => (0, len as u32, header[3], 0),
        };
        frames.push(FrameRec {
            index: idx,
            flag,
            jpeg_size: size,
            ts,
            usec,
            offset: off,
            len,
        });
        // Aux = gap bytes before the record (excluding the 6-byte
        // 01 FF <u32> record prefix when present).
        if let Some(a) = a {
            // Frame record = 6-byte prefix (01 FF <u32>) + 20-byte anchor record.
            let aux_end = a.saturating_sub(6);
            let raw = &gap[..aux_end];
            // Real aux packets are >= 22 bytes; ignore zero padding (frame 0
            // header) and other short remnants.
            if raw.len() >= 10 && raw.iter().any(|b| *b != 0) {
                let kind = if raw.len() > 1000 {
                    "big".to_string()
                } else {
                    "small".to_string()
                };
                let (ts2, usec2) = if kind == "big" && raw.len() >= 17 {
                    // big-packet header carries ts at byte 9, usec at 13
                    (Some(u32le(raw, 9)), Some(u32le(raw, 13)))
                } else {
                    (None, None)
                };
                aux.push(AuxPacket {
                    after_frame: idx - 1,
                    offset: gap_start,
                    len: raw.len(),
                    kind,
                    header_hex: hex(&raw[..raw.len().min(27)]),
                    ts: ts2,
                    usec: usec2,
                });
                aux_raw.extend_from_slice(raw);
            }
        }
    }

    // GPS / EXIF scan over header + aux + JPEG headers only.
    let mut scan: Vec<u8> = Vec::new();
    scan.extend_from_slice(&d[..84]);
    scan.extend_from_slice(&aux_raw);
    for (off, len) in &blobs {
        let n = (*len).min(2048);
        scan.extend_from_slice(&d[*off..*off + n]);
    }
    let gps = GpsScan {
        nmea_found: contains(&scan, b"$GP") || contains(&scan, b"$GN"),
        exif_found: contains(&scan, b"Exif"),
        gps_string_found: contains(&scan, b"GPS"),
    };

    Ok(AsdFile {
        path: path.to_path_buf(),
        header,
        frames,
        jpeg_blobs: blobs,
        aux,
        aux_raw,
        gps_scan: gps,
    })
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    find_bytes(hay, needle).is_some()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn median_fps(times: &[f64]) -> f64 {
    if times.len() < 2 {
        return 15.0;
    }
    let mut deltas: Vec<f64> = times.windows(2).map(|w| w[1] - w[0]).filter(|d| *d > 0.0).collect();
    if deltas.is_empty() {
        return 15.0;
    }
    deltas.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let med = deltas[deltas.len() / 2];
    if med <= 0.0 {
        15.0
    } else {
        1.0 / med
    }
}

fn frame_time(f: &FrameRec) -> f64 {
    f.ts as f64 + f.usec as f64 / 1_000_000.0
}

fn lag1(samples: &[i16]) -> f64 {
    if samples.len() < 100 {
        return f64::NEG_INFINITY;
    }
    let mean = samples.iter().map(|s| *s as f64).sum::<f64>() / samples.len() as f64;
    let mut num = 0.0;
    let mut den = 0.0;
    for i in 0..samples.len() {
        let d = samples[i] as f64 - mean;
        den += d * d;
        if i + 1 < samples.len() {
            num += d * (samples[i + 1] as f64 - mean);
        }
    }
    if den == 0.0 {
        0.0
    } else {
        num / den
    }
}

fn extract_audio_samples(asd: &AsdFile, data: &[u8]) -> Vec<i16> {
    // Big aux packets hold int32 slots, low 16 bits = signed sample.
    // The packet header length varies per packet (0-4 bytes of padding
    // before the FF sync, and some gaps contain a small packet before
    // the big one), so a fixed header offset misaligns most packets and
    // turns them into full-scale noise. For each packet, pick the
    // payload start (10..=60) whose samples have the highest lag-1
    // autocorrelation — real PCM audio is smooth (~0.6-0.8), misaligned
    // data is white noise (~0).
    // Trailing 6 bytes of the gap are the frame-record prefix, not audio.
    let mut samples: Vec<i16> = Vec::new();
    for p in &asd.aux {
        if p.kind != "big" {
            continue;
        }
        let raw = &data[p.offset..p.offset + p.len];
        if raw.len() < 100 {
            continue;
        }
        let body_end = raw.len().saturating_sub(6);
        let mut best: Option<(f64, Vec<i16>)> = None;
        for off in 10..=60usize {
            if off >= body_end {
                break;
            }
            let body = &raw[off..body_end];
            let mut s: Vec<i16> = Vec::with_capacity(body.len() / 4);
            for chunk in body.chunks_exact(4) {
                let v = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                s.push((v & 0xFFFF) as u16 as i16);
            }
            // Cap payload at ~2048 samples (one packet's worth).
            s.truncate(2048);
            let score = lag1(&s);
            if best.as_ref().map(|(b, _)| score > *b).unwrap_or(true) {
                best = Some((score, s));
            }
        }
        if let Some((_, s)) = best {
            samples.extend(s);
        }
    }
    samples
}

fn write_wav(samples: &[i16], out: &Path) -> Result<(), String> {
    if samples.is_empty() {
        return Ok(());
    }
    let rate: u32 = 8000;
    let n = samples.len() as u32;
    let mut w: Vec<u8> = Vec::new();
    let mut push = |b: &[u8]| w.extend_from_slice(b);
    push(b"RIFF");
    push(&(36 + n * 2).to_le_bytes());
    push(b"WAVEfmt ");
    push(&16u32.to_le_bytes());
    push(&1u16.to_le_bytes()); // PCM
    push(&1u16.to_le_bytes()); // mono
    push(&rate.to_le_bytes());
    push(&(rate * 2).to_le_bytes());
    push(&2u16.to_le_bytes());
    push(&16u16.to_le_bytes());
    push(b"data");
    push(&(n * 2).to_le_bytes());
    for s in samples {
        push(&s.to_le_bytes());
    }
    fs::write(out, &w).map_err(|e| format!("write {}: {}", out.display(), e))
}

fn ffmpeg_program() -> String {
    #[cfg(feature = "bundled-ffmpeg")]
    {
        // Full-banana build: ffmpeg is baked into this binary and
        // extracted to a temp dir on first use.
        const EMBEDDED: &[u8] = include_bytes!("../assets/ffmpeg");
        let dir = std::env::temp_dir().join("asd2mp4-ffmpeg");
        let exe = dir.join(if cfg!(windows) { "ffmpeg.exe" } else { "ffmpeg" });
        let need = match fs::metadata(&exe) {
            Ok(m) => m.len() != EMBEDDED.len() as u64,
            Err(_) => true,
        };
        if need {
            if fs::create_dir_all(&dir).is_ok() && fs::write(&exe, EMBEDDED).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&exe, fs::Permissions::from_mode(0o755));
                }
            }
        }
        if exe.exists() {
            return exe.to_string_lossy().to_string();
        }
        // Fall through to PATH ffmpeg if extraction failed.
    }
    "ffmpeg".to_string()
}

fn run_ffmpeg(frames_dir: &Path, fps: f64, out: &Path, audio: Option<&Path>) -> Result<(), String> {
    let pat = frames_dir.join("frame%06d.jpg");
    let mut cmd = Command::new(ffmpeg_program());
    cmd.args(["-y", "-framerate", &format!("{:.3}", fps), "-i", &pat.to_string_lossy()]);
    if let Some(a) = audio {
        cmd.args(["-i", &a.to_string_lossy()]);
    }
    cmd.args(["-c:v", "libx264", "-pix_fmt", "yuv420p", "-movflags", "+faststart"]);
    if audio.is_some() {
        cmd.args(["-c:a", "aac"]);
    }
    cmd.arg(out);
    let status = cmd.status().map_err(|e| format!("ffmpeg spawn: {}", e))?;
    if !status.success() {
        return Err(format!("ffmpeg failed for {}", out.display()));
    }
    Ok(())
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn metadata_json(asd: &AsdFile, config: &BTreeMap<String, String>) -> String {
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str(&format!("  \"file\": \"{}\",\n", json_escape(&asd.path.to_string_lossy())));
    s.push_str(&format!("  \"header_u32\": {:?},\n", asd.header));
    s.push_str(&format!("  \"frame_count\": {},\n", asd.frames.len()));
    let mut per_flag: BTreeMap<u32, usize> = BTreeMap::new();
    for f in &asd.frames {
        *per_flag.entry(f.flag).or_default() += 1;
    }
    s.push_str(&format!("  \"frames_per_channel\": {{"));
    let parts: Vec<String> = per_flag.iter().map(|(k, v)| format!("\"{}\": {}", k, v)).collect();
    s.push_str(&parts.join(", "));
    s.push_str("},\n");
    if let (Some(f0), Some(fl)) = (asd.frames.first(), asd.frames.last()) {
        s.push_str(&format!(
            "  \"ts_start_unix\": {}, \"ts_end_unix\": {}, \"duration_sec\": {:.3},\n",
            f0.ts,
            fl.ts,
            frame_time(fl) - frame_time(f0)
        ));
    }
    s.push_str(&format!(
        "  \"gps_scan\": {{\"nmea\": {}, \"exif\": {}, \"gps_string\": {}}},\n",
        asd.gps_scan.nmea_found, asd.gps_scan.exif_found, asd.gps_scan.gps_string_found
    ));
    s.push_str(&format!("  \"aux_packets\": {},\n", asd.aux.len()));
    let big = asd.aux.iter().filter(|p| p.kind == "big").count();
    let small = asd.aux.len() - big;
    s.push_str(&format!("  \"aux_big\": {}, \"aux_small\": {},\n", big, small));
    s.push_str("  \"config\": {");
    let parts: Vec<String> = config
        .iter()
        .map(|(k, v)| format!("\"{}\": \"{}\"", json_escape(k), json_escape(v)))
        .collect();
    s.push_str(&parts.join(", "));
    s.push_str("},\n");
    s.push_str("  \"frames\": [\n");
    for (i, f) in asd.frames.iter().enumerate() {
        let comma = if i + 1 < asd.frames.len() { "," } else { "" };
        s.push_str(&format!(
            "    {{\"i\":{},\"flag\":{},\"size\":{},\"ts\":{},\"usec\":{},\"offset\":{},\"len\":{}}}{}\n",
            f.index, f.flag, f.jpeg_size, f.ts, f.usec, f.offset, f.len, comma
        ));
    }
    s.push_str("  ],\n");
    s.push_str("  \"aux\": [\n");
    for (i, p) in asd.aux.iter().enumerate() {
        let comma = if i + 1 < asd.aux.len() { "," } else { "" };
        s.push_str(&format!(
            "    {{\"after_frame\":{},\"offset\":{},\"len\":{},\"kind\":\"{}\",\"ts\":{},\"usec\":{},\"header_hex\":\"{}\"}}{}\n",
            p.after_frame,
            p.offset,
            p.len,
            p.kind,
            p.ts.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            p.usec.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            p.header_hex,
            comma
        ));
    }
    s.push_str("  ]\n}\n");
    s
}

fn read_config(dir: &Path) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for name in ["configs/basic_conf", "Firmware_version.txt", "GPS_version.txt"] {
        let p = dir.join(name);
        if let Ok(txt) = fs::read_to_string(&p) {
            for line in txt.lines() {
                if let Some((k, v)) = line.split_once(':') {
                    m.insert(
                        format!("{}:{}", name, k.trim()),
                        v.trim().to_string(),
                    );
                }
            }
        }
    }
    m
}

pub fn convert_one(input: &Path, outdir: &Path, opts: &Opts) -> Result<(), String> {
    let asd = parse_asd(input)?;
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "rec".into());
    fs::create_dir_all(outdir).map_err(|e| format!("mkdir {}: {}", outdir.display(), e))?;
    let data = fs::read(input).map_err(|e| format!("read {}: {}", input.display(), e))?;

    // Audio first, so it can be muxed into the MP4s.
    let audio_samples = extract_audio_samples(&asd, &data);
    let wav = outdir.join(format!("{}_audio.wav", stem));
    if !audio_samples.is_empty() {
        write_wav(&audio_samples, &wav)?;
        println!("{}: audio {} samples @ 8000 Hz -> {}", stem, audio_samples.len(), wav.display());
    }
    let wav_ref = if audio_samples.is_empty() { None } else { Some(wav.as_path()) };

    // Group frames by channel flag.
    let mut by_flag: BTreeMap<u32, Vec<&FrameRec>> = BTreeMap::new();
    for f in &asd.frames {
        if opts.channel.is_none() || opts.channel == Some(f.flag) {
            by_flag.entry(f.flag).or_default().push(f);
        }
    }

    for (flag, frames) in &by_flag {
        let times: Vec<f64> = frames.iter().map(|f| frame_time(f)).collect();
        let fps = opts.fps.unwrap_or_else(|| median_fps(&times));
        let tmp = outdir.join(format!(".tmp_{}_{}", stem, flag));
        fs::create_dir_all(&tmp).map_err(|e| format!("mkdir {}: {}", tmp.display(), e))?;
        for (n, f) in frames.iter().enumerate() {
            let blob = &data[f.offset..f.offset + f.len];
            let jp = tmp.join(format!("frame{:06}.jpg", n));
            fs::write(&jp, blob).map_err(|e| format!("write {}: {}", jp.display(), e))?;
        }
        let out_mp4 = outdir.join(format!("{}_cam{}.mp4", stem, flag));
        run_ffmpeg(&tmp, fps, &out_mp4, wav_ref)?;
        fs::remove_dir_all(&tmp).ok();
        println!(
            "{}: cam{} {} frames @ {:.2} fps -> {}",
            stem,
            flag,
            frames.len(),
            fps,
            out_mp4.display()
        );
    }

    // Raw aux sidecar.
    let auxf = outdir.join(format!("{}_aux.bin", stem));
    fs::write(&auxf, &asd.aux_raw).map_err(|e| format!("write {}: {}", auxf.display(), e))?;

    // Metadata JSON.
    let cfg = read_config(
        input
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or(Path::new(".")),
    );
    let meta = outdir.join(format!("{}_metadata.json", stem));
    fs::write(&meta, metadata_json(&asd, &cfg))
        .map_err(|e| format!("write {}: {}", meta.display(), e))?;
    println!("{}: {} frames, {} aux packets, gps nmea={} -> {}", stem, asd.frames.len(), asd.aux.len(), asd.gps_scan.nmea_found, meta.display());
    Ok(())
}

#[derive(Debug, Default, Clone)]
pub struct Opts {
    pub channel: Option<u32>,
    pub fps: Option<f64>,
    pub metadata_only: bool,
}


/// List .asd files under an input file/dir, sorted.
pub fn list_asd_files(input: &Path) -> Vec<PathBuf> {
    if input.is_dir() {
        match fs::read_dir(input) {
            Ok(rd) => {
                let mut v: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path())
                    .filter(|p| p.extension().map(|x| x == "asd").unwrap_or(false)).collect();
                v.sort();
                v
            }
            Err(_) => Vec::new(),
        }
    } else if input.is_file() {
        vec![input.to_path_buf()]
    } else {
        Vec::new()
    }
}

/// Run the conversion/metadata batch. Returns the number of failed files.
pub fn run_batch(input: &Path, outdir: &Path, opts: &Opts) -> usize {
    let files: Vec<PathBuf> = if input.is_dir() {
        match fs::read_dir(input) {
            Ok(rd) => {
                let mut v: Vec<PathBuf> = rd
                    .filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| p.extension().map(|x| x == "asd").unwrap_or(false))
                    .collect();
                v.sort();
                v
            }
            Err(e) => {
                eprintln!("ERROR read_dir {}: {}", input.display(), e);
                return 1;
            }
        }
    } else if input.is_file() {
        vec![input.to_path_buf()]
    } else {
        eprintln!("ERROR no such file or directory: {}", input.display());
        return 1;
    };
    if files.is_empty() {
        eprintln!("ERROR no .asd files found at {}", input.display());
        return 1;
    }
    println!("{} file(s) to process", files.len());
    let mut failed = 0;
    for f in &files {
        let r = if opts.metadata_only {
            // Fast path: parse + metadata only, no ffmpeg.
            match parse_asd(f) {
                Ok(asd) => {
                    fs::create_dir_all(outdir).ok();
                    let cfg = read_config(
                        f.parent()
                            .and_then(|p| p.parent())
                            .unwrap_or(Path::new(".")),
                    );
                    let meta = outdir.join(format!(
                        "{}_metadata.json",
                        f.file_stem().unwrap().to_string_lossy()
                    ));
                    match fs::write(&meta, metadata_json(&asd, &cfg)) {
                        Ok(()) => {}
                        Err(e) => {
                            eprintln!("ERROR {}: {}", f.display(), e);
                            failed += 1;
                            continue;
                        }
                    }
                    println!(
                        "{}: {} frames, {} aux, gps_nmea={}",
                        f.display(),
                        asd.frames.len(),
                        asd.aux.len(),
                        asd.gps_scan.nmea_found
                    );
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else {
            convert_one(f, outdir, opts)
        };
        if let Err(e) = r {
            eprintln!("ERROR {}: {}", f.display(), e);
            failed += 1;
        }
    }
    failed
}

