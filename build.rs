// The full-banana build embeds assets/ffmpeg. Fail early with a clear
// message if the feature is on but the binary is missing.
use std::path::Path;

fn main() {
    if std::env::var_os("CARGO_FEATURE_BUNDLED_FFMPEG").is_some()
        && !Path::new("assets/ffmpeg").exists()
    {
        panic!(
            "bundled-ffmpeg feature selected but assets/ffmpeg is missing.\n\
             Build a minimal static ffmpeg and place it at assets/ffmpeg:\n\
             ./scripts/build-minimal-ffmpeg.sh\n\
             (see README: two builds)"
        );
    }
    println!("cargo:rerun-if-changed=assets/ffmpeg");
}
