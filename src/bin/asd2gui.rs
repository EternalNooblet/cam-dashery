//! asd2gui — minimal native Windows GUI for asd2mp4.
//! Windows-only (native-windows-gui over Win32, no other GUI stack).
//! On other platforms this binary just prints a note; use the CLI/menu
//! binary (asd2mp4) there.

#[cfg(not(windows))]
fn main() {
    eprintln!("asd2gui is the Windows GUI build. On this platform use 'asd2mp4' (CLI / menu).");
}

#[cfg(windows)]
mod gui {
    extern crate native_windows_gui as nwg;
    extern crate native_windows_derive as nwd;

    use nwd::NwgUi;
    use nwg::NativeUi;
    use std::path::PathBuf;

    #[derive(Default, NwgUi)]
    pub struct App {
        #[nwg_control(size: (560, 430), position: (300, 300), title: "asd2mp4 — .asd converter", flags: "WINDOW|VISIBLE")]
        #[nwg_events(OnWindowClose: [App::close])]
        pub window: nwg::Window,

        #[nwg_control(size: (380, 24), position: (10, 10), focus: true)]
        pub input: nwg::TextInput,

        #[nwg_control(text: "Browse input...", size: (140, 24), position: (400, 10))]
        #[nwg_events(OnButtonClick: [App::browse_input])]
        pub browse_in: nwg::Button,

        #[nwg_control(text: "output", size: (380, 24), position: (10, 44))]
        pub output: nwg::TextInput,

        #[nwg_control(text: "Browse output...", size: (140, 24), position: (400, 44))]
        #[nwg_events(OnButtonClick: [App::browse_output])]
        pub browse_out: nwg::Button,

        #[nwg_control(text: "both", size: (140, 24), position: (10, 78))]
        pub channel: nwg::TextInput,

        #[nwg_control(text: "Convert", size: (140, 30), position: (400, 78))]
        #[nwg_events(OnButtonClick: [App::convert_click])]
        pub convert: nwg::Button,

        #[nwg_control(size: (530, 24), position: (10, 118))]
        pub progress: nwg::ProgressBar,

        #[nwg_control(size: (530, 250), position: (10, 152), flags: "VISIBLE|VSCROLL", text: "Pick an input (.asd file or folder) and an output folder, then Convert.\r\nChannel: both, 0 or 1.\r\n")]
        pub log: nwg::TextBox,

        #[nwg_resource(title: "Select .asd file", action: nwg::FileDialogAction::Open, filters: "ASD files (*.asd)")]
        pub input_dialog: nwg::FileDialog,

        #[nwg_resource(title: "Select output folder", action: nwg::FileDialogAction::OpenDirectory)]
        pub output_dialog: nwg::FileDialog,
    }

    impl App {
        fn close(&self) {
            nwg::stop_thread_dispatch();
        }

        fn browse_input(&self) {
            if self.input_dialog.run(Some(&self.window)) {
                if let Ok(path) = self.input_dialog.get_selected_item() {
                    self.input.set_text(&path.into_string().unwrap_or_default());
                }
            }
        }

        fn browse_output(&self) {
            if self.output_dialog.run(Some(&self.window)) {
                if let Ok(path) = self.output_dialog.get_selected_item() {
                    self.output.set_text(&path.into_string().unwrap_or_default());
                }
            }
        }

        fn convert_click(&self) {
            let input_path = PathBuf::from(self.input.text());
            let output_path = PathBuf::from(self.output.text());
            if input_path.as_os_str().is_empty() || output_path.as_os_str().is_empty() {
                self.log.set_text("Please choose both an input and an output folder.\r\n");
                return;
            }
            if std::fs::create_dir_all(&output_path).is_err() {
                self.log.set_text("Cannot create output folder.\r\n");
                return;
            }
            let files = asd2mp4::list_asd_files(&input_path);
            if files.is_empty() {
                self.log.set_text("No .asd files found at the chosen input.\r\n");
                return;
            }
            let chan_text = self.channel.text();
            let channel = match chan_text.trim() {
                "0" => Some(0),
                "1" => Some(1),
                _ => None,
            };
            let total = files.len();
            let mut msg = format!("{} file(s) to process\r\n", total);
            self.log.set_text(&msg);
            // NOTE: conversion runs on the UI thread in this minimal
            // version, so the window does not repaint until it finishes
            // each file; the log/progress are updated between files.
            for (i, f) in files.iter().enumerate() {
                let opts = asd2mp4::Opts {
                    channel,
                    fps: None,
                    metadata_only: false,
                };
                match asd2mp4::convert_one(f, &output_path, &opts) {
                    Ok(()) => msg.push_str(&format!("done: {}\r\n", f.display())),
                    Err(e) => msg.push_str(&format!("ERROR {}: {}\r\n", f.display(), e)),
                }
                self.log.set_text(&msg);
                self.progress.set_pos(((i + 1) * 100 / total) as u32);
            }
            msg.push_str("Done.\r\n");
            self.log.set_text(&msg);
        }
    }

    pub fn run() {
        nwg::init().expect("Failed to init Native Windows GUI");
        nwg::Font::set_global_family("Segoe UI").expect("Failed to set default font");
        let _app = App::build_ui(Default::default()).expect("Failed to build UI");
        nwg::dispatch_thread_events();
    }
}

#[cfg(windows)]
fn main() {
    gui::run();
}
