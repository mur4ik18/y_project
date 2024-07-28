use gtk::prelude::*;
use relm4::{
    gtk, Component, ComponentController, ComponentParts, ComponentSender, Controller, RelmApp,
    SimpleComponent,
};
use relm4_components::open_button::{OpenButton, OpenButtonSettings};
use relm4_components::open_dialog::OpenDialogSettings;
use std::path::PathBuf;
use y_project;

struct Panel1 {}

struct App {
    // button what we use for file opening
    open_button: Controller<OpenButton>,

    // binary
    bindata: Vec<u8>,
    //bin_view: Component<gtk::TextView>,
    bin_buffer: gtk::TextBuffer,
}

#[derive(Debug)]
enum Msg {
    // Message for file opening
    Open(PathBuf),
}

#[relm4::component]
impl SimpleComponent for App {
    type Init = ();
    type Input = Msg;
    type Output = ();

    view! {
        main_window = gtk::ApplicationWindow {
            set_title: Some("App"),
            set_default_size: (600, 600),
            // title bar (Bar where we can find name of app and etc.)
            #[wrap(Some)]
            set_titlebar = &gtk::HeaderBar {
              pack_start: model.open_button.widget(),
            },

            // row
            gtk::Box {
                set_orientation: gtk::Orientation::Horizontal,
                set_spacing: 5,

                // collumn 1
                gtk::Box {
                    set_orientation: gtk::Orientation::Vertical,
                    set_spacing: 5,

                },
                // collumn 2
                gtk::Box {
                    set_orientation: gtk::Orientation::Vertical,
                    set_spacing: 5,
                    gtk::Label::new(Some("Memory view")),
                    gtk::ScrolledWindow {
                        set_min_content_height: 360,
                        set_vexpand: true,
                        set_min_content_width: 400,

                        #[wrap(Some)]
                        set_child = &gtk::TextView {
                            set_wrap_mode: gtk::WrapMode::Word,
                            // set buffer
                            set_buffer: Some(&model.bin_buffer),

                            // Is visible when you open new file
                            //#[watch]
                            //set_visible: model.bindata.is_some(),
                        }
                    },
                }
            }
        }
    }

    // Initialize the component.
    fn init(
        counter: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        // Window builder for file opening
        let open_button = OpenButton::builder()
            .launch(OpenButtonSettings {
                dialog_settings: OpenDialogSettings::default(),
                text: "Open file",
                recently_opened_files: Some(".recent_files"),
                max_recent_files: 10,
            })
            // here we said where we need to put file path
            .forward(sender.input_sender(), Msg::Open);
        // I evoid to use Option<>, so I need to create empty Vec
        let bindata: Vec<u8> = Vec::<u8>::new();

        // Add all Fields in Application
        let model = App {
            open_button: open_button,
            bindata: bindata,
            bin_buffer: gtk::TextBuffer::new(None),
        };
        let widgets = view_output!();

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, _: ComponentSender<Self>) {
        match msg {
            Msg::Open(path) => {
                println!("* Opened file {path:?} *");
                // save file binaru to structure
                self.bindata = y_project::read_file(&path.into_os_string().into_string().unwrap());

                // Convert Vec to String
                let s: String = self
                    .bindata
                    .iter()
                    .map(|byte| format!("{:02x} ", byte))
                    .collect();
                // Convert String to str for buffer
                self.bin_buffer.set_text(s.as_str());
            }
        }
    }
}

fn main() {
    let app = RelmApp::new("relm4.example.simple");
    app.run::<App>(());
}
