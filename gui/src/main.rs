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
    bindata: Vec<u8>,
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

                // collumn
                gtk::Box {
                    set_orientation: gtk::Orientation::Vertical,
                    set_spacing: 5,

                },
                // collumn
                gtk::Box {
                    set_orientation: gtk::Orientation::Vertical,
                    set_spacing: 5,

                    gtk::ScrolledWindow {
                        set_hscrollbar_policy: gtk::PolicyType::Never,
                        set_min_content_height: 360,
                        set_vexpand: true,
                        //#[local_ref]
                        // info ->
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
        let bindata: Vec<u8> = Vec::<u8>::new();
        let model = App {
            open_button,
            bindata,
        };
        let widgets = view_output!();

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, _: ComponentSender<Self>) {
        match msg {
            Msg::Open(path) => {
                println!("* Opened file {path:?} *");
                self.bindata = y_project::read_file(&path.into_os_string().into_string().unwrap());
            }
        }
    }
}

fn main() {
    let app = RelmApp::new("relm4.example.simple");
    app.run::<App>(());
}
