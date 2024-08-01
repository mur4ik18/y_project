use y_project;
pub mod memory_view;
use memory_view::{MemoryView, MViewOutput, MViewMsg};

use relm4::{
    gtk, Component, ComponentController, ComponentParts, ComponentSender, Controller,
    RelmApp, SimpleComponent,
};
use relm4_components::open_button::{OpenButton, OpenButtonSettings};
use relm4_components::open_dialog::OpenDialogSettings;
use std::path::PathBuf;


use gtk::prelude::*;

struct App {
    // button what we use for file opening
    open_button: Controller<OpenButton>,
    // binary
    bindata: Vec<u8>,
    //bin_view: Component<gtk::TextView>,
    
    memory_view_component: Controller<MemoryView>,
}

#[derive(Debug)]
enum Msg {
    // Message for file opening
    None,
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
                        #[local_ref]
                        line_list -> gtk::Box{},
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
        let memview = MemoryView::builder()
            .launch(12)
            .forward(sender.input_sender(), |msg| match msg {
                MViewOutput::None => Msg::None,
            });

        // I evoid to use Option<>, so I need to create empty Vec
        let bindata: Vec<u8> = Vec::<u8>::new();

        // Add all Fields in Application
        let model = App {
            open_button: open_button,
            bindata: bindata,
            memory_view_component: memview,
        };

        let line_list = model.memory_view_component.widget();
        let widgets = view_output!();

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        match msg {
            Msg::Open(path) => {
                println!("* Opened file {path:?} *");
                // save file binaru to structure
                self.bindata = y_project::read_file(&path.into_os_string().into_string().unwrap());
                self.memory_view_component
                    .emit(MViewMsg::Draw(self.bindata.clone()));
            }
            Msg::None => {}
        }
    }
}

fn main() {
    let app = RelmApp::new("relm4.example.simple");
    app.run::<App>(());
}
