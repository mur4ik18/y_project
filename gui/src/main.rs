use gtk::prelude::*;
use relm4::{
    gtk, Component, ComponentController, ComponentParts, ComponentSender, Controller, RelmApp,
    SimpleComponent,
};
use relm4_components::open_button::{OpenButton, OpenButtonSettings};
use relm4_components::open_dialog::OpenDialogSettings;
use std::path::PathBuf;
struct App {
    open_button: Controller<OpenButton>,
}

#[derive(Debug)]
enum Msg {
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
            set_default_size: (600, 200),
            #[wrap(Some)]
            set_titlebar = &gtk::HeaderBar {
              pack_start: model.open_button.widget(),
            },
            gtk::Box {
                set_orientation: gtk::Orientation::Horizontal,
                set_spacing: 5,
                gtk::Box {
                    set_orientation: gtk::Orientation::Vertical,
                    set_spacing: 5,

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
        let open_button = OpenButton::builder()
            .launch(OpenButtonSettings {
                dialog_settings: OpenDialogSettings::default(),
                text: "Open file",
                recently_opened_files: Some(".recent_files"),
                max_recent_files: 10,
            })
            .forward(sender.input_sender(), Msg::Open);
        let model = App { open_button };
        let widgets = view_output!();

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, _: ComponentSender<Self>) {
        match msg {
            Msg::Open(path) => {
                println!("* Opened file {path:?} *");
            }
        }
    }
}

fn main() {
    let app = RelmApp::new("relm4.example.simple");
    app.run::<App>(());
}
