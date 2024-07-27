use gtk::prelude::*;
use relm4::prelude::*;
struct App {}

#[derive(Debug)]
enum Msg {
    OpenFile,
}

#[relm4::component]
impl SimpleComponent for App {
    type Init = u8;
    type Input = Msg;
    type Output = ();

    view! {
        main_window = gtk::ApplicationWindow {
            set_title: Some("App"),
            set_default_size: (600, 200),

            gtk::Box {
                set_orientation: gtk::Orientation::Horizontal,
                set_spacing: 5,
                set_margin_all: 5,
                gtk::Box {
                    set_orientation: gtk::Orientation::Horizontal,
                    set_spacing: 5,
                    gtk::Button {
                        set_label: "Choose file",
                        connect_clicked => Msg::OpenFile,
                    }
                },
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
        let model = App {};

        // Insert the code generation of the view! macro here
        let widgets = view_output!();

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, _sender: ComponentSender<Self>) {
        match msg {
            Msg::OpenFile => {
                println!("Open File");
                let input_path_chooser = gtk::FileChooserDialog::builder()
                    .title("Select file")
                    .action(gtk::FileChooserAction::Open)
                    .modal(true)
                    //.select_multiple(true)
                    .build();

                input_path_chooser.add_button("Select", gtk::ResponseType::Accept);
                input_path_chooser.add_button("Cancel", gtk::ResponseType::Cancel);
                input_path_chooser.run_async(move |dialog, result| {
                    match result {
                        gtk::ResponseType::Accept => {
                            if let Some(file) = dialog.file() {
                                if let Some(path) = file.path() {
                                    println!("Selected file: {:?}", path);
                                } else {
                                    println!("No valid path found for the selected file.");
                                }
                            } else {
                                println!("No file selected.");
                            }
                        }
                        _ => println!("File selection cancelled."),
                    }
                    dialog.destroy();
                })
            }
        }
    }
}

fn main() {
    let app = RelmApp::new("relm4.example.simple");
    app.run::<App>(0);
}
