//pub mod memoryview_component;
use gtk::prelude::*;
//use memoryview_component::MemoryView;

use relm4::{
    factory, gtk, Component, ComponentController, ComponentParts, ComponentSender, Controller,
    RelmApp, SimpleComponent,
};
use relm4_components::open_button::{OpenButton, OpenButtonSettings};
use relm4_components::open_dialog::OpenDialogSettings;
use std::path::PathBuf;
use y_project;

use gtk::prelude::*;
//use gtk::prelude::{BoxExt, ButtonExt, GtkWindowExt, OrientableExt};
use relm4::factory::{
    DynamicIndex, FactoryComponent, FactorySender, FactoryVecDeque, FactoryVecDequeConnector,
};
//use relm4::*;
//use relm4::{ComponentParts, ComponentSender, RelmApp, RelmWidgetExt, SimpleComponent};

#[derive(Debug)]
struct MVLine {
    value: String,
    //address: u64,
}

#[derive(Debug)]
enum MVLineMsg {}

#[derive(Debug)]
enum MVLineOutput {
    None,
}

#[relm4::factory]
impl factory::FactoryComponent for MVLine {
    type Init = String;
    type Input = MVLineMsg;
    type Output = MVLineOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::Box;

    view! {
        #[root]
        gtk::Box {
            set_orientation: gtk::Orientation::Horizontal,
            set_spacing: 10,
            gtk::Label::new(Some(self.value.as_str())),


            //#[name = "list"]
            //gtk::ListBox,
        }
    }

    fn init_model(
        value: Self::Init,
        _index: &factory::DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self { value }
    }
}

#[derive(Debug)]
struct MemoryView {
    created_lines: u64,
    lines: FactoryVecDeque<MVLine>,
    // max_address: u64,
}

#[derive(Debug)]
enum MViewMsg {
    Draw,
    None,
}

#[derive(Debug)]
enum MViewOutput {
    None,
}

#[relm4::component]
impl SimpleComponent for MemoryView {
    type Init = u64;
    type Input = MViewMsg;
    type Output = MViewOutput;

    view! {
        gtk::Box {
            gtk::Button {
                set_label: "tap",
                connect_clicked => MViewMsg::Draw,

            },
            #[local_ref]
            linebox -> gtk::Box {},
        }
    }

    fn init(
        counter: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let lines = FactoryVecDeque::builder()
            .launch(gtk::Box::default())
            .forward(sender.input_sender(), |msg| match msg {
                MVLineOutput::None => MViewMsg::None,
            });

        let model = MemoryView {
            created_lines: counter,
            lines,
        };
        let linebox = model.lines.widget();
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, _sender: ComponentSender<Self>) {
        let mut lines_guard = self.lines.guard();
        match msg {
            MViewMsg::Draw => {
                lines_guard.push_back(String::from("0F"));
                self.created_lines = self.created_lines.wrapping_add(1);
            }
            MViewMsg::None => {}
        }
    }
}

struct App {
    // button what we use for file opening
    open_button: Controller<OpenButton>,
    // binary
    bindata: Vec<u8>,
    //bin_view: Component<gtk::TextView>,
    bin_buffer: gtk::TextBuffer,

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
                       // #[wrap(Some)]
                       // set_child = &gtk::TextView {
                       //     set_wrap_mode: gtk::WrapMode::Word,
                            // set buffer
                       //     set_buffer: Some(&model.bin_buffer),

                            // Is visible when you open new file
                            //#[watch]
                            //set_visible: model.bindata.is_some(),
                       // }
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
            bin_buffer: gtk::TextBuffer::new(None),
            memory_view_component: memview,
        };

        let line_list = model.memory_view_component.widget();
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
            Msg::None => {}
        }
    }
}

fn main() {
    let app = RelmApp::new("relm4.example.simple");
    app.run::<App>(());
}
