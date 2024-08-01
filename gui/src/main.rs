//pub mod memoryview_component;
use gtk::prelude::*;
//use memoryview_component::MemoryView;

use relm4::{
    factory, gtk, Component, ComponentController, ComponentParts, ComponentSender, Controller,
    MessageBroker, RelmApp, SimpleComponent,
};
use relm4_components::open_button::{OpenButton, OpenButtonSettings};
use relm4_components::open_dialog::OpenDialogSettings;
use std::path::PathBuf;
use y_project;

use gtk::prelude::*;
//use gtk::prelude::{BoxExt, ButtonExt, GtkWindowExt, OrientableExt};
use relm4::factory::{
    positions::GridPosition, DynamicIndex, FactoryComponent, FactorySender, FactoryVecDeque,
    FactoryVecDequeConnector, Position,
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

struct MVLWidgets {
    label: gtk::Label,
}

impl Position<GridPosition, DynamicIndex> for MVLine {
    fn position(&self, index: &DynamicIndex) -> GridPosition {
        let index = index.current_index();
        let x = index / 16;
        let y = index % 16;
        GridPosition {
            column: y as i32,
            row: x as i32,
            width: 1,
            height: 1,
        }
    }
}

#[relm4::factory]
impl factory::FactoryComponent for MVLine {
    type Init = String;
    type Input = MVLineMsg;
    type Output = MVLineOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::Grid;

    //type Widgets = MVLWidgets;

    view! {
        #[root]
        gtk::Box {
            gtk::Label::new(Some(self.value.as_str())),
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
    Draw(Vec<u8>),
    None,
}

static DIALOG_BROKER: MessageBroker<MViewMsg> = MessageBroker::new();

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
            #[local_ref]
            linebox -> gtk::Grid {
                    set_orientation: gtk::Orientation::Horizontal,
                    set_column_spacing: 5,
                    set_row_spacing: 5,
                },
        }
    }

    fn init(
        counter: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let lines = FactoryVecDeque::builder()
            .launch(gtk::Grid::default())
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

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        let mut lines_guard = self.lines.guard();
        match msg {
            MViewMsg::Draw(v) => {
                for i in v {
                    lines_guard.push_back(format!("{:02x} ", i));
                    self.created_lines = self.created_lines.wrapping_add(1);
                }
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
