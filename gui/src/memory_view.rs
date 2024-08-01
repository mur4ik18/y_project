use gtk::prelude::*;
use relm4::{
    factory, gtk, Component, ComponentController, ComponentParts, ComponentSender, Controller,
    RelmApp, SimpleComponent,
};

use relm4::factory::{
    positions::GridPosition, DynamicIndex, FactoryComponent, FactorySender, FactoryVecDeque,
    FactoryVecDequeConnector, Position,
};

#[derive(Debug)]
struct MVLine {
    value: String,
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
pub struct MemoryView {
    created_lines: u64,
    lines: FactoryVecDeque<MVLine>,
    // max_address: u64,
}

#[derive(Debug)]
pub enum MViewMsg {
    Draw(Vec<u8>),
    None,
}


#[derive(Debug)]
pub enum MViewOutput {
    None,
}

#[relm4::component(pub)]
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
