use gtk::prelude::*;
use relm4::{
    factory, gtk, Component, ComponentController, ComponentParts, ComponentSender, Controller,
    RelmApp, SimpleComponent, typed_view::grid::{RelmGridItem, TypedGridView},
};


use relm4::factory::{
    positions::GridPosition, DynamicIndex, FactoryComponent, FactorySender, FactoryVecDeque,
    FactoryVecDequeConnector, Position,
};

#[derive(Debug)]
struct MVLine {
    value: String,
}

impl MVLine {
    fn new(value: String) -> Self {
        Self {value}
    }
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

impl RelmGridItem for MVLine {
    type Root = gtk::Box;
    type Widgets = MVLWidgets;

    fn setup(_item: &gtk::ListItem) -> (gtk::Box, MVLWidgets) {
        relm4::view! {
            my_box = gtk::Box {
                #[name="label"]
                gtk::Label,
            },
        }
        let widgets = MVLWidgets {
            label,
        };

        (my_box, widgets)
    }

    
    fn bind(&mut self, widgets: &mut Self::Widgets, _root: &mut Self::Root) {
        let MVLWidgets {
            label,
        } = widgets;

        label.set_label(&format!("{} ", self.value));
    }
}

#[derive(Debug)]
pub struct MemoryView {
    created_lines: u64,
    lines : TypedGridView<MVLine, gtk::MultiSelection>,
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
            linebox -> gtk::GridView {
                set_orientation: gtk::Orientation::Vertical,
                set_min_columns: 16,
                set_enable_rubberband: true,
                },
        }
    }

    fn init(
        counter: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let mut lines = TypedGridView::new();

        let model = MemoryView {
            created_lines: counter,
            lines,
        };
        let linebox = &model.lines.view;
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, _: ComponentSender<Self>) {
        match msg {
            MViewMsg::Draw(v) => {
                let mut i = 0;
                for j in v {
                    if (self.created_lines%16==0) {
                        self.lines.append(MVLine::new(format!("{:06x} ", i)));
                        i+=16;
                    }
                    self.lines.append(MVLine::new(format!("{:02x} ", j)));
                    self.created_lines = self.created_lines.wrapping_add(1);
                }
            }
            MViewMsg::None => {}
        }
    }
}
