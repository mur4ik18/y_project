use gtk::prelude::*;
use relm4::{
    factory, gtk, Component, ComponentController, ComponentParts, ComponentSender, Controller,
    RelmApp, SimpleComponent, typed_view::list::{RelmListItem, TypedListView},
};


use relm4::factory::{
    positions::GridPosition, DynamicIndex, FactoryComponent, FactorySender, FactoryVecDeque,
    FactoryVecDequeConnector, Position,
};

#[derive(Debug)]
struct MVLine {
    address: String,
    value:Vec<String>,
}

impl MVLine{
    fn new(address: String, value: Vec<String>) -> Self {
        Self { address,value}
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
    c1: gtk::Label,
    c2: gtk::Label,
    c3: gtk::Label,
    c4: gtk::Label,
    c5: gtk::Label,
    c6: gtk::Label,
    c7: gtk::Label,
    c8: gtk::Label,
    c9: gtk::Label,
    c10: gtk::Label,
    c11: gtk::Label,
    c12: gtk::Label,
    c13: gtk::Label,
    c14: gtk::Label,
    c15: gtk::Label,
    c16: gtk::Label,
    
}

impl RelmListItem for MVLine {
    type Root = gtk::Box;
    type Widgets = MVLWidgets;

    fn setup(_item: &gtk::ListItem) -> (gtk::Box, MVLWidgets) {
        relm4::view! {
            my_box = gtk::Box {
                set_valign: gtk::Align::Center,
                // set_halign: gtk::Align::Fill,
                #[name="label"]
                gtk::Label{
                    set_width_request: 50,
                    set_selectable: false,
                },
                gtk::Box  {
                    set_halign: gtk::Align::End,
                    
                    #[name="c1"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                    #[name="c2"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                    #[name="c3"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                    #[name="c4"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                    #[name="c5"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                    #[name="c6"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                    #[name="c7"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                    #[name="c8"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                    #[name="c9"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                    #[name="c10"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                    #[name="c11"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                    #[name="c12"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                    #[name="c13"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                    #[name="c14"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                    #[name="c15"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                    #[name="c16"]
                    gtk::Label {
                        set_width_request: 22,
                    },
                }
                 
                 

            },
        }
        let widgets = MVLWidgets {
            label,
            c1,
            c2,
            c3,
            c4,
            c5,
            c6,
            c7,
            c8,
            c9,
            c10,
            c11,
            c12,
            c13,
            c14,
            c15,
            c16,
        };

        (my_box, widgets)
    }

    
    fn bind(&mut self, widgets: &mut Self::Widgets, _root: &mut Self::Root) {
        let MVLWidgets {
            label,
            c1,
            c2,
            c3,
            c4,
            c5,
            c6,
            c7,
            c8,
            c9,
            c10,
            c11,
            c12,
            c13,
            c14,
            c15,
            c16,
        } = widgets;

        label.set_label(&format!("{} ", self.address));
        c1.set_label(&format!("{} ", self.value[0]));
        c2.set_label(&format!("{} ", self.value[1]));
        c3.set_label(&format!("{} ", self.value[2]));
        c4.set_label(&format!("{} ", self.value[3]));
        c5.set_label(&format!("{} ", self.value[4]));
        c6.set_label(&format!("{} ", self.value[5]));
        c7.set_label(&format!("{} ", self.value[6]));
        c8.set_label(&format!("{} ", self.value[7]));
        c9.set_label(&format!("{} ", self.value[8]));
        c10.set_label(&format!("{} ", self.value[9]));
        c11.set_label(&format!("{} ", self.value[10]));
        c12.set_label(&format!("{} ", self.value[11]));
        c13.set_label(&format!("{} ", self.value[12]));
        c14.set_label(&format!("{} ", self.value[13]));
        c15.set_label(&format!("{} ", self.value[14]));
        c16.set_label(&format!("{} ", self.value[15]));
        
    }
}

#[derive(Debug)]
pub struct MemoryView {
    created_lines: u64,
    lines : TypedListView<MVLine, gtk::MultiSelection>,
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

            gtk::ScrolledWindow {
                set_min_content_height: 400,
                set_max_content_height: 300, 
                // set_vexpand: true, 
                set_min_content_width: 420,
                set_overlay_scrolling: false,
                        
                //set_placement: gtk::CornerType::BottomRight,
                set_overlay_scrolling: false,
                set_has_frame: true,
                #[local_ref]
                linebox -> gtk::ListView {
                    set_orientation: gtk::Orientation::Vertical,
                    set_enable_rubberband: false,
                    set_show_separators: true,
                    set_valign: gtk::Align::Center,
                    //set_height_request: 500,
                    //set_vexpand: true,
                    //set_valign: gtk::Align::Fill,
                },
          
            
        }
    }

    fn init(
        counter: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let mut lines = TypedListView::new();

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
                let leng: usize = v.len();
                let stopper : bool= true;
                let mut i: usize  = 0;
                while stopper
                {
                    let mut res: Vec<String> = Vec::<String>::new();
                    for j in i..i+16 {
                        if j >= leng {
                            res.push("".to_string());
                        }
                        else {
                            res.push(format!("{:02x} ", v[j]));
                        }
                        
                    }
                    self.lines.append(MVLine::new(format!("{:06x} ", i), res));
                    i+= 16;
                    if i >= leng {break;}
                }
                
                    // if (self.created_lines%16==0) {
                    //     self.lines.append(MVLine::new(format!("{:06x} ", i), self));
                    //     i+=16;
                    // }
                    //self.lines.append(MVLine::new(format!("{:02x} ", j)));
                    //self.created_lines = self.created_lines.wrapping_add(1);
            }
            MViewMsg::None => {}
        }
    }
}
