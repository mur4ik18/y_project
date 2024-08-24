use gtk::prelude::*;
use relm4::{ gtk, SimpleComponent, ComponentParts, ComponentSender};

/// GT = Go TO

#[derive(Debug)]
pub struct GoTo {
    entry: gtk::EntryBuffer,
}

#[derive(Debug)]
pub enum GTInp {
    GTGet,
}

#[derive(Debug)]
pub enum GToutput {
    GT(u64),
}

#[relm4::component(pub)]
impl SimpleComponent for GoTo {
    type Init = ();
    type Input = GTInp;
    type Output = GToutput;

    view! {
        gtk::Box {
            #[name="input"]
            gtk::Entry {
                set_tooltip_text: Some("Write Address"),
                set_buffer: &model.entry,
            },
            gtk::Button{
                set_label: "Go-To",
                connect_clicked => GTInp::GTGet,
            },
        }
    }

     fn init(
        counter: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
     ) -> ComponentParts<Self> {
         let model = GoTo {
             entry: gtk::EntryBuffer::default()
         };
         let widgets = view_output!();
         ComponentParts { model, widgets }
     }

    fn update(&mut self, msg: Self::Input, _sender: ComponentSender<Self>) {
        match msg {
            GTInp::GTGet => {
                let value = self.entry.text().to_string();
                _sender.output(GToutput::GT(u64::from_str_radix(value.as_str(), 16).expect("Not a Hex number!")));
            }
        }
    }
}
