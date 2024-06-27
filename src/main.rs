use std::env;
use std::fs;

fn read_file(file_path: String) {
    let bytes = fs::read(file_path.to_owned()).unwrap();
    for byte in bytes.iter() {
        print!("{:X} ", byte);
    }
    println!();
}

fn get_arguments() -> Vec<String> {
    let args: Vec<String> = env::args().collect();
    args
    //println!("Paht : {file_path}");
    //file_path
}

fn main() {
    println!("I will open file");
    let args: Vec<String> = get_arguments();
    read_file(args[1].clone());
}
