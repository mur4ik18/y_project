use std::env;
use std::fs;


fn main() {
    println!("I will open file");
    let file_path = "test.txt";

    let content = fs::read_to_string(file_path)
    .expect("Should have been able to read the file");

    println!("With text:\n{content}");
}
