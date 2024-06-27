use std::env;
use std::fs;

struct Signature<'a> {
    name: &'a str,
    signature: &'a [u8],
}

const SIGNATURES: [Signature; 6] = [
    Signature {
        name: "DOS MZ executable",
        signature: b"\x4D\x5A",
    },
    Signature {
        name: "DOS ZM executable",
        signature: b"\x5A\x4D",
    },
    Signature {
        name: "Executable and Linkable Format (ELF)",
        signature: b"\x7F\x45\x4C\x46",
    },
    Signature {
        name: "Mach-O binary (32-bit)",
        signature: b"\xFE\xED\xFA\xCE",
    },
    Signature {
        name: "Mach-O binary (64-bit)",
        signature: b"\xFE\xED\xFA\xCF",
    },
    Signature {
        name: "Java class file, Mach-O Fat Binary",
        signature: b"\xCA\xFE\xBA\xBE",
    }
];

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

fn get_sign(file_path: String) {
    let mut buffer = [0; 1024];
    let bytes = fs::read(file_path).unwrap(); 

    let mut offset = 0;
    while offset < bytes.len() {
        let bytes_copy = std::cmp::min(buffer.len(), bytes.len() - offset); 

        buffer[..bytes_copy].copy_from_slice(&bytes[offset..offset + bytes_copy]); 

        for signature in SIGNATURES.iter() {
            if bytes_copy >= signature.signature.len() &&
                &buffer[0..signature.signature.len()] == signature.signature {
                println!("signature trouvee: {}", signature.name);
            }
        }

        offset += bytes_copy;
    }
}

fn main() {
    println!("I will open file");
    let args: Vec<String> = get_arguments();
    read_file(args[1].clone());
    get_sign(args[1].clone());
}