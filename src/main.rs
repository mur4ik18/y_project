use std::env;
use std::fs;

struct Signature<'a> {
    name: &'a str,
    signature: &'a [u8],
}

const SIGNATURES: [Signature; 8] = [
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
        name: "Mach-O binary (reverse byte ordering scheme, 32-bit)",
        signature: b"\xCE\xFA\xED\xFE",
    },
    Signature {
        name: "Mach-O binary (reverse byte ordering scheme, 64-bit)",
        signature: b"\xCF\xFA\xED\xFE",
    },
    Signature {
        name: "Java class file, Mach-O Fat Binary",
        signature: b"\xCA\xFE\xBA\xBE",
    },
];

// context
struct Ctx {
    filename: String,
    byte: bool,
}

fn read_file(file_path: String) -> Vec<u8> {
    let bytes = fs::read(file_path.to_owned()).unwrap();
    for byte in bytes.iter() {
        print!("{:X} ", byte);
    }
    println!();
    bytes
}

fn help() {
    println!(
        "Usage:
-f <filename> - read file
-b            - show output in byte code
"
    );
}

fn get_arguments() -> Ctx {
    let args: Vec<String> = env::args().collect();
    let mut ctx = Ctx {
        filename: String::new(),
        byte: false,
    };
    if args.len() <= 2 {
        eprintln!("Usage: {} -f <filename>", args[0]);
        std::process::exit(1);
    }
    for i in 0..args.len() {
        if args[i] == "-f" {
            ctx.filename = args[i + 1].clone();
        }
        if args[i] == "-b" {
            ctx.byte = true;
        }
        println!("arg {} - {}", i, args[i]);
    }
    ctx
}

fn get_sign(bytes: Vec<u8>) -> String {
    let mut buffer = [0; 1024];

    let mut file_signature: String = String::from("unknown");

    let mut offset = 0;
    while offset < bytes.len() {
        let bytes_copy = std::cmp::min(buffer.len(), bytes.len() - offset);

        buffer[..bytes_copy].copy_from_slice(&bytes[offset..offset + bytes_copy]);

        for signature in SIGNATURES.iter() {
            if bytes_copy >= signature.signature.len()
                && &buffer[0..signature.signature.len()] == signature.signature
            {
                file_signature = String::from(signature.name);
            }
        }

        offset += bytes_copy;
    }
    println!("signature trouvee: {}", file_signature);
    file_signature
}

fn get_file_data(file_path: String, file_signature: &str) {
    match file_signature {
        "DOS MZ executable" => {
            //TODO: Search infos
        }
        "DOS ZM executable" => {
            //TODO: Search infos
        }
        "Executable and Linkable Format (ELF)" => {
            //TODO: Search infos
        }
        "Mach-O binary (32-bit)" => {
            //TODO: Search infos
        }
        "Mach-O binary (64-bit)" => {
            //TODO: Search infos
        }
        "Mach-O binary (reverse byte ordering scheme, 32-bit)" => {
            //TODO: Search infos
        }
        "Mach-O binary (reverse byte ordering scheme, 64-bit)" => {
            //TODO: Search infos
        }
        "Java class file, Mach-O Fat Binary" => {
            //TODO: Search infos
        }
        _ => {}
    }
}

fn main() {
    help();
    let context: Ctx = get_arguments();
    let bytecode = read_file(context.filename);
    get_sign(bytecode);
}
