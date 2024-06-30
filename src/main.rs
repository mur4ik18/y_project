use std::env;
use std::fs;

/**************************************************************************************/
/******************************** File Signatures *************************************/
/**************************************************************************************/

struct Signature<'a> {
    name: &'a str,
    signature: &'a [u8],
}

const SIGNATURES: [Signature; 7] = [
    Signature {
        name: "DOS MZ executable",
        signature: b"\x4D\x5A",
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

/***********************************************************************************/
/******************************** PE structure *************************************/
/***********************************************************************************/

#[derive(Debug)]
struct FileInfosMZHeader<'a> {
    magic: &'a[u8],
    extra_bytes: &'a[u8],
    pages: &'a[u8],
    entries_relocation_table: &'a[u8],
    header_size: &'a[u8],
    min_alloc: &'a[u8],
    max_alloc: &'a[u8],
    initial_ss: &'a[u8],
    initial_sp: &'a[u8],
    checksum: &'a[u8],
    initial_ip: &'a[u8],
    initial_cs: &'a[u8],
    reloc_table_address: &'a[u8],
    overlay: &'a[u8],
    pe_offset: usize,
}


#[derive(Debug)]
struct FileInfosPEHeader<'a> {
    pe_magic: &'a[u8],
    pe_machine: &'a[u8],
    pe_section_nbr: &'a[u8],
    pe_time_date_stamp: &'a[u8],
    pe_ptr_symbol_table: &'a[u8],
    pe_symbol_nbr: &'a[u8],
    pe_size_opt_header: &'a[u8],
    pe_characteristics: &'a[u8],
}

#[derive(Debug)]
struct FileInfosPEOptionalHeaderDataDirectory<'a> {
    pf_virtual_address: &'a[u8],
    pf_size: &'a[u8],
}

#[derive(Debug)]
struct FileInfosPEOptionalHeader<'a> {
    pb_magic: &'a[u8],
    pb_major_lv: &'a[u8],
    pb_minor_lv: &'a[u8],
    pb_size_code: &'a[u8],
    pb_size_init_data: &'a[u8],
    pb_size_uinit_data: &'a[u8],
    pb_entry_point: &'a[u8],
    pb_code_base: &'a[u8],
    pb_data_base: &'a[u8],
    pb_image_base: &'a[u8],
    pb_section_align: &'a[u8],
    pb_file_align: &'a[u8],
    pb_major_os_version: &'a[u8],
    pb_minor_os_version: &'a[u8],
    pb_major_img_version: &'a[u8],
    pb_minor_img_version: &'a[u8],
    pb_major_subsystem_version: &'a[u8],
    pb_minor_subsystem_version: &'a[u8],
    pb_win32_version_value: &'a[u8],
    pb_img_size: &'a[u8],
    pb_headers_size: &'a[u8],
    pb_checksum: &'a[u8],
    pb_subsystem: &'a[u8],
    pb_dll_characteristics: &'a[u8],
    pb_size_stack_reserve: &'a[u8],
    pb_size_stack_commit: &'a[u8],
    pb_size_heap_reserve: &'a[u8],
    pb_size_heap_commit: &'a[u8],
    pb_loader_flags: &'a[u8],
    pb_nbr_rva_and_sizes: &'a[u8],
    pb_data_directory: FileInfosPEOptionalHeaderDataDirectory <'a>
}

#[derive(Debug)]
struct FileInfosPE<'a> {
    mz_header: FileInfosMZHeader <'a>,
    pe_header: FileInfosPEHeader <'a>,
    pe_optional_header: FileInfosPEOptionalHeader <'a>,
}

/************************************************************************************/
/******************************** ELF structure *************************************/
/************************************************************************************/

#[derive(Debug)]
struct FileInfoELFIdentification<'a> {
    ei_mag: &'a[u8],
    ei_class: &'a[u8],
    ei_data: &'a[u8],
    ei_version: &'a[u8],
    ei_osabi: &'a[u8],
    ei_abiversion: &'a[u8],
    ei_pad: &'a[u8]
}

#[derive(Debug)]
struct FileInfoELFHeader<'a> {
    e_type: &'a[u8],
    e_machine: &'a[u8],
    e_version: &'a[u8],
    e_entry: &'a[u8],
    e_phoff: &'a[u8],
    e_shoff: &'a[u8],
    e_flags: &'a[u8],
    e_ehsize: &'a[u8],
    e_phentsize: &'a[u8],
    e_phnum: &'a[u8],
    e_shentsize: &'a[u8],
    e_shnum: &'a[u8],
    e_shstrndx: &'a[u8],
}

#[derive(Debug)]
struct FileInfoELF<'a> {
    identification: FileInfoELFIdentification<'a>,
    header: FileInfoELFHeader<'a>,
}

/***************************************************************************************/
/******************************** Mach-O structure *************************************/
/***************************************************************************************/
#[derive(Debug)]
struct FileInfoMachO<'a> {
    e_magic: &'a [u8],
    e_cputype: &'a [u8],
    e_cpusubtype: &'a [u8],
    e_ftype: &'a [u8],
    e_lcnum: &'a [u8],
    e_lcsize: &'a [u8],
    e_flags: &'a [u8],
}



fn reverse_bytes<T: Clone>(slice: &[T]) -> Vec<T> {
    slice.iter().cloned().rev().collect()
}

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

fn get_sign(bytes: &[u8]) -> String {
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

fn get_file_data(file_signature: &str, bytes: &[u8]) {
    match file_signature {
        "DOS MZ executable" => {
            let pe_offset_bytes = &bytes[60..64];
            let pe_offset = u32::from_le_bytes([pe_offset_bytes[0], pe_offset_bytes[1], pe_offset_bytes[2], pe_offset_bytes[3]]) as usize;

            let file_info: FileInfosMZHeader = FileInfosMZHeader {
                magic:  &bytes[0..2],
                extra_bytes:  &bytes[2..4],
                pages: &bytes[4..6],
                entries_relocation_table: &bytes[6..8],
                header_size: &bytes[8..10],
                min_alloc: &bytes[10..12],
                max_alloc: &bytes[12..14],
                initial_ss: &bytes[14..16],
                initial_sp: &bytes[16..18],
                checksum: &bytes[18..20],
                initial_ip: &bytes[20..22],
                initial_cs: &bytes[22..24],
                reloc_table_address: &bytes[24..26],
                overlay: &bytes[26..28],
                pe_offset,
            };

            let file_info_pe: FileInfosPEHeader = FileInfosPEHeader {
                pe_magic: &bytes[pe_offset..pe_offset+4],
                pe_machine: &bytes[pe_offset+4..pe_offset+6],
                pe_section_nbr: &bytes[pe_offset+6..pe_offset+8],
                pe_time_date_stamp: &bytes[pe_offset+8..pe_offset+12],
                pe_ptr_symbol_table: &bytes[pe_offset+12..pe_offset+16],
                pe_symbol_nbr: &bytes[pe_offset+16..pe_offset+20],
                pe_size_opt_header: &bytes[pe_offset+20..pe_offset+22],
                pe_characteristics: &bytes[pe_offset+22..pe_offset+24],
            };

            println!("File Infos: {:?} {:?}", file_info, file_info_pe);
        }
        "Executable and Linkable Format (ELF)" => {
            let file_info_identification: FileInfoELFIdentification = FileInfoELFIdentification {
                ei_mag: &bytes[0..4],
                ei_class: &bytes[4..5],
                ei_data: &bytes[5..6],
                ei_version: &bytes[6..7],
                ei_osabi: &bytes[7..8],
                ei_abiversion: &bytes[8..9],
                ei_pad: &bytes[9..16],
            };
            let file_info_header = if file_info_identification.ei_class == b"\x01" {
                FileInfoELFHeader {
                    e_type: &bytes[16..18],
                    e_machine: &bytes[18..20],
                    e_version: &bytes[20..22],
                    e_entry: &bytes[22..26],
                    e_phoff: &bytes[26..30], 
                    e_shoff: &bytes[30..34],
                    e_flags: &bytes[34..38],
                    e_ehsize: &bytes[38..40],
                    e_phentsize: &bytes[40..42],
                    e_phnum: &bytes[42..44],
                    e_shentsize: &bytes[44..46],
                    e_shnum: &bytes[46..48],
                    e_shstrndx: &bytes[48..50],
                }
            } else {
                FileInfoELFHeader {
                    e_type: &bytes[16..18],
                    e_machine: &bytes[18..20],
                    e_version: &bytes[20..22],
                    e_entry: &bytes[22..30],
                    e_phoff: &bytes[30..38],
                    e_shoff: &bytes[38..46],
                    e_flags: &bytes[46..50],
                    e_ehsize: &bytes[50..52],
                    e_phentsize: &bytes[52..54],
                    e_phnum: &bytes[54..56],
                    e_shentsize: &bytes[56..58],
                    e_shnum: &bytes[58..60],
                    e_shstrndx: &bytes[60..62],
                }
            };
            let file_info: FileInfoELF = FileInfoELF{
                identification: file_info_identification,
                header: file_info_header,
            };
            println!("File Infos: {:?}", file_info);
            
        }
        "Mach-O binary (32-bit)" | "Mach-O binary (64-bit)" => {
            let file_info: FileInfoMachO = FileInfoMachO {
                e_magic: &bytes[0..4],
                e_cputype: &bytes[4..8],
                e_cpusubtype: &bytes[8..12],
                e_ftype: &bytes[12..16],
                e_lcnum: &bytes[16..20],
                e_lcsize: &bytes[20..24],
                e_flags: &bytes[24..28],
            };
            println!("File Infos: {:?}", file_info);
        }
        "Mach-O binary (reverse byte ordering scheme, 32-bit)" | "Mach-O binary (reverse byte ordering scheme, 64-bit)" => {
            let file_info: FileInfoMachO = FileInfoMachO {
                e_magic: &reverse_bytes(&bytes[0..4]),
                e_cputype: &reverse_bytes(&bytes[4..8]),
                e_cpusubtype: &reverse_bytes(&bytes[8..12]),
                e_ftype: &reverse_bytes(&bytes[12..16]),
                e_lcnum: &reverse_bytes(&bytes[16..20]),
                e_lcsize: &reverse_bytes(&bytes[20..24]),
                e_flags: &reverse_bytes(&bytes[24..28]),
            };
            println!("File Infos: {:?}", file_info);
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
    let sign = get_sign(&bytecode);
    get_file_data(&sign, &bytecode);
}
