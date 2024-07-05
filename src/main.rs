use std::env;
use std::fs;

// context
struct Ctx {
    filename: String,
    byte: bool,
}

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

#[allow(dead_code)]
#[derive(Debug)]
struct MZHeader<'a> {
    magic: &'a [u8],
    extra_bytes: &'a [u8],
    pages: &'a [u8],
    entries_relocation_table: &'a [u8],
    header_size: &'a [u8],
    min_alloc: &'a [u8],
    max_alloc: &'a [u8],
    initial_ss: &'a [u8],
    initial_sp: &'a [u8],
    checksum: &'a [u8],
    initial_ip: &'a [u8],
    initial_cs: &'a [u8],
    reloc_table_address: &'a [u8],
    overlay: &'a [u8],
    pe_offset: usize,
}

#[allow(dead_code)]
#[derive(Debug)]
struct PEHeader<'a> {
    magic: &'a [u8],
    machine: &'a [u8],
    section_count: &'a [u8],
    timestamp: &'a [u8],
    symbol_table_pointer: usize,
    symbol_count: u32,
    optional_header_size: &'a [u8],
    characteristics: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct DataDirectory<'a> {
    virtual_address: &'a [u8],
    size: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct OptionalHeader<'a> {
    magic: &'a [u8],
    major_linker_version: &'a [u8],
    minor_linker_version: &'a [u8],
    code_size: &'a [u8],
    initialized_data_size: &'a [u8],
    uninitialized_data_size: &'a [u8],
    entry_point_address: &'a [u8],
    base_of_code: &'a [u8],
    base_of_data: &'a [u8],
    image_base: &'a [u8],
    section_alignment: &'a [u8],
    file_alignment: &'a [u8],
    major_os_version: &'a [u8],
    minor_os_version: &'a [u8],
    major_image_version: &'a [u8],
    minor_image_version: &'a [u8],
    major_subsystem_version: &'a [u8],
    minor_subsystem_version: &'a [u8],
    win32_version_value: &'a [u8],
    image_size: &'a [u8],
    headers_size: &'a [u8],
    checksum: &'a [u8],
    subsystem: &'a [u8],
    dll_characteristics: &'a [u8],
    stack_reserve_size: &'a [u8],
    stack_commit_size: &'a [u8],
    heap_reserve_size: &'a [u8],
    heap_commit_size: &'a [u8],
    loader_flags: &'a [u8],
    number_of_rva_and_sizes: &'a [u8],
    data_directory: DataDirectory<'a>,
}

#[allow(dead_code)]
#[derive(Debug)]
struct PEFile<'a> {
    mz_header: MZHeader<'a>,
    pe_header: PEHeader<'a>,
    optional_header: OptionalHeader<'a>,
}

#[allow(dead_code)]
#[derive(Debug)]
struct Symbol<'a> {
    name: String,
    value: &'a [u8],
    section_number: &'a [u8],
    data_type: &'a [u8],
    storage_class: &'a [u8],
    number_aux_symbols: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct SymbolTable<'a> {
    symbols:  Vec<Symbol<'a>>,
}


/************************************************************************************/
/******************************** ELF structure *************************************/
/************************************************************************************/

#[allow(dead_code)]
#[derive(Debug)]
struct ELFIdentification<'a> {
    magic: &'a [u8],
    class: &'a [u8],
    data: &'a [u8],

    version: &'a [u8],
    os_abi: &'a [u8],
    abi_version: &'a [u8],
    padding: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct ELFHeader<'a> {
    file_type: &'a [u8],
    machine: &'a [u8],
    version: &'a [u8],
    entry_point: &'a [u8],
    program_header_offset: &'a [u8],
    section_header_offset: &'a [u8],
    flags: &'a [u8],
    header_size: &'a [u8],
    program_header_entry_size: &'a [u8],
    program_header_entry_count: &'a [u8],
    section_header_entry_size: &'a [u8],
    section_header_entry_count: &'a [u8],
    section_name_string_table_index: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct FileInfoELF<'a> {
    identification: ELFIdentification<'a>,
    header: ELFHeader<'a>,
}

/***************************************************************************************/
/******************************** Mach-O structure *************************************/
/***************************************************************************************/
#[allow(dead_code)]
#[derive(Debug)]
struct MachOHeader<'a> {
    magic: &'a [u8],
    cputype: &'a [u8],
    cpusubtype: &'a [u8],
    ftype: &'a [u8],
    lcnum: &'a [u8],
    lcsize: &'a [u8],
    flags: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct LoadCommand<'a> {
    cmd: &'a [u8],
    cmdsize: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct SegmentCommand<'a> {
    load_cmd: LoadCommand <'a>,
    segname: &'a [u8],
    vmaddr: &'a [u8],
    vmsize: &'a [u8],
    fileoff: &'a [u8],
    filesize: &'a [u8],
    maxprot: &'a [u8],
    initprot: &'a [u8],
    nsects: &'a [u8],
    flags: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct DylibCommand<'a> {
    load_cmd: LoadCommand <'a>,
    name_offset: &'a [u8],
    timestamp: &'a [u8],
    current_version: &'a [u8],
    compatibility_version: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct SymtabCommand<'a> {
    load_cmd: LoadCommand <'a>,
    symoff: &'a [u8],
    nsyms: &'a [u8],
    stroff: &'a [u8],
    strsize: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct SymsegCommand<'a> {
    load_cmd: LoadCommand <'a>,
    offset: &'a [u8],
    size: &'a [u8]
}

#[allow(dead_code)]
#[derive(Debug)]

struct EntryPointCommand<'a>{
    load_cmd: LoadCommand <'a>,
    entryoff: &'a [u8],
    stacksize: &'a [u8]
}



#[allow(dead_code)]
enum LoadCommandData<'a> {
    Segment(SegmentCommand<'a>),
    Symtab(SymtabCommand<'a>),
    Dymlib(DylibCommand<'a>)
}

/***************************************************************************************/
/******************************** JVM structure ****************************************/
/***************************************************************************************/

#[allow(dead_code)]
#[derive(Debug)]
struct ClassFile<'a> {
    magic: &'a [u8],
    minor_version: &'a [u8],
    major_version: &'a [u8],
    pool_count: &'a [u8],
    //todo add pool struct
    access_flags: &'a [u8],
    this_class: &'a [u8],
    super_class: &'a [u8],
    interfaces_count: &'a [u8],
    //todo add interfaces struct
    fields_count: &'a [u8],
    //todo add field struct
    method_count: &'a [u8],
    //todo add method struct
    attributes_count: &'a [u8],
    //todo add attribute struct
}




fn reverse_bytes<T: Clone>(slice: &[T]) -> Vec<T> {
    slice.iter().cloned().rev().collect()
}

fn read_file(file_path: &String) -> Vec<u8> {
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
            let pe_offset = u32::from_le_bytes([
                pe_offset_bytes[0],
                pe_offset_bytes[1],
                pe_offset_bytes[2],
                pe_offset_bytes[3],
            ]) as usize;

            let file_info: MZHeader = MZHeader {
                magic: &bytes[0..2],
                extra_bytes: &bytes[2..4],
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
            let symbol_table_offset_bytes = &bytes[pe_offset + 12..pe_offset + 16];
            let symbol_table_pointer = u32::from_le_bytes([
                symbol_table_offset_bytes[0],
                symbol_table_offset_bytes[1],
                symbol_table_offset_bytes[2],
                symbol_table_offset_bytes[3],
            ]) as usize;

            let symbol_count_bytes = &bytes[pe_offset + 16..pe_offset + 20];
            let symbol_count = u32::from_le_bytes([
                symbol_count_bytes[0],
                symbol_count_bytes[1],
                symbol_count_bytes[2],
                symbol_count_bytes[3],
            ]);

            let file_info_pe: PEHeader = PEHeader {
                magic: &bytes[pe_offset..pe_offset + 4],
                machine: &bytes[pe_offset + 4..pe_offset + 6],
                section_count: &bytes[pe_offset + 6..pe_offset + 8],
                timestamp: &bytes[pe_offset + 8..pe_offset + 12],
                symbol_table_pointer: symbol_table_pointer,
                symbol_count: symbol_count,
                optional_header_size: &bytes[pe_offset + 20..pe_offset + 22],
                characteristics: &bytes[pe_offset + 22..pe_offset + 24],
            };

            let mut symbol_table = SymbolTable{
                symbols: Vec::new(),
            };
                
            let mut offset:usize = 0;
            for _i in 0..file_info_pe.symbol_count {
                let name_bytes = &bytes[file_info_pe.symbol_table_pointer + offset..file_info_pe.symbol_table_pointer + 8 + offset];
                let name = String::from_utf8_lossy(name_bytes).trim_end_matches('\0').to_string();

                symbol_table.symbols.push(Symbol {
                    name,
                    value: &bytes[symbol_table_pointer + 8 + offset..symbol_table_pointer + 12 + offset],
                    section_number: &bytes[symbol_table_pointer + 12 + offset..symbol_table_pointer + 14 + offset],
                    data_type: &bytes[symbol_table_pointer + 14 + offset..symbol_table_pointer + 16 + offset],
                    storage_class: &bytes[symbol_table_pointer + 16 + offset..symbol_table_pointer + 17 + offset],
                    number_aux_symbols: &bytes[symbol_table_pointer + 17 + offset..symbol_table_pointer + 18 + offset],
                });
                offset += 18;
            }
            //TODO: Verify if assumtpions are correct

            println!("File Infos: {:?} {:?} {:?}", file_info, file_info_pe, symbol_table);
        }
        "Executable and Linkable Format (ELF)" => {
            let file_info_identification: ELFIdentification = ELFIdentification {
                magic: &bytes[0..4],
                class: &bytes[4..5],
                data: &bytes[5..6],
                version: &bytes[6..7],
                os_abi: &bytes[7..8],
                abi_version: &bytes[8..9],
                padding: &bytes[9..16],
            };
            let file_info_header = if file_info_identification.class == b"\x01" {
                ELFHeader {
                    file_type: &bytes[16..18],
                    machine: &bytes[18..20],
                    version: &bytes[20..22],
                    entry_point: &bytes[22..26],
                    program_header_offset: &bytes[26..30],
                    section_header_offset: &bytes[30..34],
                    flags: &bytes[34..38],
                    header_size: &bytes[38..40],
                    program_header_entry_size: &bytes[40..42],
                    program_header_entry_count: &bytes[42..44],
                    section_header_entry_size: &bytes[44..46],
                    section_header_entry_count: &bytes[46..48],
                    section_name_string_table_index: &bytes[48..50],
                }
            } else {
                ELFHeader {
                    file_type: &bytes[16..18],
                    machine: &bytes[18..20],
                    version: &bytes[20..22],
                    entry_point: &bytes[22..30],
                    program_header_offset: &bytes[30..38],
                    section_header_offset: &bytes[38..46],
                    flags: &bytes[46..50],
                    header_size: &bytes[50..52],
                    program_header_entry_size: &bytes[52..54],
                    program_header_entry_count: &bytes[54..56],
                    section_header_entry_size: &bytes[56..58],
                    section_header_entry_count: &bytes[58..60],
                    section_name_string_table_index: &bytes[60..62],
                }
            };
            let file_info: FileInfoELF = FileInfoELF {
                identification: file_info_identification,
                header: file_info_header,
            };
            println!("File Infos: {:?}", file_info);
            //TODO: Extract Code
        }
        "Mach-O binary (32-bit)" | "Mach-O binary (64-bit)" => {
            let file_info: MachOHeader = MachOHeader {
                magic: &bytes[0..4],
                cputype: &bytes[4..8],
                cpusubtype: &bytes[8..12],
                ftype: &bytes[12..16],
                lcnum: &bytes[16..20],
                lcsize: &bytes[20..24],
                flags: &bytes[24..28],
            };
            println!("File Infos: {:?}", file_info);
            //TODO: Extract code
        }
        "Mach-O binary (reverse byte ordering scheme, 32-bit)"
        | "Mach-O binary (reverse byte ordering scheme, 64-bit)" => {
            let file_info: MachOHeader = MachOHeader {
                magic: &reverse_bytes(&bytes[0..4]),
                cputype: &reverse_bytes(&bytes[4..8]),
                cpusubtype: &reverse_bytes(&bytes[8..12]),
                ftype: &reverse_bytes(&bytes[12..16]),
                lcnum: &reverse_bytes(&bytes[16..20]),
                lcsize: &reverse_bytes(&bytes[20..24]),
                flags: &reverse_bytes(&bytes[24..28]),
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
    let bytecode = read_file(&context.filename);
    let sign = get_sign(&bytecode);
    get_file_data(&sign, &bytecode);
}