use std::env;
use std::fs;
use std::convert::TryInto;

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
struct DOSHeader<'a> {
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
struct COFFHeader<'a> {
    magic: &'a [u8],
    machine: &'a [u8],
    section_count: usize,
    timestamp: &'a [u8],
    symbol_table_pointer: usize,
    symbol_count: usize,
    optional_header_size: usize,
    characteristics: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct DataDirectoryEntry<'a> {
    virtual_address: &'a [u8],
    size: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct DataDirectory<'a> {
    export_table: DataDirectoryEntry<'a>,
    import_table: DataDirectoryEntry<'a>,
    resource_table: DataDirectoryEntry<'a>,
    exception_table: DataDirectoryEntry<'a>,
    certificate_table: DataDirectoryEntry<'a>,
    base_relocation_table: DataDirectoryEntry<'a>,
    debug: DataDirectoryEntry<'a>,
    architecture: DataDirectoryEntry<'a>,
    global_ptr: DataDirectoryEntry<'a>,
    tls_table: DataDirectoryEntry<'a>,
    load_config_table: DataDirectoryEntry<'a>,
    bound_import: DataDirectoryEntry<'a>,
    iat: DataDirectoryEntry<'a>,
    delay_import_descriptor: DataDirectoryEntry<'a>,
    clr_runtime_header: DataDirectoryEntry<'a>,
    reserved: DataDirectoryEntry<'a>,
}

#[allow(dead_code)]
#[derive(Debug)]
struct OptionalHeader<'a> {
    //Standard COFF fields
    magic: &'a [u8],
    major_linker_version: &'a [u8],
    minor_linker_version: &'a [u8],
    code_size: usize,
    initialized_data_size: &'a [u8],
    uninitialized_data_size: &'a [u8],
    entry_point_address: usize,
    base_of_code: &'a [u8],
    base_of_data: &'a [u8],
    //Windows Specific Fields
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
    //Data directories
    data_directory: DataDirectoryEntry<'a>,
}

#[allow(dead_code)]
#[derive(Debug)]
struct PEFile<'a> {
    mz_header: DOSHeader<'a>,
    pe_header: COFFHeader<'a>,
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

#[allow(dead_code)]
#[derive(Debug)]
struct SectionTable<'a> {
    sections: Vec<Section<'a>>
}

#[allow(dead_code)]
#[derive(Debug)]
struct StringTable {
    length: usize,
    strings: Vec<String>
}

#[allow(dead_code)]
#[derive(Debug)]
struct Section<'a> {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    raw_data_size: usize,
    ptr_to_raw_data: usize,
    ptr_to_relocations: usize,
    ptr_to_linenumbers: usize,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
    raw_data: &'a[u8]
}

#[allow(dead_code)]
#[derive(Debug)]
struct COFFStringTable<'a> {
    strings: Vec<COFFString<'a>>
}

#[allow(dead_code)]
#[derive(Debug)]
struct COFFString<'a> {
    length: usize,
    structure_length: usize,
    data_type: &'a[u8],
    string: String
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
struct SectionCommand<'a> {
    sectname: &'a [u8],
    segname: &'a [u8],
    addr: &'a [u8],
    size: &'a [u8],
    symbol_table_for_offset: &'a [u8],
    align: &'a [u8],
    reloff: &'a [u8],
    nreloc: &'a [u8],
    flags: &'a [u8],
    reserved: &'a [u8],
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
    symbol_table_for_offset: &'a [u8],
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
#[derive(Debug)]
struct RoutineCommand<'a>{
    load_cmd: LoadCommand <'a>,
    init_address: &'a [u8],
    init_module: &'a [u8],
    reserved_bytes: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct DysymtabCommand<'a>{
    load_cmd: LoadCommand <'a>,
    ilocalsym: &'a [u8],
    nlocalsym: &'a [u8],
    iextdefsym: &'a [u8],
    nextdefsim: &'a [u8],
    iundefsym: &'a [u8],
    nundefsym: &'a [u8],
    tocoff: &'a [u8],
    ntoc: &'a [u8],
    modtaboff: &'a [u8],
    nmodtab: &'a [u8],
    extrefsymoff: &'a [u8],
    nextrefsyms: &'a [u8],
    indirectsymoff: &'a [u8],
    nindirectsyms: &'a [u8],
    extreloff: &'a [u8],
    nextre1: &'a [u8],
    locreloff: &'a [u8],
    nlocre1: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct PrebindChecksumCommand<'a>{
    load_cmd: LoadCommand <'a>,
    cksum: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct UUIDCommand<'a>{
    load_cmd: LoadCommand <'a>,
    uuid: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct ThreadCommand<'a> {
    load_cmd: LoadCommand <'a>,
    flavor: &'a[u8],
    count: &'a[u8],
    state: &'a[u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct EncryptionInfoCommand<'a> {
    load_cmd: LoadCommand <'a>,
    cryptoff: &'a[u8],
    cryptsize: &'a[u8],
    cryptid: &'a[u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct VersionMinCommand<'a> {
    load_cmd: LoadCommand <'a>,
    version: &'a[u8],	
    sdk: &'a[u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct LinkEditDataCommand<'a>{
    load_cmd: LoadCommand <'a>,
    dataoff: &'a[u8],	
    datasize: &'a[u8],	
}

#[allow(dead_code)]
#[derive(Debug)]
struct DyldInfoCommand<'a>{
    load_cmd: LoadCommand <'a>,
    rebase_off: &'a[u8],
    rebase_size: &'a[u8],
    bind_off: &'a[u8],
    bind_size: &'a[u8],
    weak_bind_off: &'a[u8],
    weak_bind_size: &'a[u8],
    lazy_bind_off: &'a[u8],
    lazy_bind_size: &'a[u8],
    export_of: &'a[u8],
    export_size: &'a[u8],
}

#[allow(dead_code)]
#[derive(Debug)]
struct RunPathCommand<'a>{
    load_cmd: LoadCommand <'a>,
    symbol_table_for_offset: &'a[u8],
}

#[allow(dead_code)]
enum LoadCommandData<'a> {
    Segment(SegmentCommand<'a>),
    Symtab(SymtabCommand<'a>),
    Dymlib(DylibCommand<'a>),
    Dysymtab(DysymtabCommand<'a>),
    Routine(RoutineCommand<'a>),
    EntryPoint(EntryPointCommand<'a>),
    Symseg(SymsegCommand<'a>),
    PrebindChecksum(PrebindChecksumCommand<'a>),
    UUID(UUIDCommand<'a>),
    Thread(ThreadCommand<'a>),
    EncryptionInfo(EncryptionInfoCommand<'a>),
    VersionMin(VersionMinCommand<'a>),
    RunPath(RunPathCommand<'a>),
    DyldInfo(DyldInfoCommand<'a>),
    LinkEditData(LinkEditDataCommand<'a>)
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

/****************************************************************************************/
/******************************** Code Functions ****************************************/
/****************************************************************************************/


fn le_to_u32(bytes: &[u8]) -> u32 {
    let array: [u8; 4] = bytes[0..4].try_into().expect("wrong size length");
    u32::from_le_bytes(array)
} 

fn le_to_u16(bytes: &[u8]) -> u16 {
    let array: [u8; 2] = bytes[0..2].try_into().expect("wrong size length");
    u16::from_le_bytes(array)
}

fn le_to_usize(bytes: &[u8]) -> usize {
    let mut array = [0u8; std::mem::size_of::<usize>()];
    for (i, &byte) in bytes.iter().enumerate() {
        array[i] = byte;
    }
    usize::from_le_bytes(array)
}


fn reverse_bytes<T: Clone>(slice: &[T]) -> Vec<T> {
    slice.iter().cloned().rev().collect()
}

fn read_file(file_path: &String) -> Vec<u8> {
    let bytes = fs::read(file_path.to_owned()).unwrap();
    // for byte in bytes.iter() {
    //     print!("{:X} ", byte);
    // }
    // println!();
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

    let mut symbol_table_for_offset = 0;
    while symbol_table_for_offset < bytes.len() {
        let bytes_copy = std::cmp::min(buffer.len(), bytes.len() - symbol_table_for_offset);

        buffer[..bytes_copy].copy_from_slice(&bytes[symbol_table_for_offset..symbol_table_for_offset + bytes_copy]);

        for signature in SIGNATURES.iter() {
            if bytes_copy >= signature.signature.len()
                && &buffer[0..signature.signature.len()] == signature.signature
            {
                file_signature = String::from(signature.name);
            }
        }

        symbol_table_for_offset += bytes_copy;
    }
    println!("signature trouvee: {}", file_signature);
    file_signature
}

fn get_file_data(file_signature: &str, bytes: &[u8]) {
    match file_signature {
        "DOS MZ executable" => {
            let pe_offset = le_to_usize(&bytes[60..64]);
            
            //Extracting the MZ Header
            let file_dos_header: DOSHeader = DOSHeader {
                magic:                      &bytes[0..2],
                extra_bytes:                &bytes[2..4],
                pages:                      &bytes[4..6],
                entries_relocation_table:   &bytes[6..8],
                header_size:                &bytes[8..10],
                min_alloc:                  &bytes[10..12],
                max_alloc:                  &bytes[12..14],
                initial_ss:                 &bytes[14..16],
                initial_sp:                 &bytes[16..18],
                checksum:                   &bytes[18..20],
                initial_ip:                 &bytes[20..22],
                initial_cs:                 &bytes[22..24],
                reloc_table_address:        &bytes[24..26],
                overlay:                    &bytes[26..28],
                pe_offset,
            };

            let file_dos_stub = &bytes[64..pe_offset];

            let symbol_table_pointer = le_to_usize(&bytes[pe_offset + 12..pe_offset + 16]);

            let symbol_count = le_to_usize(&bytes[pe_offset + 16..pe_offset + 20]);
            
            let optional_header_size = le_to_usize(&bytes[pe_offset + 20..pe_offset + 22]);

            //Extracting the PE Header
            let file_coff_header: COFFHeader = COFFHeader {
                magic:                      &bytes[pe_offset..pe_offset + 4],
                machine:                    &bytes[pe_offset + 4..pe_offset + 6],
                section_count:              le_to_usize(&bytes[pe_offset + 6..pe_offset + 8]),
                timestamp:                  &bytes[pe_offset + 8..pe_offset + 12],
                symbol_table_pointer:       symbol_table_pointer,
                symbol_count:               symbol_count,
                optional_header_size:       optional_header_size,
                characteristics:            &bytes[pe_offset + 22..pe_offset + 24],
            };

            let code_size = le_to_usize(&bytes[pe_offset + 28..pe_offset + 32]);

            //Extracting the PE Optionnal header
            let entry_point_address = le_to_usize(&bytes[pe_offset + 36..pe_offset + 40]);
            
            let file_optional_header: OptionalHeader = OptionalHeader {
                magic:                      &bytes[pe_offset + 24..pe_offset + 26],
                major_linker_version:       &bytes[pe_offset + 26..pe_offset + 27],
                minor_linker_version:       &bytes[pe_offset + 27..pe_offset + 28],
                code_size: code_size,
                initialized_data_size:      &bytes[pe_offset + 32..pe_offset + 36],
                uninitialized_data_size:    &bytes[pe_offset + 36..pe_offset + 40],
                entry_point_address:        entry_point_address,
                base_of_code:               &bytes[pe_offset + 44..pe_offset + 48],
                base_of_data:               &bytes[pe_offset + 48..pe_offset + 52],
                image_base:                 &bytes[pe_offset + 52..pe_offset + 56],
                section_alignment:          &bytes[pe_offset + 56..pe_offset + 60],
                file_alignment:             &bytes[pe_offset + 60..pe_offset + 64],
                major_os_version:           &bytes[pe_offset + 64..pe_offset + 66],
                minor_os_version:           &bytes[pe_offset + 66..pe_offset + 68],
                major_image_version:        &bytes[pe_offset + 68..pe_offset + 70],
                minor_image_version:        &bytes[pe_offset + 70..pe_offset + 72],
                major_subsystem_version:    &bytes[pe_offset + 72..pe_offset + 74],
                minor_subsystem_version:    &bytes[pe_offset + 74..pe_offset + 76],
                win32_version_value:        &bytes[pe_offset + 76..pe_offset + 80],
                image_size:                 &bytes[pe_offset + 80..pe_offset + 84],
                headers_size:               &bytes[pe_offset + 84..pe_offset + 88],
                checksum:                   &bytes[pe_offset + 88..pe_offset + 92],
                subsystem:                  &bytes[pe_offset + 92..pe_offset + 94],
                dll_characteristics:        &bytes[pe_offset + 94..pe_offset + 96],
                stack_reserve_size:         &bytes[pe_offset + 96..pe_offset + 100],
                stack_commit_size:          &bytes[pe_offset + 100..pe_offset + 104],
                heap_reserve_size:          &bytes[pe_offset + 104..pe_offset + 108],
                heap_commit_size:           &bytes[pe_offset + 108..pe_offset + 112],
                loader_flags:               &bytes[pe_offset + 112..pe_offset + 116],
                number_of_rva_and_sizes:    &bytes[pe_offset + 116..pe_offset + 120],
                data_directory: DataDirectoryEntry {
                    virtual_address:        &bytes[pe_offset + 120..pe_offset + 124],
                    size:                   &bytes[pe_offset + 124..pe_offset + 128],
                },
            };
    
            //Extracting the symbol table
            let mut symbol_table = SymbolTable{
                symbols: Vec::new(),
            };
                
            let mut symbol_table_for_offset:usize = 0;
            for _i in 0..file_coff_header.symbol_count {
                let name_bytes = &bytes[file_coff_header.symbol_table_pointer + symbol_table_for_offset..file_coff_header.symbol_table_pointer + 8 + symbol_table_for_offset];
                let name = String::from_utf8_lossy(name_bytes).trim_end_matches('\0').to_string();

                symbol_table.symbols.push(Symbol {
                    name,
                    value:                  &bytes[symbol_table_pointer + 8 + symbol_table_for_offset..symbol_table_pointer + 12 + symbol_table_for_offset],
                    section_number:         &bytes[symbol_table_pointer + 12 + symbol_table_for_offset..symbol_table_pointer + 14 + symbol_table_for_offset],
                    data_type:              &bytes[symbol_table_pointer + 14 + symbol_table_for_offset..symbol_table_pointer + 16 + symbol_table_for_offset],
                    storage_class:          &bytes[symbol_table_pointer + 16 + symbol_table_for_offset..symbol_table_pointer + 17 + symbol_table_for_offset],
                    number_aux_symbols:     &bytes[symbol_table_pointer + 17 + symbol_table_for_offset..symbol_table_pointer + 18 + symbol_table_for_offset],
                });
                symbol_table_for_offset += 18;
            }

            let mut section_table = SectionTable{
                sections: Vec::new(),
            };

            let section_table_offset = pe_offset + file_coff_header.optional_header_size + 24;    

            let mut for_offset_section_table: usize = 0;

            for _i in 0..file_coff_header.section_count {
                let ptr_to_raw_data = le_to_usize(&bytes[section_table_offset + 20 +  for_offset_section_table .. section_table_offset + 24 + for_offset_section_table]);
                let raw_data_size = le_to_usize(&bytes[section_table_offset + 16 +  for_offset_section_table .. section_table_offset + 20 + for_offset_section_table]);
                section_table.sections.push(Section {
                    name: String::from_utf8_lossy(&bytes[section_table_offset + for_offset_section_table .. section_table_offset + 8 + for_offset_section_table]).trim_end_matches('\0').to_string(),
                    virtual_size: le_to_u32(&bytes[section_table_offset + 8 +  for_offset_section_table .. section_table_offset + 12 + for_offset_section_table]),
                    virtual_address: le_to_u32(&bytes[section_table_offset + 12 +  for_offset_section_table .. section_table_offset + 16 + for_offset_section_table]),
                    raw_data_size: raw_data_size,
                    ptr_to_raw_data: ptr_to_raw_data,
                    ptr_to_relocations: le_to_usize(&bytes[section_table_offset + 24 +  for_offset_section_table .. section_table_offset + 28 + for_offset_section_table]),
                    ptr_to_linenumbers: le_to_usize(&bytes[section_table_offset + 28 +  for_offset_section_table .. section_table_offset + 32 + for_offset_section_table]),
                    number_of_relocations: le_to_u16(&bytes[section_table_offset + 32 +  for_offset_section_table .. section_table_offset + 34 + for_offset_section_table]),
                    number_of_linenumbers: le_to_u16(&bytes[section_table_offset + 34 +  for_offset_section_table .. section_table_offset + 36 + for_offset_section_table]),
                    characteristics: le_to_u32(&bytes[section_table_offset + 36 +  for_offset_section_table .. section_table_offset + 40 + for_offset_section_table]),
                    raw_data: &bytes[ptr_to_raw_data..ptr_to_raw_data+raw_data_size]
                });
                for_offset_section_table += 40;
            }         
            let mut extracted_code: &[u8] = &[];
            for section in section_table.sections.iter() {
                match section.name.as_str() {
                    ".text" => extracted_code = section.raw_data,

                    _ => println!("Unknown section"),
                }
            }

            let string_table_offset = symbol_table_pointer + (18 * symbol_count);

            let mut string_table = StringTable{
                length: le_to_usize(&bytes[string_table_offset..string_table_offset + 4]),
                strings: Vec::new()
            };
            
            let entire_string_table = String::from_utf8_lossy(&bytes[string_table_offset+4..string_table_offset + string_table.length]);

            string_table.strings = entire_string_table.split('\0').map(|s| s.to_string()).collect();

            //todo: Extract String table and tradure the /xx sections name to extract them
            // println!("Dos Header: {:x?}", file_dos_header);
            // println!("Dos Stub: {:x?}", file_dos_stub);
            // println!("Coff Header: {:x?}", file_coff_header);
            //println!("Symbol Table: {:x?}", symbol_table);
            // println!("Optionnal Header: {:x?}", file_optional_header);
            // println!("Extracted Code: {:x?}", extracted_code);
            // println!("Section Table symbol_table_for_offset: {:?}", section_table_offset);
            // println!("Section Table: {:x?}", section_table);
            println!("String Table: {:?}", string_table);
        }
        "Executable and Linkable Format (ELF)" => {
            let file_info_identification: ELFIdentification = ELFIdentification {
                magic:          &bytes[0..4],
                class:          &bytes[4..5],
                data:           &bytes[5..6],
                version:        &bytes[6..7],
                os_abi:         &bytes[7..8],
                abi_version:    &bytes[8..9],
                padding:        &bytes[9..16],
            };
            let file_info_header = if file_info_identification.class == b"\x01" {
                ELFHeader {
                    file_type:                          &bytes[16..18],
                    machine:                            &bytes[18..20],
                    version:                            &bytes[20..22],
                    entry_point:                        &bytes[22..26],
                    program_header_offset:              &bytes[26..30],
                    section_header_offset:              &bytes[30..34],
                    flags:                              &bytes[34..38],
                    header_size:                        &bytes[38..40],
                    program_header_entry_size:          &bytes[40..42],
                    program_header_entry_count:         &bytes[42..44],
                    section_header_entry_size:          &bytes[44..46],
                    section_header_entry_count:         &bytes[46..48],
                    section_name_string_table_index:    &bytes[48..50],
                }
            } else {
                ELFHeader {
                    file_type:                          &bytes[16..18],
                    machine:                            &bytes[18..20],
                    version:                            &bytes[20..22],
                    entry_point:                        &bytes[22..30],
                    program_header_offset:              &bytes[30..38],
                    section_header_offset:              &bytes[38..46],
                    flags:                              &bytes[46..50],
                    header_size:                        &bytes[50..52],
                    program_header_entry_size:          &bytes[52..54],
                    program_header_entry_count:         &bytes[54..56],
                    section_header_entry_size:          &bytes[56..58],
                    section_header_entry_count:         &bytes[58..60],
                    section_name_string_table_index:    &bytes[60..62],
                }
            };
            let file_dos_header: FileInfoELF = FileInfoELF {
                identification: file_info_identification,
                header: file_info_header,
            };

            
            println!("File Infos: {:?}", file_dos_header);
            //TODO: Extract Code
        }
        "Mach-O binary (32-bit)" | "Mach-O binary (64-bit)" => {
            let file_dos_header: MachOHeader = MachOHeader {
                magic:          &bytes[0..4],
                cputype:        &bytes[4..8],
                cpusubtype:     &bytes[8..12],
                ftype:          &bytes[12..16],
                lcnum:          &bytes[16..20],
                lcsize:         &bytes[20..24],
                flags:          &bytes[24..28],
            };
            println!("File Infos: {:?}", file_dos_header);
            //TODO: Extract code
        }
        "Mach-O binary (reverse byte ordering scheme, 32-bit)"
        | "Mach-O binary (reverse byte ordering scheme, 64-bit)" => {
            let file_dos_header: MachOHeader = MachOHeader {
                magic:      &reverse_bytes(&bytes[0..4]),
                cputype:    &reverse_bytes(&bytes[4..8]),
                cpusubtype: &reverse_bytes(&bytes[8..12]),
                ftype:      &reverse_bytes(&bytes[12..16]),
                lcnum:      &reverse_bytes(&bytes[16..20]),
                lcsize:     &reverse_bytes(&bytes[20..24]),
                flags:      &reverse_bytes(&bytes[24..28]),
            };
            println!("File Infos: {:?}", file_dos_header);
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