use std::collections::HashMap;
use std::env;
use std::fs;
pub mod util;

//use relm4::gtk::glib::current_dir;

use util::pe_structure::RessourceAdress;
use util::pe_structure::RessourceAdresses;
use util::pe_structure::RessourceDataEntry;
use util::pe_structure::RessourceDirEntries;
use util::pe_structure::UnknownSection;
use util::pe_structure::UnknownSections;

use crate::util::pe_structure::COFFHeader;
use crate::util::pe_structure::DOSHeader;
use crate::util::pe_structure::DataDirectoryEntry;
use crate::util::pe_structure::OptionalHeader;
use crate::util::pe_structure::RessourceDir;
use crate::util::pe_structure::Section;
use crate::util::pe_structure::SectionTable;
use crate::util::pe_structure::StringTable;
use crate::util::pe_structure::Symbol;
use crate::util::pe_structure::SymbolTable;
use crate::util::pe_structure::SectionData;
use crate::util::pe_structure::TextData;
use crate::util::pe_structure::RsrcDataList;
use crate::util::pe_structure::RsrcData;
use crate::util::pe_structure::ImportDescriptor;

use crate::util::signature::SIGNATURES;

use crate::util::elf_structure::ELFHeader;
use crate::util::elf_structure::ELFIdentification;
use crate::util::elf_structure::FileInfoELF;

use crate::util::macho_structure::MachOHeader;
use crate::util::match_codepage;
use crate::util::le_to_u16;
use crate::util::le_to_u32;
use crate::util::le_to_usize;


// context
struct Ctx {
    filename: String,
    byte: bool,
}

/****************************************************************************************/
/******************************** Code Functions ****************************************/
/****************************************************************************************/

fn reverse_bytes<T: Clone>(slice: &[T]) -> Vec<T> {
    slice.iter().cloned().rev().collect()
}

fn extract_dos_header(bytes: &[u8]) -> DOSHeader {
    println!("*[+] Extracting DOS Header...");
    let pe_offset = le_to_usize(&bytes[60..64]);

    let file_dos_header: DOSHeader = DOSHeader {
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
    file_dos_header
}

fn extract_dos_stub(bytes: &[u8], pe_offset: usize) -> &[u8] {
    println!("*[+] Extracting DOS Stub...");
    let file_dos_stub = &bytes[64..pe_offset];
    file_dos_stub
}

fn extract_coff_header(bytes: &[u8], pe_offset: usize) -> COFFHeader {
    println!("*[+] Extracting COFF Header...");
    let symbol_table_pointer = le_to_usize(&bytes[pe_offset + 12..pe_offset + 16]);

    let symbol_count = le_to_usize(&bytes[pe_offset + 16..pe_offset + 20]);

    let optional_header_size = le_to_usize(&bytes[pe_offset + 20..pe_offset + 22]);

    let coff_header: COFFHeader = COFFHeader {
        magic: &bytes[pe_offset..pe_offset + 4],
        machine: &bytes[pe_offset + 4..pe_offset + 6],
        section_count: le_to_usize(&bytes[pe_offset + 6..pe_offset + 8]),
        timestamp: &bytes[pe_offset + 8..pe_offset + 12],
        symbol_table_pointer: symbol_table_pointer,
        symbol_count: symbol_count,
        optional_header_size: optional_header_size,
        characteristics: &bytes[pe_offset + 22..pe_offset + 24],
    };
    coff_header
}

fn extract_opt_header(bytes: &[u8], pe_offset: usize) -> OptionalHeader {
    println!("*[+] Extracting Optionnal Header...");
    let code_size = le_to_usize(&bytes[pe_offset + 28..pe_offset + 32]);

    let entry_point_address = le_to_usize(&bytes[pe_offset + 36..pe_offset + 40]);

    let file_optional_header: OptionalHeader = OptionalHeader {
        magic: &bytes[pe_offset + 24..pe_offset + 26],
        major_linker_version: &bytes[pe_offset + 26..pe_offset + 27],
        minor_linker_version: &bytes[pe_offset + 27..pe_offset + 28],
        code_size: code_size,
        initialized_data_size: &bytes[pe_offset + 32..pe_offset + 36],
        uninitialized_data_size: &bytes[pe_offset + 36..pe_offset + 40],
        entry_point_address: entry_point_address,
        base_of_code: &bytes[pe_offset + 44..pe_offset + 48],
        base_of_data: &bytes[pe_offset + 48..pe_offset + 52],
        image_base: &bytes[pe_offset + 52..pe_offset + 56],
        section_alignment: &bytes[pe_offset + 56..pe_offset + 60],
        file_alignment: &bytes[pe_offset + 60..pe_offset + 64],
        major_os_version: &bytes[pe_offset + 64..pe_offset + 66],
        minor_os_version: &bytes[pe_offset + 66..pe_offset + 68],
        major_image_version: &bytes[pe_offset + 68..pe_offset + 70],
        minor_image_version: &bytes[pe_offset + 70..pe_offset + 72],
        major_subsystem_version: &bytes[pe_offset + 72..pe_offset + 74],
        minor_subsystem_version: &bytes[pe_offset + 74..pe_offset + 76],
        win32_version_value: &bytes[pe_offset + 76..pe_offset + 80],
        image_size: &bytes[pe_offset + 80..pe_offset + 84],
        headers_size: &bytes[pe_offset + 84..pe_offset + 88],
        checksum: &bytes[pe_offset + 88..pe_offset + 92],
        subsystem: &bytes[pe_offset + 92..pe_offset + 94],
        dll_characteristics: &bytes[pe_offset + 94..pe_offset + 96],
        stack_reserve_size: &bytes[pe_offset + 96..pe_offset + 100],
        stack_commit_size: &bytes[pe_offset + 100..pe_offset + 104],
        heap_reserve_size: &bytes[pe_offset + 104..pe_offset + 108],
        heap_commit_size: &bytes[pe_offset + 108..pe_offset + 112],
        loader_flags: &bytes[pe_offset + 112..pe_offset + 116],
        number_of_rva_and_sizes: &bytes[pe_offset + 116..pe_offset + 120],
        data_directory: DataDirectoryEntry {
            virtual_address: &bytes[pe_offset + 120..pe_offset + 124],
            size: &bytes[pe_offset + 124..pe_offset + 128],
        },
    };
    file_optional_header
}

fn extract_symbol_table<'a>(
    bytes: &'a [u8],
    pe_offset: usize,
    coff_header: COFFHeader<'a>,
) -> SymbolTable<'a> {
    println!("*[+] Extracting Symbol Table...");
    let mut symbol_table = SymbolTable {
        symbols: Vec::new(),
    };

    let mut symbol_table_for_offset: usize = 0;
    for _i in 0..coff_header.symbol_count {
        let name_bytes = &bytes[coff_header.symbol_table_pointer + symbol_table_for_offset
            ..coff_header.symbol_table_pointer + 8 + symbol_table_for_offset];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_end_matches('\0')
            .to_string();

        symbol_table.symbols.push(Symbol {
            name,
            value: &bytes[coff_header.symbol_table_pointer + 8 + symbol_table_for_offset
                ..coff_header.symbol_table_pointer + 12 + symbol_table_for_offset],
            section_number: &bytes[coff_header.symbol_table_pointer + 12 + symbol_table_for_offset
                ..coff_header.symbol_table_pointer + 14 + symbol_table_for_offset],
            data_type: &bytes[coff_header.symbol_table_pointer + 14 + symbol_table_for_offset
                ..coff_header.symbol_table_pointer + 16 + symbol_table_for_offset],
            storage_class: &bytes[coff_header.symbol_table_pointer + 16 + symbol_table_for_offset
                ..coff_header.symbol_table_pointer + 17 + symbol_table_for_offset],
            number_aux_symbols: &bytes[coff_header.symbol_table_pointer
                + 17
                + symbol_table_for_offset
                ..coff_header.symbol_table_pointer + 18 + symbol_table_for_offset],
        });
        symbol_table_for_offset += 18;
    }
    symbol_table
}

fn extract_string_table(bytes: &[u8], coff_header: COFFHeader) -> StringTable {
    println!("*[+] Extracting String Table...");
    let string_table_offset = coff_header.symbol_table_pointer + (18 * coff_header.symbol_count);

    let mut string_table = StringTable {
        length: le_to_usize(&bytes[string_table_offset..string_table_offset + 4]),
        strings: Vec::new(),
    };

    let entire_string_table = String::from_utf8_lossy(
        &bytes[string_table_offset + 4..string_table_offset + string_table.length],
    );

    string_table.strings = entire_string_table
        .split('\0')
        .map(|s| s.to_string())
        .collect();
    string_table
}

fn extract_section_table<'a>(
    bytes: &'a [u8],
    pe_offset: usize,
    file_coff_header: COFFHeader<'a>,
) -> SectionTable<'a> {
    println!("*[+] Extracting Section Table...");
    let mut section_table = SectionTable {
        sections: Vec::new(),
    };

    let section_table_offset = pe_offset + file_coff_header.optional_header_size + 24;

    let mut for_offset_section_table: usize = 0;

    for _i in 0..file_coff_header.section_count {
        let ptr_to_raw_data = le_to_usize(
            &bytes[section_table_offset + 20 + for_offset_section_table
                ..section_table_offset + 24 + for_offset_section_table],
        );
        let raw_data_size = le_to_usize(
            &bytes[section_table_offset + 16 + for_offset_section_table
                ..section_table_offset + 20 + for_offset_section_table],
        );
        section_table.sections.push(Section {
            name: String::from_utf8_lossy(
                &bytes[section_table_offset + for_offset_section_table
                    ..section_table_offset + 8 + for_offset_section_table],
            )
            .trim_end_matches('\0')
            .to_string(),
            virtual_size: le_to_usize(
                &bytes[section_table_offset + 8 + for_offset_section_table
                    ..section_table_offset + 12 + for_offset_section_table],
            ),
            virtual_address: le_to_usize(
                &bytes[section_table_offset + 12 + for_offset_section_table
                    ..section_table_offset + 16 + for_offset_section_table],
            ),
            raw_data_size: raw_data_size,
            ptr_to_raw_data: ptr_to_raw_data,
            ptr_to_relocations: le_to_usize(
                &bytes[section_table_offset + 24 + for_offset_section_table
                    ..section_table_offset + 28 + for_offset_section_table],
            ),
            ptr_to_linenumbers: le_to_usize(
                &bytes[section_table_offset + 28 + for_offset_section_table
                    ..section_table_offset + 32 + for_offset_section_table],
            ),
            number_of_relocations: le_to_u16(
                &bytes[section_table_offset + 32 + for_offset_section_table
                    ..section_table_offset + 34 + for_offset_section_table],
            ),
            number_of_linenumbers: le_to_u16(
                &bytes[section_table_offset + 34 + for_offset_section_table
                    ..section_table_offset + 36 + for_offset_section_table],
            ),
            characteristics: le_to_u32(
                &bytes[section_table_offset + 36 + for_offset_section_table
                    ..section_table_offset + 40 + for_offset_section_table],
            ),
            raw_data: &bytes[ptr_to_raw_data..ptr_to_raw_data + raw_data_size],
        });
        for_offset_section_table += 40;
    }
    section_table
}

fn read_file(file_path: &String) -> Vec<u8> {
    println!("*[+] Reading file...");
    let bytes = fs::read(file_path.to_owned()).unwrap();
    // for byte in bytes.iter() {
    //     print!("{:X} ", byte);
    // }
    // println!();
    bytes
}

fn get_dll_name<'a>(bytes: &'a[u8], offset: usize) -> String {
    let mut dll_name: String = Default::default();
    let sliced_bytes = &bytes[offset..];
    for &byte in sliced_bytes.iter() {
        if byte==0x00{
            break;
        }
        dll_name.push(byte as char);
    }
    dll_name
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
        // println!("arg {} - {}", i, args[i]);
    }
    ctx
}

fn get_sign(bytes: &[u8]) -> String {
    println!("*[+] Obtaining file signature...");
    let mut buffer = [0; 1024];

    let mut file_signature: String = String::from("unknown");

    let mut symbol_table_for_offset = 0;
    while symbol_table_for_offset < bytes.len() {
        let bytes_copy = std::cmp::min(buffer.len(), bytes.len() - symbol_table_for_offset);

        buffer[..bytes_copy]
            .copy_from_slice(&bytes[symbol_table_for_offset..symbol_table_for_offset + bytes_copy]);

        for signature in SIGNATURES.iter() {
            if bytes_copy >= signature.signature.len()
                && &buffer[0..signature.signature.len()] == signature.signature
            {
                file_signature = String::from(signature.name);
            }
        }

        symbol_table_for_offset += bytes_copy;
    }
    println!("*[+] File signature detected: {}", file_signature);
    file_signature
}

fn replace_section_names(string_table: &StringTable, section_table: &mut SectionTable) {
    println!("*[+] Replacing section names...");
    for section in section_table.sections.iter_mut() {
        if section.name.starts_with("/") {
            let mut name: String = section.name.to_string();
            name = name.trim_start_matches("/").to_string();
            let index: usize = name.parse().unwrap();
            section.name = string_table.strings[index].clone();
        }
    }
}

struct SectionsData<'a> {
    sections: HashMap<String, SectionData<'a>>,
}

fn extract_section_datas<'a>(
    bytes: &'a[u8],
    section_table: &'a mut SectionTable,
    sections_data: &mut SectionsData<'a>,
) {
    let mut unknown_sections = UnknownSections {
        sections: Vec::new()
    };
    println!("*[+] Extracting data from sections...");
    for section in section_table.sections.iter_mut() {
        match section.name.as_str() {
            ".text" => {
                sections_data.sections.insert(
                    section.name.clone(),
                    SectionData::Text(TextData {
                        extracted_code: section.raw_data,
                    }),
                );
            }
            ".rsrc" => {
                let mut rsrc_data_adresses = RessourceAdresses {
                    adresses: Vec::new(),
                };
                let mut rsrc_data_list = RsrcDataList {
                    data: Vec::new(),
                };

                find_rsrc_data_adresses(
                    &mut rsrc_data_adresses,
                    0,
                    section.raw_data,
                    section.virtual_size,
                    section.ptr_to_raw_data,
                    section.virtual_address,
                );

                println!(
                    "*[+] Found {} resource entries in .rsrc section. ", rsrc_data_adresses.adresses.len(),
                );

                for adresses in rsrc_data_adresses.adresses {
                    let data = RsrcData {
                        extracted_raw: &bytes[adresses.address..adresses.address + adresses.size],
                        codepage: adresses.codepage
                    };
                    rsrc_data_list.data.push(data);
                }

                sections_data.sections.insert(
                    section.name.clone(),
                    SectionData::Rsrc(rsrc_data_list),
                );

            }

            ".idata" => {
                let mut offset: usize = 0;
                println!("{:?}",section);
                loop {
                    let import_descriptor = ImportDescriptor{
                        original_first_thunk: le_to_usize(&section.raw_data[offset + 0..offset + 4]),
                        time_date_stamp: le_to_usize(&section.raw_data[offset + 4..offset + 8]),
                        forwarder_chain: le_to_usize(&section.raw_data[offset + 8..offset + 12]),
                        name_rva: le_to_usize(&section.raw_data[offset + 12..offset + 16]),
                        first_thunk: le_to_usize(&section.raw_data[offset + 16..offset + 20]),
                    };

                    offset+=20;

                    if import_descriptor.first_thunk + import_descriptor.time_date_stamp
                       + import_descriptor.forwarder_chain + import_descriptor.name_rva
                       + import_descriptor.first_thunk == 0
                    {
                        break;
                    }

                    let stdd: String;
                    stdd = get_dll_name(bytes, (import_descriptor.name_rva+section.ptr_to_raw_data)-section.virtual_address);
                    println!("{}", stdd);
                    println!("{:?}, {:?}, {:?}", import_descriptor.name_rva,section.ptr_to_raw_data,section.virtual_address);
                }
            }   

            _ => {
                let unknown_section = UnknownSection {
                    section_name: section.name.to_owned(),
                    extracted_raw: section.raw_data,
                };
                unknown_sections.sections.push(unknown_section);
            }
        }
    }
    sections_data.sections.insert(
        "Unknown".to_string(),
        SectionData::Unknown(UnknownSections {
            sections: unknown_sections.sections
        }),
    );

}

fn is_a_subdirectory(value: &[u8]) -> bool {
    value[3] & 0b10000000 != 0
}

fn msb_to_0(value: &[u8]) -> Vec<u8> {
    let mut result = value.to_vec();
    result[3] &= 0x7F;
    result
}

fn find_rsrc_data_adresses(
    rsrc_adresses: &mut RessourceAdresses,
    mut offset: usize,
    bytes: &[u8],
    virtual_size: usize,
    ptr_raw_data: usize,
    virtual_address: usize,
) {
    let current_dir = RessourceDir {
        characteristics: &bytes[offset..offset + 4],
        time_date_stamp: &bytes[offset + 4..offset + 8],
        major_version: &bytes[offset + 8..offset + 10],
        minor_version: &bytes[offset + 10..offset + 12],
        name_entries_number: le_to_usize(&bytes[offset + 12..offset + 14]),
        id_entries_number: le_to_usize(&bytes[offset + 14..offset + 16]),
    };
    offset += 16;

    for _ in 0..current_dir.name_entries_number {
        let current_name_entry = RessourceDirEntries {
            name_offset: le_to_usize(&bytes[offset..offset + 4]),
            data_entry_offset: &bytes[offset + 4..offset + 8],
        };

        if is_a_subdirectory(&current_name_entry.data_entry_offset) {
            let offset: &[u8] = &msb_to_0(&current_name_entry.data_entry_offset);
            find_rsrc_data_adresses(
                rsrc_adresses,
                le_to_usize(offset),
                bytes,
                virtual_size,
                ptr_raw_data,
                virtual_address,
            );
        } else {
            let data_entry = RessourceDataEntry {
                data_rva: le_to_usize(&bytes[offset + 8..offset + 12]),
                size: le_to_usize(&bytes[offset + 12..offset + 16]),
                codepage: &bytes[offset + 16..offset + 20],
                reserved: &bytes[offset + 20..offset + 24],
            };
            let codepage: &str;
            
            codepage = match_codepage(le_to_u16(data_entry.codepage));

            let data = RessourceAdress {
                size: data_entry.size,
                address: data_entry.data_rva - virtual_address + ptr_raw_data,
                codepage: codepage,
            };

            rsrc_adresses.adresses.push(data);
        }

        offset += 8;
    }

    for _ in 0..current_dir.id_entries_number {
        let current_id_entry = RessourceDirEntries {
            name_offset: le_to_usize(&bytes[offset..offset + 4]),
            data_entry_offset: &bytes[offset + 4..offset + 8],
        };

        if is_a_subdirectory(&current_id_entry.data_entry_offset) {
            let offset: &[u8] = &msb_to_0(&current_id_entry.data_entry_offset);
            find_rsrc_data_adresses(
                rsrc_adresses,
                le_to_usize(offset),
                bytes,
                virtual_size,
                ptr_raw_data,
                virtual_address,
            );
        } else {
            let data_entry = RessourceDataEntry {
                data_rva: le_to_usize(&bytes[offset + 8..offset + 12]),
                size: le_to_usize(&bytes[offset + 12..offset + 16]),
                codepage: &bytes[offset + 16..offset + 20],
                reserved: &bytes[offset + 20..offset + 24],
            };
            let codepage: &str;
            
            codepage = match_codepage(le_to_u16(data_entry.codepage));

            let data = RessourceAdress {
                size: data_entry.size,
                address: data_entry.data_rva - virtual_address + ptr_raw_data,
                codepage: codepage,
            };

            rsrc_adresses.adresses.push(data);
        }

        offset += 8;
    }
}

fn get_file_data(file_signature: &str, bytes: &[u8]) {
    println!("*[+] Obtaining file infos...");
    match file_signature {
        "DOS MZ executable" => {
            let dos_header = extract_dos_header(bytes);

            let dos_stub = extract_dos_stub(bytes, dos_header.pe_offset);

            let coff_header = extract_coff_header(bytes, dos_header.pe_offset);

            let opt_header = extract_opt_header(bytes, dos_header.pe_offset);

            let symbol_table =
                extract_symbol_table(bytes, dos_header.pe_offset, coff_header.clone());

            let string_table = extract_string_table(bytes, coff_header.clone());

            let mut section_table =
                extract_section_table(bytes, dos_header.pe_offset, coff_header.clone());

            let mut sections_data = SectionsData {
                sections: HashMap::new(),
            };

            replace_section_names(&string_table, &mut section_table);

            extract_section_datas(bytes, &mut section_table, &mut sections_data);

            if let Some(SectionData::Text(text_data)) = sections_data.sections.get(".text") {
                // println!("Extracted .text section data: {:?}", text_data.extracted_code);
            }

            if let Some(SectionData::Rsrc(rsrc_data)) = sections_data.sections.get(".rsrc") {
                // println!("Extracted .rsrc section data: {:?}", rsrc_data);
            }

            if let Some(SectionData::Unknown(unknown_sections)) = sections_data.sections.get("Unknown") {
                // println!("Unrecognized section data: {:?}", unknown_sections);
            }
            
            // println!("{:?}", &bytes[18804..18820]);
            // println!("{:?}", &bytes[17728..17900]);
            // println!("{:?}", &bytes[17488..17700]);
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
            let file_dos_header: FileInfoELF = FileInfoELF {
                identification: file_info_identification,
                header: file_info_header,
            };

            println!("File Infos: {:?}", file_dos_header);
            //TODO: Extract Code
        }
        "Mach-O binary (32-bit)" | "Mach-O binary (64-bit)" => {
            let file_dos_header: MachOHeader = MachOHeader {
                magic: &bytes[0..4],
                cputype: &bytes[4..8],
                cpusubtype: &bytes[8..12],
                ftype: &bytes[12..16],
                lcnum: &bytes[16..20],
                lcsize: &bytes[20..24],
                flags: &bytes[24..28],
            };
            println!("File Infos: {:?}", file_dos_header);
            //TODO: Extract code
        }
        "Mach-O binary (reverse byte ordering scheme, 32-bit)"
        | "Mach-O binary (reverse byte ordering scheme, 64-bit)" => {
            let file_dos_header: MachOHeader = MachOHeader {
                magic: &reverse_bytes(&bytes[0..4]),
                cputype: &reverse_bytes(&bytes[4..8]),
                cpusubtype: &reverse_bytes(&bytes[8..12]),
                ftype: &reverse_bytes(&bytes[12..16]),
                lcnum: &reverse_bytes(&bytes[16..20]),
                lcsize: &reverse_bytes(&bytes[20..24]),
                flags: &reverse_bytes(&bytes[24..28]),
            };
            println!("File Infos: {:?}", file_dos_header);
        }
        "Java class file, Mach-O Fat Binary" => {
            //TODO: Search infos
        }
        _ => {}
    }
}

// =========================================================================== 
//                                    Graphisme
// ===========================================================================

fn main() {
    //help();
    let context: Ctx = get_arguments();
    let bytecode = read_file(&context.filename);
    let sign = get_sign(&bytecode);
    get_file_data(&sign, &bytecode);
}
