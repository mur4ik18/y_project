use std::collections::HashMap;
use std::env;
use std::fs;

pub mod elf_structure;
pub mod jvm_structure;
pub mod macho_structure;
pub mod pe_structure;
pub mod signature;

use crate::pe_structure::COFFHeader;
use crate::pe_structure::COFFString;
use crate::pe_structure::COFFStringTable;
use crate::pe_structure::DOSHeader;
use crate::pe_structure::DataDirectoryEntry;
use crate::pe_structure::OptionalHeader;
use crate::pe_structure::PEFile;
use crate::pe_structure::RessourceDir;
use crate::pe_structure::Section;
use crate::pe_structure::SectionTable;
use crate::pe_structure::StringTable;
use crate::pe_structure::Symbol;
use crate::pe_structure::SymbolTable;

use crate::signature::SIGNATURES;


use crate::elf_structure::ELFHeader;
use crate::elf_structure::ELFIdentification;
use crate::elf_structure::FileInfoELF;

use crate::macho_structure::MachOHeader;

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


pub fn read_file(file_path: &String) -> Vec<u8> {
    println!("*[+] Reading file...");
    let bytes = fs::read(file_path.to_owned()).unwrap();
    // for byte in bytes.iter() {
    //     print!("{:X} ", byte);
    // }
    // println!();
    bytes
}

pub fn help() {
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

pub fn get_sign(bytes: &[u8]) -> String {
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


pub fn get_file_data(file_signature: &str, bytes: &[u8]) {
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

            if let Some(SectionData::IData(idata_data)) = sections_data.sections.get(".idata") {
                // println!("Extracted .idata section data: {:?}", idata_data);
            }

            let string_table_offset = symbol_table_pointer + (18 * symbol_count);

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

            let mut text_section_data: &[u8] = &[];

            for section in section_table.sections.iter_mut() {
                if section.name.starts_with("/") {
                    let mut name: String = section.name.to_string();
                    name = name.trim_start_matches("/").to_string();
                    let index: usize = name.parse().unwrap();
                    section.name = string_table.strings[index].clone();
                }

                match section.name.as_str() {
                    ".text" => {
                        let mut text_section_data: &[u8] = &[];
                        text_section_data = section.raw_data;
                    }
                    ".rsrc" => {
                        let mut rsrc_section_data: &[u8] = &[];
                        rsrc_section_data = section.raw_data;
                        let rsrc_dir = RessourceDir {
                            characteristics: &rsrc_section_data[0..4],
                            time_data_stamp: &rsrc_section_data[4..8],
                            major_version: &rsrc_section_data[8..10],
                            minor_version: &rsrc_section_data[10..12],
                            name_entries_number: le_to_usize(&rsrc_section_data[12..14]),
                            id_entries_number: le_to_usize(&rsrc_section_data[14..16]),
                        };
                        // println!("Rsrc Data: {:?}", rsrc_section_data);
                        // println!("Rsrc Dir: {:?}", rsrc_dir);

                        // fonction récursive qui lis un directory, on lui donne un offset.

                        // elle lis le nombre d'entrée de nom,
                        // si c'est un subdirectory alors elle se rappelle elle même
                        // sinon elle stocke les données de la name entry

                        // elle lis le nombre d'entrée d'id
                        // si c'est un subdirectory alors elle se rappelle elle même
                        // sinon elle stocke les données de l'id entry

                        // si bit poids fort == 1 alors entrée de donnée sinon subdir
                        // les 31 autres bits sont l'offset des données
                    }

                    //ToDo: Add common file sections name and extracts their data
                    _ => println!("Unknown section {}", section.name),
                    //ToDo: Add extraction of unknow section name by pushing them into a vec containing name and raw data associated
                }
            }

            //   println!("Dos Header: {:x?}", file_dos_header);
            //   println!("Dos Stub: {:x?}", file_dos_stub);
            //   println!("Coff Header: {:x?}", file_coff_header);
            //   println!("Symbol Table: {:x?}", symbol_table);
            //   println!("Optionnal Header: {:x?}", file_optional_header);
            //   println!("Extracted Code: {:x?}", text_section_data);
            //   println!("Section Table symbol_table_for_offset: {:?}", section_table_offset);
            //   println!("Section Table: {:?}", section_table);
            //   println!("String Table: {:?}", string_table);
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

