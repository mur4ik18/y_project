#[allow(dead_code)]
#[derive(Debug)]
pub struct DOSHeader<'a> {
    pub magic: &'a [u8],
    pub extra_bytes: &'a [u8],
    pub pages: &'a [u8],
    pub entries_relocation_table: &'a [u8],
    pub header_size: &'a [u8],
    pub min_alloc: &'a [u8],
    pub max_alloc: &'a [u8],
    pub initial_ss: &'a [u8],
    pub initial_sp: &'a [u8],
    pub checksum: &'a [u8],
    pub initial_ip: &'a [u8],
    pub initial_cs: &'a [u8],
    pub reloc_table_address: &'a [u8],
    pub overlay: &'a [u8],
    pub pe_offset: usize,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct COFFHeader<'a> {
    pub magic: &'a [u8],
    pub machine: &'a [u8],
    pub section_count: usize,
    pub timestamp: &'a [u8],
    pub symbol_table_pointer: usize,
    pub symbol_count: usize,
    pub optional_header_size: usize,
    pub characteristics: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct DataDirectoryEntry<'a> {
    pub virtual_address: &'a [u8],
    pub size: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct DataDirectory<'a> {
    pub export_table: DataDirectoryEntry<'a>,
    pub import_table: DataDirectoryEntry<'a>,
    pub resource_table: DataDirectoryEntry<'a>,
    pub exception_table: DataDirectoryEntry<'a>,
    pub certificate_table: DataDirectoryEntry<'a>,
    pub base_relocation_table: DataDirectoryEntry<'a>,
    pub debug: DataDirectoryEntry<'a>,
    pub architecture: DataDirectoryEntry<'a>,
    pub global_ptr: DataDirectoryEntry<'a>,
    pub tls_table: DataDirectoryEntry<'a>,
    pub load_config_table: DataDirectoryEntry<'a>,
    pub bound_import: DataDirectoryEntry<'a>,
    pub iat: DataDirectoryEntry<'a>,
    pub delay_import_descriptor: DataDirectoryEntry<'a>,
    pub clr_runtime_header: DataDirectoryEntry<'a>,
    pub reserved: DataDirectoryEntry<'a>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct OptionalHeader<'a> {
    //Standard COFF fields
    pub magic: &'a [u8],
    pub major_linker_version: &'a [u8],
    pub minor_linker_version: &'a [u8],
    pub code_size: usize,
    pub initialized_data_size: &'a [u8],
    pub uninitialized_data_size: &'a [u8],
    pub entry_point_address: usize,
    pub base_of_code: &'a [u8],
    pub base_of_data: &'a [u8],
    //Windows Specific Fields
    pub image_base: &'a [u8],
    pub section_alignment: &'a [u8],
    pub file_alignment: &'a [u8],
    pub major_os_version: &'a [u8],
    pub minor_os_version: &'a [u8],
    pub major_image_version: &'a [u8],
    pub minor_image_version: &'a [u8],
    pub major_subsystem_version: &'a [u8],
    pub minor_subsystem_version: &'a [u8],
    pub win32_version_value: &'a [u8],
    pub image_size: &'a [u8],
    pub headers_size: &'a [u8],
    pub checksum: &'a [u8],
    pub subsystem: &'a [u8],
    pub dll_characteristics: &'a [u8],
    pub stack_reserve_size: &'a [u8],
    pub stack_commit_size: &'a [u8],
    pub heap_reserve_size: &'a [u8],
    pub heap_commit_size: &'a [u8],
    pub loader_flags: &'a [u8],
    pub number_of_rva_and_sizes: &'a [u8],
    //Data directories
    pub data_directory: DataDirectoryEntry<'a>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct PEFile<'a> {
    pub mz_header: DOSHeader<'a>,
    pub pe_header: COFFHeader<'a>,
    pub optional_header: OptionalHeader<'a>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Symbol<'a> {
    pub name: String,
    pub value: &'a [u8],
    pub section_number: &'a [u8],
    pub data_type: &'a [u8],
    pub storage_class: &'a [u8],
    pub number_aux_symbols: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SymbolTable<'a> {
    pub symbols: Vec<Symbol<'a>>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SectionTable<'a> {
    pub sections: Vec<Section<'a>>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct StringTable {
    pub length: usize,
    pub strings: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Section<'a> {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: usize,
    pub ptr_to_raw_data: usize,
    pub ptr_to_relocations: usize,
    pub ptr_to_linenumbers: usize,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
    pub raw_data: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct COFFStringTable<'a> {
    pub strings: Vec<COFFString<'a>>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct COFFString<'a> {
    pub length: usize,
    pub structure_length: usize,
    pub data_type: &'a [u8],
    pub string: String,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct RessourceDir<'a> {
    pub characteristics: &'a [u8],
    pub time_data_stamp: &'a [u8],
    pub major_version: &'a [u8],
    pub minor_version: &'a [u8],
    pub name_entries_number: usize,
    pub id_entries_number: usize,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct RessourceDirEntries {
    pub name_offset: usize,
    pub data_entry_offset: usize,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct RessourceDirString<'a> {
    pub length: usize,
    pub unicode_string: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct RessourceDataEntry<'a> {
    pub data_rva: &'a [u8],
    pub size: usize,
    pub codepage: &'a [u8],
    pub reserved: &'a [u8],
}
