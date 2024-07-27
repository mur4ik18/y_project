#[allow(dead_code)]
#[derive(Debug)]
pub struct ELFIdentification<'a> {
    pub magic: &'a [u8],
    pub class: &'a [u8],
    pub data: &'a [u8],
    pub version: &'a [u8],
    pub os_abi: &'a [u8],
    pub abi_version: &'a [u8],
    pub padding: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct ELFHeader<'a> {
    pub file_type: &'a [u8],
    pub machine: &'a [u8],
    pub version: &'a [u8],
    pub entry_point: &'a [u8],
    pub program_header_offset: &'a [u8],
    pub section_header_offset: &'a [u8],
    pub flags: &'a [u8],
    pub header_size: &'a [u8],
    pub program_header_entry_size: &'a [u8],
    pub program_header_entry_count: &'a [u8],
    pub section_header_entry_size: &'a [u8],
    pub section_header_entry_count: &'a [u8],
    pub section_name_string_table_index: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct FileInfoELF<'a> {
    pub identification: ELFIdentification<'a>,
    pub header: ELFHeader<'a>,
}
