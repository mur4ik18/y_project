#[allow(dead_code)]
#[derive(Debug)]
pub struct ClassFile<'a> {
    pub magic: &'a [u8],
    pub minor_version: &'a [u8],
    pub major_version: &'a [u8],
    pub pool_count: &'a [u8],
    //todo add pool struct
    pub access_flags: &'a [u8],
    pub this_class: &'a [u8],
    pub super_class: &'a [u8],
    pub interfaces_count: &'a [u8],
    //todo add interfaces struct
    pub fields_count: &'a [u8],
    //todo add field struct
    pub method_count: &'a [u8],
    //todo add method struct
    pub attributes_count: &'a [u8],
    //todo add attribute struct
}
