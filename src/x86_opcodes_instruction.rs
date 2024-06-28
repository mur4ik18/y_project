use std::collections::HashMap;

pub fn get_opcodes() -> HashMap {
    let x86 = HashMap::from([
        (0x00, "ADD"),
        (0x01, "ADD"),
        (0x02, "ADD"),
        (0x03, "ADD"),
        (0x04, "ADD"),
        (0x05, "ADD"),
        (0x06, "invalid"),
        (0x07, "invalid"),
        (0x08, "OR"),
        (0x09, "OR"),
        (0x0A, "OR"),
        (0x0B, "OR"),
        (0x0C, "OR"),
        (0x0D, "OR"),
        (0x0E, "invalid"),
        (0x10, "ADC"),
    ]);
}
