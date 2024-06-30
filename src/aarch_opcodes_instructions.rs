use create::opcodes_instructions::Opcode;
use std::collections::HashMap;

pub fn get_opcodes() -> HashMap {
    let ARM = HashMap::from([
        (0x8B, Opcode("ADD", Addressing::IMMEDIATE)),
        (0xD2, Opcode("MOV", Addressing::IMMEDIATE)),
        (0xAA, Opcode("MOV", Addressing::RTR)),
    ]);
}
