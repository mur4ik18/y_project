use create::opcodes_instructions::Opcode;
use std::collections::HashMap;

pub fn get_opcodes() -> HashMap {
    let ARM = HashMap::from([
        (0x8B, Opcode("ADD", Addressing::IMMEDIATE)),
        //(0x8B, Opcode("ADD", Addressing::RTR),
        (0xCB, Opcode("SUB", Addressing::RTR)),
        (0x9B, Opcode("MUL", Addressing::RTR)),
        //
        (0x8A, Opcode("AND", Addressing::RTR)),
        (0xAA, Opcode("ORR", Addressing::RTR)),
        (0xCA, Opcode("EOR", Addressing::RTR)),
        // Movement Instructions
        (0xD2, Opcode("MOV", Addressing::IMMEDIATE)),
        (0xAA, Opcode("MOV", Addressing::RTR)),
        (0xF9, Opcode("LDR", Addressing::IMMEDIATE)),
        (0xAA, Opcode("STR", Addressing::RTR)),
    ]);
}
