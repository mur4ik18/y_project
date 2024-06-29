use create::opcodes_instructions::Opcode;
use std::collections::HashMap;

pub fn get_opcodes() -> HashMap {
    let ARM = HashMap::from([
        (0x__,Opcode("CBZ", Addressing::)),
        (0x__,Opcode()),
    ]);
}
