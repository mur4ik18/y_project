enum Addressing {
    DIRECT,
    RDIRECT,
    IMMEDIATE,
    RINDIRECT,
    RINDIRECTWO,
    RINDIRECT_PRE_INC,
    RINDIRECT_POS_INC,
    RINDIRECT_RINDEXED,
    RINDIRECT_INDEXED,
    RTR, // Register to Register
}

struct Opcode {
    mnemonic: String,
    addressing: Addressing,
}
