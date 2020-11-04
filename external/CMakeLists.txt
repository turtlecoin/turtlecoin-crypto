add_subdirectory(argon2)
add_subdirectory(ed25519)
add_subdirectory(sha3)
add_subdirectory(uint256_t)

set_property(TARGET argon2 PROPERTY FOLDER "external/argon2")
set_property(TARGET ed25519 PROPERTY FOLDER "external/ed25519")
set_property(TARGET sha3 PROPERTY FOLDER "external/sha3")
set_property(TARGET uint256t PROPERTY FOLDER "external/uint256t")
