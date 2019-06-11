add_subdirectory(argon2)

if(MSVC)
    set_property(TARGET argon2 PROPERTY FOLDER "external")
elseif(NOT MSVC)
    set_property(TARGET argon2 PROPERTY FOLDER "external")
endif()
