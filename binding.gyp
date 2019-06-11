{
  "targets": [
    {
      "target_name": "turtlecoin-crypto",
      "defines": [
        "NDEBUG",
        "NO_CRYPTO_EXPORTS",
        "FORCE_USE_HEAP",
        "NO_AES"
      ],
      "include_dirs": [
        "include",
        "<!(node -e \"require('nan')\")",
        "external/argon2/include",
        "external/argon2/lib"
      ],
      "sources": [
        "src/aesb.c",
        "src/blake256.c",
        "src/chacha8.cpp",
        "src/crypto.cpp",
        "src/crypto-ops.c",
        "src/crypto-ops-data.c",
        "src/groestl.c",
        "src/hash.c",
        "src/hash-extra-blake.c",
        "src/hash-extra-groestl.c",
        "src/hash-extra-jh.c",
        "src/hash-extra-skein.c",
        "src/jh.c",
        "src/keccak.c",
        "src/oaes_lib.c",
        "src/random.cpp",
        "src/skein.c",
        "src/slow-hash-arm.c",
        "src/slow-hash-x86.c",
        "src/slow-hash-portable.c",
        "src/StringTools.cpp",
        "src/tree-hash.c",
        "external/argon2/lib/argon2.c",
        "external/argon2/arch/generic/lib/argon2-arch.c",
        "external/argon2/lib/core.c",
        "external/argon2/lib/encoding.c",
        "external/argon2/lib/genkat.c",
        "external/argon2/lib/impl-select.c",
        "external/argon2/lib/thread.c",
        "external/argon2/lib/blake2/blake2.c",
        "src/turtlecoin-crypto.cpp",
        "src/turtlecoin-crypto-node.cpp"
      ],
      "cflags!": [
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Wpointer-arith",
        "-Wvla",
        "-Wwrite-strings",
        "-Wno-error=extra",
        "-Wno-error=unused-function",
        "-Wno-error=sign-compare",
        "-Wno-error=strict-aliasing",
        "-Wno-error=type-limits",
        "-Wno-error=unused-parameter",
        "-Wno-error=unused-variable",
        "-Wno-error=undef",
        "-Wno-error=uninitialized",
        "-Wno-error=unused-result",
        "-Wlogical-op",
        "-Wno-error=maybe-uninitialized",
        "-Wno-error=clobbered",
        "-Wno-error=unused-but-set-variable",
        "-Waggregate-return",
        "-Wnested-externs",
        "-Wold-style-definition",
        "-Wstrict-prototypes",
        "-fno-exceptions"
      ],
      "cflags_cc!": [
        "-fno-exceptions"
      ],
      "cflags_cc": [
        "-Wall",
        "-Wextra",
        "-Wpointer-arith",
        "-Wvla",
        "-Wwrite-strings",
        "-Wno-error=extra",
        "-Wno-error=unused-function",
        "-Wno-error=sign-compare",
        "-Wno-error=strict-aliasing",
        "-Wno-error=type-limits",
        "-Wno-unused-parameter",
        "-Wno-error=unused-variable",
        "-Wno-error=undef",
        "-Wno-error=uninitialized",
        "-Wno-error=unused-result",
        "-Wlogical-op",
        "-Wno-error=maybe-uninitialized",
        "-Wno-error=clobbered",
        "-Wno-error=unused-but-set-variable",
        "-Wno-reorder",
        "-Wno-missing-field-initializers",
        "-fexceptions"
      ],
      "conditions": [
        [
          'OS=="mac"', 
          {
            'xcode_settings': {
              'OTHER_CPLUSPLUSFLAGS': [
                '-stdlib=libc++',
                '-fexceptions',
              ],
              'CLANG_CXX_LIBRARY': 'libc++',
              'CLANG_CXX_LANGUAGE_STANDARD':'c++17',
              'MACOSX_DEPLOYMENT_TARGET': '10.7'
            }
          }
        ],
        [
          "OS=='win'",
          {
            "include_dirs": [
              "src/platform/msc"
            ],
            "configurations": {
              "Release": {
                "msvs_settings": {
                  "VCCLCompilerTool": {
                    "RuntimeLibrary": 0,
                    "Optimization": 3,
                    "FavorSizeOrSpeed": 1,
                    "InlineFunctionExpansion": 2,
                    "WholeProgramOptimization": "true",
                    "OmitFramePointers": "true",
                    "EnableFunctionLevelLinking": "true",
                    "EnableIntrinsicFunctions": "true",
                    "RuntimeTypeInfo": "false",
                    "ExceptionHandling": "0",
                    "AdditionalOptions": [
                      "/EHsc -D_WIN32_WINNT=0x0501 /bigobj /MP /W3 /D_CRT_SECURE_NO_WARNINGS /wd4996 /wd4345 /D_WIN32_WINNT=0x0600 /DWIN32_LEAN_AND_MEAN /DGTEST_HAS_TR1_TUPLE=0 /D_VARIADIC_MAX=8 /D__SSE4_1__"
                    ]
                  },
                  "VCLibrarianTool": {
                    "AdditionalOptions": [
                      "/LTCG"
                    ]
                  },
                  "VCLinkerTool": {
                    "LinkTimeCodeGeneration": 1,
                    "OptimizeReferences": 2,
                    "EnableCOMDATFolding": 2,
                    "LinkIncremental": 1,
                    "AdditionalLibraryDirectories": []
                  }
                }
              }
            }
          }
        ]
      ]
    }
  ]
}
