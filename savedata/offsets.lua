
-- Game identification via the last "nibble" of `luaB_auxwrap`.
games_identification = {
    [0xbb0] = "RaspberryCube",
    [0xb90] = "Aibeya",
    [0x170] = "Aikagi2",  -- Family: [F]
    [0x420] = "HamidashiCreative",
    [0x5d0] = "AikagiKimiIsshoniPack",
    [0x280] = "C",
    [0x600] = "E",
    [0xd80] = "IxSHETell",
    [0x660] = "NoraPrincess",  -- CUSA13303 Nora Princess and Stray Cat Heart HD
    [0xb10] = "JinkiResurrection", -- CUSA25179
    [0x410] = "FuyuKiss",
    [0x2e0] = "NoraPrincess2",  -- CUSA13586 Nora Princess and Crying Cat 2
    [0x070] = "SnowDrop" --CUSA14324
}

--[[
Game identification as a tie breaker via a CRC32 hash of the first 0xFF bytes of libc
in the event where game identification via `luaB_auxwrap` is not sufficient.
i.e. Some games have the same eboot but have different libc libraries.
In the event of a clash:
  - Add `clash = 0x1` to libc_addrofs for the parent game.
    - i.e. a game present in `games_identification` above.
  - Add `libc_addrofs` offsets for affected games to the `gadget_table`.
  - Add affected games to `lua.resolve_libc_clash_game_by_name`.
The CRC32 should give the same result as Python zlib's CRC32 implementation.
]]
libc_identification = {
    [0x8e236ee4] = "Aikagi2", -- Family: [F]
    [0xf987a2bc] = "F",
}

gadget_table = {
    raspberry_cube = {
        gadgets = {
            ["ret"] = 0xd2811,

            ["pop rsp; ret"] = 0xa12,
            ["pop rbp; ret"] = 0x79,
            ["pop rax; ret"] = 0xa02,
            ["pop rbx; ret"] = 0x5dce6,
            ["pop rcx; ret"] = 0x147cf,
            ["pop rdx; ret"] = 0x53762,
            ["pop rdi; ret"] = 0x467c69,
            ["pop rsi; ret"] = 0xd2810,
            ["pop r8; ret"] = 0xa01,
            ["mov r9, rbx; call [rax + 8]"] = 0x14a9a0,
            
            ["mov [rax + 8], rcx; ret"] = 0x135aea,
            ["mov [rax + 0x28], rdx; ret"] = 0x148b9f,
            ["mov [rcx + 0xa0], rdi; ret"] = 0xd0bbe,
            ["mov r9, [rax + rsi + 0x18]; xor eax, eax; mov [r8], r9; ret"] = 0x116792,
            ["add rax, r8; ret"] = 0xa893,

            ["mov [rdi], rsi; ret"] = 0xd0d7f,
            ["mov [rdi], rax; ret"] = 0x9522b,
            ["mov [rdi], eax; ret"] = 0x9522c,
            ["add [rbx], eax; ret"] = 0x4091a3,
            ["add [rbx], ecx; ret"] = nil,
            ["mov rax, [rax]; ret"] = 0x1fd5b,
            ["inc dword [rax]; ret"] = 0x1a12eb,

            -- branching specific gadgets
            ["cmp [rax], ebx; ret"] = 0x3e86a8,
            ["sete al; ret"] = 0x538c7,
            ["setne al; ret"] = 0x556,
            ["seta al; ret"] = 0x166fce,
            ["setb al; ret"] = 0x5dd64,
            ["setg al; ret"] = nil,
            ["setl al; ret"] = 0xcb0da,
            ["shl rax, cl; ret"] = 0xd5611,
            ["add rax, rcx; ret"] = 0x354be,

            stack_pivot = {
                ["mov esp, 0xfb0000bd; ret"] = 0x3963d4, -- crash handler
                ["mov esp, 0xf00000b9; ret"] = 0x39c11c, -- native handler
            }
        },
        eboot_addrofs = {
            fake_string = 0x600164, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x1a7bb0, -- to resolve eboot base
            strerror_import = 0x619440, -- to resolve libc base

            luaL_optinteger = 0x1a5590,
            luaL_checklstring = 0x1a5180,
            lua_pushlstring = 0x1a3280,
            lua_pushinteger = 0x1a3260,

            luaL_newstate = 0x1a64d0,
            luaL_openlibs = 0x1b06e0,
            lua_setfield = 0x1a3d40,
            luaL_loadstring = 0x1a6460,
            lua_pcall = 0x1a43e0,
            lua_pushcclosure = 0x1a3490,
            lua_tolstring = 0x1a2990,
            lua_pushstring = 0x1a32e0,
        },
        libc_addrofs = {
            calloc = 0x58a50,
            memcpy = 0x4e9d0,
            setjmp = 0xb6860,
            longjmp = 0xb68b0,
            strerror = 0x42e40,
            error = 0x178,
            sceKernelGetModuleInfoFromAddr = 0x1a8,
            gettimeofday_import = 0x11c010, -- syscall wrapper

            Thrd_join = 0x57ed0,
            Thrd_exit = 0x57f50,
            Thrd_create = 0x58060,

            Mtx_init = 0x582e0,
            Mtx_lock = 0x58370,
            Mtx_unlock = 0x58360,

            Atomic_fetch_add_8 = 0x44240,
        }
    },
    aibeya = {
        gadgets = {    
            ["ret"] = 0x4c,

            ["pop rsp; ret"] = 0xa02,
            ["pop rbp; ret"] = 0x79,
            ["pop rax; ret"] = 0x9f2,
            ["pop rbx; ret"] = 0x60876,
            ["pop rcx; ret"] = 0x14a7f,
            ["pop rdx; ret"] = 0x3f3647,
            ["pop rdi; ret"] = 0x1081c0,
            ["pop rsi; ret"] = 0x10ef32,
            ["pop r8; ret"] = 0x9f1,
            ["mov r9, rbx; call [rax + 8]"] = 0x1511ff,
            
            ["mov [rax + 8], rcx; ret"] = 0x13c4fa,
            ["mov [rax + 0x28], rdx; ret"] = 0x14f43f,
            ["mov [rcx + 0xa0], rdi; ret"] = 0xd753e,
            ["mov r9, [rax + rsi + 0x18]; xor eax, eax; mov [r8], r9; ret"] = 0x11d452,
            ["add rax, r8; ret"] = 0xa7a3,

            ["mov [rdi], rsi; ret"] = 0xd76ff,
            ["mov [rdi], rax; ret"] = 0x994cb,
            ["mov [rdi], eax; ret"] = 0x994cc,
            ["add [rbx], eax; ret"] = nil,
            ["add [rbx], ecx; ret"] = 0x44093b,
            ["mov rax, [rax]; ret"] = 0x2008b,
            ["inc dword [rax]; ret"] = 0x1a82cb,

            -- branching specific gadgets
            ["cmp [rax], ebx; ret"] = 0x40ec68,
            ["sete al; ret"] = 0x55747,
            ["setne al; ret"] = 0x50f,
            ["seta al; ret"] = 0x16dbce,
            ["setb al; ret"] = 0x608f4,
            ["setg al; ret"] = nil,
            ["setl al; ret"] = 0xd1a6a,
            ["shl rax, cl; ret"] = 0xdbf31,
            ["add rax, rcx; ret"] = 0x35afe,

            stack_pivot = {
                ["mov esp, 0xfb0000bd; ret"] = 0x3bca94, -- crash handler
                ["mov esp, 0xf00000b9; ret"] = 0x3c27dc, -- native handler
            }
        },
        eboot_addrofs = {
            fake_string = 0x600164, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x1aeb90, -- to resolve eboot base
            strerror_import = 0x6194A0, -- to resolve libc base

            luaL_optinteger = 0x1ac580,
            luaL_checklstring = 0x1ac170,
            lua_pushlstring = 0x1aa260,
            lua_pushinteger = 0x1aa240,
            
            luaL_newstate = 0x1ad4b0,
            luaL_openlibs = 0x1b7680,
            lua_setfield = 0x1aad30,
            luaL_loadstring = 0x1ad440,
            lua_pcall = 0x1ab3d0,
            lua_pushcclosure = 0x1aa470,
            lua_tolstring = 0x1a9970,
            lua_pushstring = 0x1aa2c0,
        },
        libc_addrofs = {
            calloc = 0x57e00,
            memcpy = 0x4df50,
            setjmp = 0xb5630,
            longjmp = 0xb5680,
            strerror = 0x42540,
            error = 0x168,
            sceKernelGetModuleInfoFromAddr = 0x198,
            gettimeofday_import = 0x204060, -- syscall wrapper

            Thrd_join = 0x57260,
            Thrd_exit = 0x572e0,
            Thrd_create = 0x573f0,

            Mtx_init = 0x57670,
            Mtx_lock = 0x57700,
            Mtx_unlock = 0x576F0,

            Atomic_fetch_add_8 = 0x43900,
        }
    },
    aikagi_2 = {
        gadgets = {
            ["ret"] = 0x4c,
            
            ["pop rsp; ret"] = 0xa02,
            ["pop rbp; ret"] = 0x79,
            ["pop rax; ret"] = 0x9f2,
            ["pop rbx; ret"] = 0x5d436,
            ["pop rcx; ret"] = 0x143af,
            ["pop rdx; ret"] = 0x3d20e7,
            ["pop rdi; ret"] = 0xcd77e,
            ["pop rsi; ret"] = 0x10d92d,
            ["pop r8; ret"] = 0x9f1,
            ["mov r9, rbx; call [rax + 8]"] = nil,
            ["pop r13; pop r14; pop r15; ret"] = 0x1150f3,
            ["mov r9, r13; call [rax + 8]"] = 0x13b504,
            
            ["mov [rax + 8], rcx; ret"] = 0x13b48a,
            ["mov [rax + 0x28], rdx; ret"] = 0x14e21f,
            ["mov [rcx + 0xa0], rdi; ret"] = 0xd6a8e,
            ["mov r9, [rax + rsi + 0x18]; xor eax, eax; mov [r8], r9; ret"] = 0x11bea2,
            ["add rax, r8; ret"] = 0xa083,
            
            ["mov [rdi], rsi; ret"] = 0xd6c4f,
            ["mov [rdi], rax; ret"] = 0x95bbb,
            ["mov [rdi], eax; ret"] = 0x95bbc,
            ["add [rbx], eax; ret"] = nil,
            ["add [rbx], ecx; ret"] = nil,
            ["add [rbx], edi; ret"] = 0x3eb1d3,
            ["mov rax, [rax]; ret"] = 0x1fcdb,
            ["inc dword [rax]; ret"] = 0x1a694b,
            
            -- branching specific gadgets
            ["cmp [rax], ebx; ret"] = 0x3ed708,
            ["sete al; ret"] = 0x52d27,
            ["setne al; ret"] = 0x50f,
            ["seta al; ret"] = 0x16c67e,
            ["setb al; ret"] = 0x5d4b4,
            ["setg al; ret"] = nil,
            ["setl al; ret"] = 0xd103a,
            ["shl rax, cl; ret"] = 0xdb312,
            ["add rax, rcx; ret"] = 0x3582e,
            
            stack_pivot = {
                ["mov esp, 0xfb0000bd; ret"] = 0x39b744, -- crash handler
                ["mov esp, 0xf00000b9; ret"] = 0x3a148c, -- native handler
            }
        },
        eboot_addrofs = {
            fake_string = 0x600164, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x1ad170, -- to resolve eboot base
            strerror_import = 0x619218, -- to resolve libc base
            
            luaL_optinteger = 0x1aaba0,
            luaL_checklstring = 0x1aa790,
            lua_pushlstring = 0x1a88b0,
            lua_pushinteger = 0x1a8890,
            
            luaL_newstate = 0x1abab0,
            luaL_openlibs = 0x1b5b00,
            lua_setfield = 0x1a9370,
            luaL_loadstring = 0x1aba40,
            lua_pcall = 0x1a9a00,
            lua_pushcclosure = 0x1a8ac0,
            lua_tolstring = 0x1a7fc0,
            lua_pushstring = 0x1a8910,
        },
        libc_addrofs = {
            clash = 0x1,
            calloc = 0x4e910,
            memcpy = 0x44150,
            setjmp = 0xb35f0,
            longjmp = 0xb3640,
            strerror = 0x38340,
            error = 0x168,
            sceKernelGetModuleInfoFromAddr = 0x198,
            gettimeofday_import = 0x11ba28, -- syscall wrapper
            
            Thrd_join = 0x4dd20,
            Thrd_exit = 0x4dda0,
            Thrd_create = 0x4df20,

            Mtx_init = 0x4e1a0,
            Mtx_lock = 0x4e230,
            Mtx_unlock = 0x4e220,

            Atomic_fetch_add_8 = 0x39800,
        }
    },
    hamidashi_creative = {
        gadgets = {    
            ["ret"] = 0x42,

            ["pop rsp; ret"] = 0x9a2,
            ["pop rbp; ret"] = 0x79,
            ["pop rax; ret"] = 0x992,
            ["pop rbx; ret"] = 0x5b6e8,
            ["pop rcx; ret"] = 0xe64,
            ["pop rdx; ret"] = 0x3b02d7,
            ["pop rdi; ret"] = 0xc9dfe,
            ["pop rsi; ret"] = 0xd77d,
            ["pop r8; ret"] = 0x991,
            ["mov r9, rbx; call [rax + 8]"] = nil,
            ["pop r13; pop r14; pop r15; ret"] = 0x141fc7,
            ["mov r9, r13; call [rax + 8]"] = 0x136970,
            
            ["mov [rax + 8], rcx; ret"] = 0x1368da,
            ["mov [rax + 0x28], rdx; ret"] = 0x14967f,
            ["mov [rcx + 0xa0], rdi; ret"] = 0xd30ae,
            ["mov r9, [rax + rsi + 0x18]; xor eax, eax; mov [r8], r9; ret"] = 0x117882,
            ["add rax, r8; ret"] = 0x9de0,

            ["mov [rdi], rsi; ret"] = 0xd326f,
            ["mov [rdi], rax; ret"] = 0x92c67,
            ["mov [rdi], eax; ret"] = 0x92c68,
            ["add [rbx], eax; ret"] = nil,
            ["add [rbx], ecx; ret"] = nil,
            ["add [rbx], edi; ret"] = 0x3c95f3,
            ["mov rax, [rax]; ret"] = 0x1eebb,
            ["inc dword [rax]; ret"] = 0x1a0acb,

            -- branching specific gadgets
            ["cmp [rax], ebx; ret"] = 0x3cbb08,
            ["sete al; ret"] = 0x51367,
            ["setne al; ret"] = 0x4bf,
            ["seta al; ret"] = 0x16742e,
            ["setb al; ret"] = 0x5b763,
            ["setg al; ret"] = nil,
            ["setl al; ret"] = 0xcd74a,
            ["shl rax, cl; ret"] = 0xd7885,
            ["add rax, rcx; ret"] = 0x347ae,

            stack_pivot = {
                ["mov esp, 0xfb0000bd; ret"] = 0x3798f4, -- crash handler
                ["mov esp, 0xf00000b9; ret"] = 0x37f63c, -- native handler
            }
        },
        eboot_addrofs = {
            fake_string = 0x600164, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x1a7420, -- to resolve eboot base
            strerror_import = 0x616978, -- to resolve libc base

            luaL_optinteger = 0x1a4d80,
            luaL_checklstring = 0x1a4970,
            lua_pushlstring = 0x1a2a50,
            lua_pushinteger = 0x1a2a30,
            
            luaL_newstate = 0x1a5d40,
            luaL_openlibs = 0x1afdf0,
            lua_setfield = 0x1a3530,
            luaL_loadstring = 0x1a5cd0,
            lua_pcall = 0x1a3bc0,
            lua_pushcclosure = 0x1a2c60,
            lua_tolstring = 0x1a21b0,
            lua_pushstring = 0x1a2ab0,
        },
        libc_addrofs = {
            calloc = 0x4cdb0,
            memcpy = 0x42410,
            setjmp = 0xb0020,
            longjmp = 0xb0070,
            strerror = 0x366e0,
            error = 0x168,
            sceKernelGetModuleInfoFromAddr = 0x198,
            gettimeofday_import = 0x1179a8, -- syscall wrapper

            Thrd_join = 0x4c1c0,
            Thrd_exit = 0x4c240,
            Thrd_create = 0x4c3c0,

            Mtx_init = 0x4c650,
            Mtx_lock = 0x4c6f0,
            Mtx_unlock = 0x4c6e0,

            Atomic_fetch_add_8 = 0x37bf0,
        }
    },
    aikagi_kimi_isshoni_pack = {
        gadgets = {    
            ["ret"] = 0x4c,

            ["pop rsp; ret"] = 0xa12,
            ["pop rbp; ret"] = 0x79,
            ["pop rax; ret"] = 0xa02,
            ["pop rbx; ret"] = 0x5d726,
            ["pop rcx; ret"] = 0x147cf,
            ["pop rdx; ret"] = 0x3cb8b7,
            ["pop rdi; ret"] = 0x51c7d,
            ["pop rsi; ret"] = 0xd2230,
            ["pop r8; ret"] = 0xa01,
            ["mov r9, rbx; call [rax + 8]"] = 0x14a3c0,
            
            ["mov [rax + 8], rcx; ret"] = 0x13550a,
            ["mov [rax + 0x28], rdx; ret"] = 0x1485bf,
            ["mov [rcx + 0xa0], rdi; ret"] = 0xd05de,
            ["mov r9, [rax + rsi + 0x18]; xor eax, eax; mov [r8], r9; ret"] = 0x1161b2,
            ["add rax, r8; ret"] = 0xa893,

            ["mov [rdi], rsi; ret"] = 0xd079f,
            ["mov [rdi], rax; ret"] = 0x94c4b,
            ["mov [rdi], eax; ret"] = 0x94c4c,
            ["add [rbx], eax; ret"] = 0x407a23,
            ["add [rbx], ecx; ret"] = nil,
            ["add [rbx], edi; ret"] = 0x3e4a43,
            ["mov rax, [rax]; ret"] = 0x1fd5b,
            ["inc dword [rax]; ret"] = 0x1a0d0b,

            -- branching specific gadgets
            ["cmp [rax], ebx; ret"] = 0x3e6f28,
            ["sete al; ret"] = 0x53307,
            ["setne al; ret"] = 0x556,
            ["seta al; ret"] = 0x1669ee,
            ["setb al; ret"] = 0x5d7a4,
            ["setg al; ret"] = nil,
            ["setl al; ret"] = 0xcaafa,
            ["shl rax, cl; ret"] = 0xd5031,
            ["add rax, rcx; ret"] = 0x34efe,

            stack_pivot = {
                ["mov esp, 0xfb0000bd; ret"] = 0x394c54, -- crash handler
                ["mov esp, 0xf00000b9; ret"] = 0x39a99c, -- native handler
            }
        },
        eboot_addrofs = {
            fake_string = 0x600164, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x1a75d0, -- to resolve eboot base
            strerror_import = 0x619440, -- to resolve libc base

            luaL_optinteger = 0x1a4fb0,
            luaL_checklstring = 0x1a4ba0,
            lua_pushlstring = 0x1a2ca0,
            lua_pushinteger = 0x1a2c80,
            
            luaL_newstate = 0x1a5ef0,
            luaL_openlibs = 0x1b0100,
            lua_setfield = 0x1a3760,
            luaL_loadstring = 0x1a5e80,
            lua_pcall = 0x1a3e00,
            lua_pushcclosure = 0x1a2eb0,
            lua_tolstring = 0x1a23b0,
            lua_pushstring = 0x1a2d00,
        },
        libc_addrofs = {
            calloc = 0x58a50,
            memcpy = 0x4e9d0,
            setjmp = 0xb6860,
            longjmp = 0xb68b0,
            strerror = 0x42e40,
            error = 0x178,
            sceKernelGetModuleInfoFromAddr = 0x1a8,
            gettimeofday_import = 0x11c010, -- syscall wrapper

            Thrd_join = 0x57ed0,
            Thrd_exit = 0x57f50,
            Thrd_create = 0x58060,

            Mtx_init = 0x582e0,
            Mtx_lock = 0x58370,
            Mtx_unlock = 0x58360,

            Atomic_fetch_add_8 = 0x44240,
        }
    },
    -- not supporting new mov r9, consider dropping
    c = {
        gadgets = {
            ["ret"] = 0x4c,

            ["pop rsp; ret"] = 0x972,
            ["pop rbp; ret"] = 0x79,
            ["pop rax; ret"] = 0x962,
            ["pop rbx; ret"] = 0x3f311,
            ["pop rcx; ret"] = 0xc35,
            ["pop rdx; ret"] = 0x3066e2,
            ["pop rdi; ret"] = 0x107550,
            ["pop rsi; ret"] = 0xfcd16,
            ["pop r8; ret"] = 0x961,
            ["mov r9, rbx; call [rax + 8]"] = 0x145f20,
            
            ["mov [rax + 8], rcx; ret"] = 0x12c5ff,
            ["mov [rax + 0x28], rdx; ret"] = 0x14439f,
            ["mov [rcx + 0xa0], rdi; ret"] = 0xcbc3e,
            ["mov r9, [rax + rsi + 0x18]; xor eax, eax; mov [r8], r9; ret"] = nil,
            ["add rax, r8; ret"] = 0x116d16,

            ["mov [rdi], rsi; ret"] = 0xcbe0f,
            ["mov [rdi], rax; ret"] = 0xa16b,
            ["mov [rdi], eax; ret"] = 0xa16c,
            ["add [rbx], eax; ret"] = 0x405d0b,
            ["add [rbx], ecx; ret"] = nil,
            ["add [rbx], edi; ret"] = 0x3e2e53,
            ["mov rax, [rax]; ret"] = 0x1e55b,
            ["inc dword [rax]; ret"] = 0x18ecbb,

            -- branching specific gadgets
            ["cmp [rax], ebx; ret"] = 0x3e5358,
            ["sete al; ret"] = 0x55bc5,
            ["setne al; ret"] = 0x1c58e,
            ["seta al; ret"] = 0x16187e,
            ["setb al; ret"] = 0x55be4,
            ["setg al; ret"] = nil,
            ["setl al; ret"] = 0xc600a,
            ["shl rax, cl; ret"] = 0xd0623,
            ["add rax, rcx; ret"] = 0x102341,

            stack_pivot = {
                ["mov esp, 0xfb0000bd; ret"] = 0x3925e4, -- crash handler
                ["mov esp, 0xf00000b9; ret"] = 0x39832c, -- native handler
            }
        },
        eboot_addrofs = {
            fake_string = 0x4b0164, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x195280, -- to resolve eboot base
            strerror_import = 0x4CB040, -- to resolve libc base

            luaL_optinteger = 0x192cc0,
            luaL_checklstring = 0x1928b0,
            lua_pushlstring = 0x190a20,
            lua_pushinteger = 0x190a00,
            
            luaL_newstate = 0x193bd0,
            luaL_openlibs = 0x19ce50,
            lua_setfield = 0x1914f0,
            luaL_loadstring = 0x193b60,
            lua_pcall = 0x191b80,
            lua_pushcclosure = 0x190c30,
            lua_tolstring = 0x190220,
            lua_pushstring = 0x190a80,
        },
        libc_addrofs = {
            calloc = 0x5e2e0,
            memcpy = 0x54a60,
            setjmp = 0x71ad0,
            longjmp = 0x71b20,
            strerror = 0x49020,
            error = 0x148,
            sceKernelGetModuleInfoFromAddr = 0x548,
            gettimeofday_import = 0xdbd60, -- syscall wrapper

            Thrd_join = 0x5da90,
            Thrd_exit = 0x5db10,
            Thrd_create = 0x5dc20,

            Mtx_init = 0x43cf0,
            Mtx_lock = 0x43e10,
            Mtx_unlock = 0x43db0,

            Atomic_fetch_add_8 = 0x4a340,
        }
    },
    e = {
        gadgets = {    
            ["ret"] = 0x4c,
            
            ["pop rsp; ret"] = 0x932,
            ["pop rbp; ret"] = 0x79,
            ["pop rax; ret"] = 0x922,
            ["pop rbx; ret"] = 0xd16f5,
            ["pop rcx; ret"] = 0xc15,
            ["pop rdx; ret"] = 0x194902,
            ["pop rdi; ret"] = 0xd74c2,
            ["pop rsi; ret"] = 0xe4b04,
            ["pop r8; ret"] = 0x921,
            ["mov r9, rbx; call [rax + 8]"] = 0x14f760,
            
            ["mov [rax + 8], rcx; ret"] = 0x13b120,
            ["mov [rax + 0x28], rdx; ret"] = 0x14d97f,
            ["mov [rcx + 0xa0], rdi; ret"] = 0xd575e,
            ["mov r9, [rax + rsi + 0x18]; xor eax, eax; mov [r8], r9; ret"] = 0x11c2c2,
            ["add rax, r8; ret"] = 0x125b56,

            ["mov [rdi], rsi; ret"] = 0xd592f,
            ["mov [rdi], rax; ret"] = 0xa42b,
            ["mov [rdi], eax; ret"] = 0xa42c,
            ["add [rbx], eax; ret"] = 0x42a0db,
            ["add [rbx], ecx; ret"] = nil,
            ["add [rbx], edi; ret"] = 0x408943,
            ["mov rax, [rax]; ret"] = 0x201cb,
            ["inc dword [rax]; ret"] = 0x198dbb,

            -- branching specific gadgets
            ["cmp [rax], ebx; ret"] = 0x40ae28,
            ["sete al; ret"] = 0x5e635,
            ["setne al; ret"] = 0x1e39e,
            ["seta al; ret"] = 0x16af0e,
            ["setb al; ret"] = 0x5e654,
            ["setg al; ret"] = nil,
            ["setl al; ret"] = 0xcfc4a,
            ["shl rax, cl; ret"] = 0xda391,
            ["add rax, rcx; ret"] = 0x355ce,

            stack_pivot = {
                ["mov esp, 0xfb0000bd; ret"] = 0x3b8784, -- crash handler
                ["mov esp, 0xf00000b9; ret"] = 0x3be4cc, -- native handler
            }
        },
        eboot_addrofs = {
            fake_string = 0x4d8164, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x19f600, -- to resolve eboot base
            strerror_import = 0x4F3B78, -- to resolve libc base

            luaL_optinteger = 0x19d010,
            luaL_checklstring = 0x19cc00,
            lua_pushlstring = 0x19ad00,
            lua_pushinteger = 0x19ace0,
            
            luaL_newstate = 0x19df60,
            luaL_openlibs = 0x1a7960,
            lua_setfield = 0x19b7c0,
            luaL_loadstring = 0x19def0,
            lua_pcall = 0x19be60,
            lua_pushcclosure = 0x19af10,
            lua_tolstring = 0x19a440,
            lua_pushstring = 0x19ad60,
        },
        libc_addrofs = {
            calloc = 0x22090,
            memcpy = 0x18590,
            setjmp = 0x7f660,
            longjmp = 0x7f6b0,
            strerror = 0xcda0,
            error = 0x138,
            sceKernelGetModuleInfoFromAddr = 0x568,
            gettimeofday_import = 0xefd10, -- syscall wrapper

            Thrd_join = 0x21520,
            Thrd_exit = 0x215a0,
            Thrd_create = 0x216b0,

            Mtx_init = 0x21940,
            Mtx_lock = 0x219d0,
            Mtx_unlock = 0x219c0,

            Atomic_fetch_add_8 = 0xe0c0,
        }
    },
    ixshe_tell = {
        gadgets = {    
            ["ret"] = 0x4c,
            
            ["pop rsp; ret"] = 0xa02,
            ["pop rbp; ret"] = 0x79,
            ["pop rax; ret"] = 0x9f2,
            ["pop rbx; ret"] = 0x608b6,
            ["pop rcx; ret"] = 0x14a7f,
            ["pop rdx; ret"] = 0x3f3ce7,
            ["pop rdi; ret"] = 0x899fb,
            ["pop rsi; ret"] = 0x10f122,
            ["pop r8; ret"] = 0x9f1,
            ["mov r9, rbx; call [rax + 8]"] = 0x1513ef,
            
            ["mov [rax + 8], rcx; ret"] = 0x13c6ea,
            ["mov [rax + 0x28], rdx; ret"] = 0x14f62f,
            ["mov [rcx + 0xa0], rdi; ret"] = 0xd772e,
            ["mov r9, [rax + rsi + 0x18]; xor eax, eax; mov [r8], r9; ret"] = 0x11d642,
            ["add rax, r8; ret"] = 0xa7a3,

            ["mov [rdi], rsi; ret"] = 0xd78ef,
            ["mov [rdi], rax; ret"] = 0x996bb,
            ["mov [rdi], eax; ret"] = 0x996bc,
            ["add [rbx], eax; ret"] = nil,
            ["add [rbx], ecx; ret"] = 0x44107f,
            ["add [rbx], edi; ret"] = 0x40cde3,
            ["mov rax, [rax]; ret"] = 0x2008b,
            ["inc dword [rax]; ret"] = 0x1a84bb,

            -- branching specific gadgets
            ["cmp [rax], ebx; ret"] = 0x40f308,
            ["sete al; ret"] = 0x55787,
            ["setne al; ret"] = 0x50f,
            ["seta al; ret"] = 0x16ddbe,
            ["setb al; ret"] = 0x60934,
            ["setg al; ret"] = nil,
            ["setl al; ret"] = 0xd1c5a,
            ["shl rax, cl; ret"] = 0xdc121,
            ["add rax, rcx; ret"] = 0x35afe,

            stack_pivot = {
                ["mov esp, 0xfb0000bd; ret"] = 0x3bd134, -- crash handler
                ["mov esp, 0xf00000b9; ret"] = 0x3c2e7c, -- native handler
            }
        },
        eboot_addrofs = {
            fake_string = 0x600164, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x1aed80, -- to resolve eboot base
            strerror_import = 0x6194A0, -- to resolve libc base

            luaL_optinteger = 0x1ac770,
            luaL_checklstring = 0x1ac360,
            lua_pushlstring = 0x1aa450,
            lua_pushinteger = 0x1aa430,
            
            luaL_newstate = 0x1ad6a0,
            luaL_openlibs = 0x1b7870,
            lua_setfield = 0x1aaf20,
            luaL_loadstring = 0x1ad630,
            lua_pcall = 0x1ab5c0,
            lua_pushcclosure = 0x1aa660,
            lua_tolstring = 0x1a9b60,
            lua_pushstring = 0x1aa4b0,
        },
        libc_addrofs = {
            calloc = 0x57e00,
            memcpy = 0x4df50,
            setjmp = 0xb5630,
            longjmp = 0xb5680,
            strerror = 0x42540,
            error = 0x168,
            sceKernelGetModuleInfoFromAddr = 0x198,
            gettimeofday_import = 0x204060, -- syscall wrapper

            Thrd_join = 0x57260,
            Thrd_exit = 0x572e0,
            Thrd_create = 0x573f0,

            Mtx_init = 0x57670,
            Mtx_lock = 0x57700,
            Mtx_unlock = 0x576f0,

            Atomic_fetch_add_8 = 0x43900,
        }
    },
    nora_princess = {
        gadgets = {
            ["ret"] = 0x4c,

            ["pop rsp; ret"] = 0x982,
            ["pop rbp; ret"] = 0x79,
            ["pop rax; ret"] = 0x972,
            ["pop rbx; ret"] = 0xd0b25,
            ["pop rcx; ret"] = 0xc62,
            ["pop rdx; ret"] = 0x249e2,
            ["pop rdi; ret"] = 0x509cd,
            ["pop rsi; ret"] = 0xe3534,
            ["pop r8; ret"] = 0x971,

            ["mov r9, rbx; call [rax + 8]"] = 0x14fc50,
            -- or
            ["pop r13; pop r14; pop r15; ret"] = 0x114543,
            ["mov r9, r13; call [rax + 8]"] = 0x13ae54,

            ["mov [rax + 8], rcx; ret"] = 0x13adda,
            ["mov [rax + 0x28], rdx; ret"] = 0x14deaf,
            ["mov [rcx + 0xa0], rdi; ret"] = 0xd4afe,
            ["mov r9, [rax + rsi + 0x18]; xor eax, eax; mov [r8], r9; ret"] = 0x11b4f2,
            ["add rax, r8; ret"] = 0xb423,

            ["mov [rdi], rsi; ret"] = 0xd4ccf,
            ["mov [rdi], rax; ret"] = 0x972db,
            ["mov [rdi], eax; ret"] = nil,

            ["add [rbx], eax; ret"] = 0x425a3b,
            -- or
            ["add [rbx], ecx; ret"] = nil,
            -- or
            ["add [rbx], edi; ret"] = 0x403ad3,

            ["mov rax, [rax]; ret"] = 0x20e3b,
            ["inc dword [rax]; ret"] = 0x199d7b,

            -- branching specific gadgets
            ["cmp [rax], ebx; ret"] = 0x405fc8,
            ["sete al; ret"] = 0x5e495,
            ["setne al; ret"] = 0x1f14e,
            ["seta al; ret"] = 0x16c0ae,
            ["setb al; ret"] = 0x5e4b4,
            ["setg al; ret"] = nil,
            ["setl al; ret"] = 0xcefda,
            ["shl rax, cl; ret"] = 0xd9551,
            ["add rax, rcx; ret"] = 0x366ee,

            stack_pivot = {
                ["mov esp, 0xfb0000bd; ret"] = 0x3b44d4, -- crash handler
                ["mov esp, 0xf00000b9; ret"] = 0x3ba21c, -- native handler
            }
        },
        eboot_addrofs = {
            fake_string = 0x4D8164, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x1A0660, -- to resolve eboot base
            strerror_import = 0x4F3D20, -- to resolve libc base

            luaL_optinteger = 0x19E040,
            luaL_checklstring = 0x19DC30,
            lua_pushlstring = 0x19BD20,
            lua_pushinteger = 0x19BD00,

            luaL_newstate = 0x19EF90,
            luaL_openlibs = 0x1A8FE0,
            lua_setfield = 0x19C7E0,
            luaL_loadstring = 0x19EF20,
            lua_pcall = 0x19CE80,
            lua_pushcclosure = 0x19BF30,
            lua_tolstring = 0x19B430,
            lua_pushstring = 0x19BD80,
        },
        libc_addrofs = {
            calloc = 0x22A90,
            memcpy = 0x18B90,
            setjmp = 0x802A0,
            longjmp = 0x802F0,
            strerror = 0xCF70,
            error = 0x138,
            sceKernelGetModuleInfoFromAddr = 0x568,
            gettimeofday_import = 0xEFE20, -- syscall wrapper

            Thrd_join = 0x21F00,
            Thrd_exit = 0x21F80,
            Thrd_create = 0x22090,

            Mtx_init = 0x22320,
            Mtx_lock = 0x223B0,
            Mtx_unlock = 0x223A0,

            Atomic_fetch_add_8 = 0xE380,
        }
    },
    jinki_resurrection = {
        gadgets = {
            ["ret"] = 0x42,

            ["pop rsp; ret"] = 0x992,
            ["pop rbp; ret"] = 0x79,
            ["pop rax; ret"] = 0x982,
            ["pop rbx; ret"] = 0x5b438,
            ["pop rcx; ret"] = 0xeaa,
            ["pop rdx; ret"] = 0x57802,
            ["pop rdi; ret"] = 0xdcc0e,
            ["pop rsi; ret"] = 0xd330,
            ["pop r8; ret"] = 0x981,

            ["mov r9, rbx; call [rax + 8]"] = nil,
            -- or
            ["pop r13; pop r14; pop r15; ret"] = 0x124418,
            ["mov r9, r13; call [rax + 8]"] = 0x14A5B0,

            ["mov [rax + 8], rcx; ret"] = 0x14A51A,
            ["mov [rax + 0x28], rdx; ret"] = 0x15D52F,
            ["mov [rcx + 0xa0], rdi; ret"] = 0xE5FBE,
            ["mov r9, [rax + rsi + 0x18]; xor eax, eax; mov [r8], r9; ret"] = 0x12B062,
            ["add rax, r8; ret"] = 0x9E70,

            ["mov [rdi], rsi; ret"] = 0xE617F,
            ["mov [rdi], rax; ret"] = 0xA5C17,
            ["mov [rdi], eax; ret"] = 0xA5C18,

            ["add [rbx], eax; ret"] = nil,
            -- or
            ["add [rbx], ecx; ret"] = nil,
            -- or
            ["add [rbx], edi; ret"] = 0x482E23,

            ["mov rax, [rax]; ret"] = 0x1E75B,
            ["inc dword [rax]; ret"] = 0x1B507B,

            -- branching specific gadgets
            ["cmp [rax], ebx; ret"] = 0x485348,
            ["sete al; ret"] = 0x51097,
            ["setne al; ret"] = 0x4BF,
            ["seta al; ret"] = 0x17B56E,
            ["setb al; ret"] = 0x5B4B4,
            ["setg al; ret"] = nil,
            ["setl al; ret"] = 0xE055A,
            ["shl rax, cl; ret"] = 0xEA805,
            ["add rax, rcx; ret"] = 0x3407E,

            stack_pivot = {
                ["mov esp, 0xfb0000bd; ret"] = 0x433174, -- crash handler
                ["mov esp, 0xf00000b9; ret"] = 0x438EBC, -- native handler
            }
        },
        eboot_addrofs = {
            fake_string = 0x600164, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x1BBB10, -- to resolve eboot base
            strerror_import = 0x61B0C0, -- to resolve libc base

            luaL_optinteger = 0x1B94B0,
            luaL_checklstring = 0x1B90A0,
            lua_pushlstring = 0x1B7140,
            lua_pushinteger = 0x1B7120,

            luaL_newstate = 0x1BA430,
            luaL_openlibs = 0x1C4510,
            lua_setfield = 0x1B7C20,
            luaL_loadstring = 0x1BA3C0,
            lua_pcall = 0x1B82B0,
            lua_pushcclosure = 0x1B7350,
            lua_tolstring = 0x1B6830,
            lua_pushstring = 0x1B71A0,
        },
        libc_addrofs = {
            calloc = 0x4D610,
            memcpy = 0x42B10,
            setjmp = 0xB11B0,
            longjmp = 0xB1200,
            strerror = 0x36C90,
            error = 0x168,
            sceKernelGetModuleInfoFromAddr = 0x198,
            gettimeofday_import = 0x1179A8,

            Thrd_join = 0x4CA20,
            Thrd_exit = 0x4CAA0,
            Thrd_create = 0x4CC20,

            Mtx_init = 0x4CEA0,
            Mtx_lock = 0x4CF30,
            Mtx_unlock = 0x4CF20,

            Atomic_fetch_add_8 = 0x381C0,
        }
    },
    fuyu_kiss = {
        gadgets = {
            ["ret"] = 0x42,
            
            ["pop rsp; ret"] = 0x66090,
            ["pop rbp; ret"] = 0x79,
            ["pop rax; ret"] = 0xb02,
            ["pop rbx; ret"] = 0x5d918,
            ["pop rcx; ret"] = 0x12c4,
            ["pop rdx; ret"] = 0x1bfbf2,
            ["pop rdi; ret"] = 0xe0b3e,
            ["pop rsi; ret"] = 0xe0fd,
            ["pop r8; ret"] = 0xb01,
            ["mov r9, rbx; call [rax + 8]"] = nil,
            ["pop r13; pop r14; pop r15; ret"] = 0x158107,
            ["mov r9, r13; call [rax + 8]"] = 0x14ca80,
            
            ["mov [rax + 8], rcx; ret"] = 0x14c9ea,
            ["mov [rax + 0x28], rdx; ret"] = 0x15f83f,
            ["mov [rcx + 0xa0], rdi; ret"] = 0xe9dae,
            ["mov r9, [rax + rsi + 0x18]; xor eax, eax; mov [r8], r9; ret"] = 0x12ddf2,
            ["add rax, r8; ret"] = 0xae10,
            
            ["mov [rdi], rsi; ret"] = 0xe9f6f,
            ["mov [rdi], rax; ret"] = 0xa99b7,
            ["mov [rdi], eax; ret"] = 0xa99b8,
            ["add [rbx], eax; ret"] = nil,
            ["add [rbx], ecx; ret"] = nil,
            ["add [rbx], edi; ret"] = 0x4825f3,
            ["mov rax, [rax]; ret"] = 0x202fb,
            ["inc [rax]; ret"] = 0x1b6bab,
            
            -- branching specific gadgets
            ["cmp [rax], ebx; ret"] = 0x484b28,
            ["sete al; ret"] = 0x533b7,
            ["setne al; ret"] = 0x4cf,
            ["seta al; ret"] = 0x17d66e,
            ["setb al; ret"] = 0x5d993,
            ["setg al; ret"] = nil,
            ["setl al; ret"] = 0xe448a,
            ["shl rax, cl; ret"] = 0xee635,
            ["add rax, rcx; ret"] = 0x3618e,
            
            stack_pivot = {
                ["mov esp, 0xfb0000bd; ret"] = 0x432954, -- crash handler
                ["mov esp, 0xf00000b9; ret"] = 0x43869c, -- native handler
            }
        },
        eboot_addrofs = {
            fake_string = 0x600184, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x1bd410, -- to resolve eboot base
            strerror_import = 0x61C700, -- to resolve libc base
            
            luaL_optinteger = 0x1bad80,
            luaL_checklstring = 0x1ba970,
            lua_pushlstring = 0x1b8aa0,
            lua_pushinteger = 0x1b8a80,
            
            luaL_newstate = 0x1bbd40,
            luaL_openlibs = 0x1c5dd0,
            lua_setfield = 0x1b9540,
            luaL_loadstring = 0x1bbcd0,
            lua_pcall = 0x1b9bd0,
            lua_pushcclosure = 0x1b8cc0,
            lua_tolstring = 0x1b8230,
            lua_pushstring = 0x1b8b00,
        },
        libc_addrofs = {
            calloc = 0x4d160,
            memcpy = 0x42410,
            setjmp = 0xb0450,
            longjmp = 0xb04a0,
            strerror = 0x36690,
            error = 0x168,
            sceKernelGetModuleInfoFromAddr = 0x198,
            gettimeofday_import = 0x1179a8,
            
            Thrd_join = 0x4c570,
            Thrd_exit = 0x4c5f0,
            Thrd_create = 0x4c770,
            Mtx_init = 0x4ca00,
            Mtx_lock = 0x4caa0,
            Mtx_unlock = 0x4ca90,
            
            Atomic_fetch_add_8 = 0x37b80,
        }
    },
    nora_princess2 = {
        gadgets = {
            ["ret"] = 0x4c,

            ["pop rsp; ret"] = 0xa42,
            ["pop rbp; ret"] = 0x79,
            ["pop rax; ret"] = 0xa32,
            ["pop rbx; ret"] = 0xd17a5,
            ["pop rcx; ret"] = 0xd32,
            ["pop rdx; ret"] = 0x2e1a32,
            ["pop rdi; ret"] = 0xc608d,
            ["pop rsi; ret"] = 0x785e2,
            ["pop r8; ret"] = 0xa31,

            ["mov r9, rbx; call [rax + 8]"] = 0x1508d0,
            -- or
            ["pop r13; pop r14; pop r15; ret"] = 0x1151c3,
            ["mov r9, r13; call [rax + 8]"] = 0x13bad4,

            ["mov [rax + 8], rcx; ret"] = 0x13ba5a,
            ["mov [rax + 0x28], rdx; ret"] = 0x14eb2f,
            ["mov [rcx + 0xa0], rdi; ret"] = 0xd577e,
            ["mov r9, [rax + rsi + 0x18]; xor eax, eax; mov [r8], r9; ret"] = 0x11c172,
            ["add rax, r8; ret"] = 0xac83,

            ["mov [rdi], rsi; ret"] = 0xd594f,
            ["mov [rdi], rax; ret"] = 0x97f5b,
            ["mov [rdi], eax; ret"] = nil,

            ["add [rbx], eax; ret"] = 0x426c1f,
            -- or
            ["add [rbx], ecx; ret"] = nil,
            -- or
            ["add [rbx], edi; ret"] = 0x404e33,

            ["mov rax, [rax]; ret"] = 0x2075b,
            ["inc dword [rax]; ret"] = 0x19a9fb,

            -- branching specific gadgets
            ["cmp [rax], ebx; ret"] = 0x407328,
            ["sete al; ret"] = 0x5e765,
            ["setne al; ret"] = 0x573,
            ["seta al; ret"] = 0x16cd2e,
            ["setb al; ret"] = 0x5e784,
            ["setg al; ret"] = nil,
            ["setl al; ret"] = 0xcfc5a,
            ["shl rax, cl; ret"] = 0xda1d1,
            ["add rax, rcx; ret"] = 0x36a6e,

            stack_pivot = {
                ["mov esp, 0xfb0000bd; ret"] = 0x3b5824, -- crash handler
                ["mov esp, 0xf00000b9; ret"] = 0x3bb56c, -- native handler
            }
        },
        eboot_addrofs = {
            fake_string = 0x4D8164, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x1A12E0, -- to resolve eboot base
            strerror_import = 0x4F3D60, -- to resolve libc base

            luaL_optinteger = 0x19ECC0,
            luaL_checklstring = 0x19E8B0,
            lua_pushlstring = 0x19C9A0,
            lua_pushinteger = 0x19C980,

            luaL_newstate = 0x19FC10,
            luaL_openlibs = 0x1A9C60,
            lua_setfield = 0x19D460,
            luaL_loadstring = 0x19FBA0,
            lua_pcall = 0x19DB00,
            lua_pushcclosure = 0x19CBB0,
            lua_tolstring = 0x19C0B0,
            lua_pushstring = 0x19CA00,
        },
        libc_addrofs = {
            calloc = 0x22A90,
            memcpy = 0x18B90,
            setjmp = 0x802A0,
            longjmp = 0x802F0,
            strerror = 0xCF70,
            error = 0x138,
            sceKernelGetModuleInfoFromAddr = 0x568,
            gettimeofday_import = 0xEFE20, -- syscall wrapper

            Thrd_join = 0x21F00,
            Thrd_exit = 0x21F80,
            Thrd_create = 0x22090,

            Mtx_init = 0x22320,
            Mtx_lock = 0x223B0,
            Mtx_unlock = 0x223A0,

            Atomic_fetch_add_8 = 0xE380,
        }
    },
    -- Games with clashes below here, only libc offsets are required.
    f = {  -- Clashes with Aikagi2
        libc_addrofs = {
            calloc = 0x4E910,
            memcpy = 0x44150,
            setjmp = 0xB2D60,
            longjmp = 0xB2DB0,
            strerror = 0x38340,
            error = 0x168,
            sceKernelGetModuleInfoFromAddr = 0x198,
            gettimeofday_import = 0x11BA78, -- syscall wrapper

            Thrd_join = 0x4DD20,
            Thrd_exit = 0x4DDA0,
            Thrd_create = 0x4DF20,

            Mtx_init = 0x4E1A0,
            Mtx_lock = 0x4E230,
            Mtx_unlock = 0x4E220,

            Atomic_fetch_add_8 = 0x39800,
        }
    },
    snow_drop = {
        gadgets = {
            ["ret"] = 0x4C,

            ["pop rsp; ret"] = 0xA42,
            ["pop rbp; ret"] = 0x79,
            ["pop rax; ret"] = 0xA32,
            ["pop rbx; ret"] = 0xD1535,
            ["pop rcx; ret"] = 0xD32,
            ["pop rdx; ret"] = 0x3EAD17,
            ["pop rdi; ret"] = 0xD71C2,
            ["pop rsi; ret"] = 0xA5376,
            ["pop r8; ret"] = 0xa31,

            ["mov r9, rbx; call [rax + 8]"] = 0x150660,

            ["pop r13; pop r14; pop r15; ret"] = 0x114F53,
            ["mov r9, r13; call [rax + 8]"] = 0x13B864,

            ["mov [rax + 8], rcx; ret"] = 0x13B7EA,
            ["mov [rax + 0x28], rdx; ret"] = 0x14E8BF,
            ["mov [rcx + 0xa0], rdi; ret"] = 0xD550E,
            ["mov r9, [rax + rsi + 0x18]; xor eax, eax; mov [r8], r9; ret"] = 0x11BF02,
            ["add rax, r8; ret"] = 0xAC43,

            ["mov [rdi], rsi; ret"] = 0xD56DF,
            ["mov [rdi], rax; ret"] = 0x97CEB,
            ["mov [rdi], eax; ret"] = 0x97CEC,

            ["add [rbx], eax; ret"] = 0x4253FF,
            ["add [rbx], ecx; ret"] = nil,
            ["add [rbx], edi; ret"] = 0x403653,
            ["mov rax, [rax]; ret"] = 0x2069B,
            ["inc dword [rax]; ret"] = 0x19A78B,

            ["cmp [rax], ebx; ret"] = 0x405B48,
            ["sete al; ret"] = 0x5E515,
            ["setne al; ret"] = 0x573,
            ["seta al; ret"] = 0x16CABE,
            ["setb al; ret"] = 0x5E534,
            ["setg al; ret"] = nil,
            ["setl al; ret"] = 0xCF9EA,
            ["shl rax, cl; ret"] = 0xD9F61,
            ["add rax, rcx; ret"] = 0x3681E,

            stack_pivot = {
                ["mov esp, 0xfb0000bd; ret"] = 0x3B4054,
                ["mov esp, 0xf00000b9; ret"] = 0x3B9D9C,
            }
        },
        eboot_addrofs = {
            fake_string = 0x4D8164,
            luaB_auxwrap = 0x1a1070,
            strerror_import = 0x4f3d40,

            luaL_optinteger = 0x19ea50,
            luaL_checklstring = 0x19e640,
            lua_pushlstring = 0x19c730,
            lua_pushinteger = 0x19c710,

            luaL_newstate = 0x19f9a0,
            luaL_openlibs = 0x1a99f0,
            lua_setfield = 0x19d1f0,
            luaL_loadstring = 0x19f930,
            lua_pcall = 0x19d890,
            lua_pushcclosure = 0x19c940,
            lua_tolstring = 0x19be40,
            lua_pushstring = 0x19c790,
        },
        libc_addrofs = {
            calloc = 0x22a90,
            memcpy = 0x18b90,
            setjmp = 0x802a0,
            longjmp = 0x802f0,
            strerror = 0xcf70,
            error = 0x138,
            sceKernelGetModuleInfoFromAddr = 0x568,
            gettimeofday_import = 0xefe20,

            Thrd_join = 0x21f00,
            Thrd_exit = 0x21f80,
            Thrd_create = 0x22090,

            Mtx_init = 0x22320,
            Mtx_lock = 0x223b0,
            Mtx_unlock = 0x223a0,

            Atomic_fetch_add_8 = 0xe380
        }

    },
}
