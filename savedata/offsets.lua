
games_identification = {
    [0xbb0] = "RaspberryCube",
    [0xb90] = "Aibeya",
    [0x420] = "HamidashiCreative",
    [0x5d0] = "AikagiKimiIsshoniPack",
    [0x280] = "C",
    [0x600] = "E",
    [0xd80] = "F",
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
            ["cmp [rcx], eax; ret"] = 0x2dcc59,
            ["cmp [rax], eax; ret"] = nil,
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
            longjmp_import = 0x619388, -- to resolve libc base

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

            scePthreadMutexLock = 0x1e8,
            scePthreadMutexUnlock = 0x1f8,
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
            ["cmp [rcx], eax; ret"] = 0x303609,
            ["cmp [rax], eax; ret"] = 0x44ef72,
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
            longjmp_import = 0x6193e8, -- to resolve libc base

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

            scePthreadMutexLock = 0x1d8,
            scePthreadMutexUnlock = 0x1e8,
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
            ["pop r13 ; pop r14 ; pop r15 ; ret"] = 0x141fc7,
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
            ["cmp [rcx], eax; ret"] = nil,
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
            longjmp_import = 0x6168c0, -- to resolve libc base

            luaL_optinteger = 0x1a4d80,
            luaL_checklstring = 0x1a4970,
            lua_pushlstring = 0x1a2a50,
            lua_pushinteger = 0x1a2a30,
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
            ["cmp [rcx], eax; ret"] = 0x2db4d9,
            ["cmp [rax], ebx; ret"] = nil,
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
            longjmp_import = 0x619388, -- to resolve libc base

            luaL_optinteger = 0x1a4fb0,
            luaL_checklstring = 0x1a4ba0,
            lua_pushlstring = 0x1a2ca0,
            lua_pushinteger = 0x1a2c80,
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
            ["cmp [rcx], eax; ret"] = 0x2d2d79,
            ["cmp [rax], ebx; ret"] = nil,
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
            fake_string = 0x600164, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x195280, -- to resolve eboot base
            longjmp_import = 0x4caf88, -- to resolve libc base

            luaL_optinteger = 0x192cc0,
            luaL_checklstring = 0x1928b0,
            lua_pushlstring = 0x190a20,
            lua_pushinteger = 0x190a00,
        },
        libc_addrofs = {
            calloc = 0x5e2e0,
            memcpy = 0x54a60,
            setjmp = 0x74ad0,
            longjmp = 0x71b20,
            strerror = 0x49020,
            error = 0x148,
            sceKernelGetModuleInfoFromAddr = 0x548,
            gettimeofday_import = 0xdbd60, -- syscall wrapper
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
            ["cmp [rcx], eax; ret"] = 0x2f93a9,
            ["cmp [rax], eax; ret"] = nil,
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
            fake_string = 0x600164, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x19f600, -- to resolve eboot base
            longjmp_import = 0x4f3ac0, -- to resolve libc base

            luaL_optinteger = 0x19d010,
            luaL_checklstring = 0x19cc00,
            lua_pushlstring = 0x19ad00,
            lua_pushinteger = 0x19ace0,
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
        }
    },
    f = {
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
            ["cmp [rcx], eax; ret"] = 0x303ca9,
            ["cmp [rax], eax; ret"] = 0x44f6fe,
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
            longjmp_import = 0x6193e8, -- to resolve libc base

            luaL_optinteger = 0x1ac770,
            luaL_checklstring = 0x1ac360,
            lua_pushlstring = 0x1aa450,
            lua_pushinteger = 0x1aa430,
        },
        libc_addrofs = {
            calloc = 0x57e00,
            memcpy = 0x4df0,
            setjmp = 0xb5630,
            longjmp = 0xb5680,
            strerror = 0x42540,
            error = 0x168,
            sceKernelGetModuleInfoFromAddr = 0x198,
            gettimeofday_import = 0x204060, -- syscall wrapper
        }
    },
}