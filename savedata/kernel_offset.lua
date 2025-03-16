
-- kernel offsets
-- credit to @hammer-83 for these offsets
-- https://github.com/hammer-83/ps5-jar-loader/blob/main/sdk/src/main/java/org/ps5jb/sdk/core/kernel/KernelOffsets.java

ps5_kernel_offset_list = {

    [{ "1.00", "1.01", "1.02" }] = {

        DATA_BASE = 0x01B40000,
        DATA_SIZE = 0x08631930,

        DATA_BASE_DYNAMIC = 0x00000000,
        DATA_BASE_TO_DYNAMIC = 0x0658BB58,
        DATA_BASE_ALLPROC = 0x026D1BF8,
        DATA_BASE_SECURITY_FLAGS = 0x06241074,
        DATA_BASE_ROOTVNODE = 0x06565540,
        DATA_BASE_KERNEL_PMAP_STORE = 0x02F9F2B8,
        DATA_BASE_DATA_CAVE = 0x05F20000,
        DATA_BASE_GVMSPACE = 0x06202E70,

        PMAP_STORE_PML4PML4I = -0x1C,
        PMAP_STORE_DMPML4I = 0x288,
        PMAP_STORE_DMPDPI = 0x28C,
    },

    [{ "1.05", "1.10", "1.11", "1.12", "1.13", "1.14" }] = {

        DATA_BASE = 0x01B40000,
        DATA_SIZE = 0x08631930,

        DATA_BASE_DYNAMIC = 0x00000000,
        DATA_BASE_TO_DYNAMIC = 0x0658BB58,
        DATA_BASE_ALLPROC = 0x026D1C18,
        DATA_BASE_SECURITY_FLAGS = 0x06241074,
        DATA_BASE_ROOTVNODE = 0x06565540,
        DATA_BASE_KERNEL_PMAP_STORE = 0x02F9F328,
        DATA_BASE_DATA_CAVE = 0x05F20000,
        DATA_BASE_GVMSPACE = 0x06202E70,

        PMAP_STORE_PML4PML4I = -0x1C,
        PMAP_STORE_DMPML4I = 0x288,
        PMAP_STORE_DMPDPI = 0x28C,
    },

    [{ "2.00", "2.20", "2.25", "2.26", "2.30", "2.50", "2.70" }] = {

        DATA_BASE = 0x01B80000,
        DATA_SIZE = 0x087E1930,

        DATA_BASE_DYNAMIC = 0x00000000,
        DATA_BASE_TO_DYNAMIC = 0x06739B88,
        DATA_BASE_ALLPROC = 0x02701C28,
        DATA_BASE_SECURITY_FLAGS = 0x063E1274,
        DATA_BASE_ROOTVNODE = 0x067134C0,
        DATA_BASE_KERNEL_PMAP_STORE = 0x031338C8,
        DATA_BASE_DATA_CAVE = 0x060C0000,  -- Use same as Specter's Byepervisor repo for interop
        DATA_BASE_GVMSPACE = 0x063A2EB0,

        PMAP_STORE_PML4PML4I = -0x1C,
        PMAP_STORE_DMPML4I = 0x288,
        PMAP_STORE_DMPDPI = 0x28C,
    },

    [{ "3.00", "3.20", "3.21" }] = {

        DATA_BASE = 0x0BD0000,
        DATA_SIZE = 0x08871930,

        DATA_BASE_DYNAMIC = 0x00010000,
        DATA_BASE_TO_DYNAMIC = 0x067D1B90,
        DATA_BASE_ALLPROC = 0x0276DC58,
        DATA_BASE_SECURITY_FLAGS = 0x06466474,
        DATA_BASE_ROOTVNODE = 0x067AB4C0,
        DATA_BASE_KERNEL_PMAP_STORE = 0x031BE218,
        DATA_BASE_DATA_CAVE = 0x06140000,  -- Unconfirmed
        DATA_BASE_GVMSPACE = 0x06423F80,

        PMAP_STORE_PML4PML4I = -0x1C,
        PMAP_STORE_DMPML4I = 0x288,
        PMAP_STORE_DMPDPI = 0x28C,
    },

    [{ "4.00", "4.02", "4.03", "4.50", "4.51" }] = {

        DATA_BASE = 0x0C00000,
        DATA_SIZE = 0x087B1930,

        DATA_BASE_DYNAMIC = 0x00010000,
        DATA_BASE_TO_DYNAMIC = 0x0670DB90,
        DATA_BASE_ALLPROC = 0x027EDCB8,
        DATA_BASE_SECURITY_FLAGS = 0x06506474,
        DATA_BASE_ROOTVNODE = 0x066E74C0,
        DATA_BASE_KERNEL_PMAP_STORE = 0x03257A78,
        DATA_BASE_DATA_CAVE = 0x06C01000,  -- Unconfirmed
        DATA_BASE_GVMSPACE = 0x064C3F80,

        PMAP_STORE_PML4PML4I = -0x1C,
        PMAP_STORE_DMPML4I = 0x288,
        PMAP_STORE_DMPDPI = 0x28C,
    },

    [{ "5.00", "5.02" , "5.10"}] = {

        DATA_BASE = 0x0C40000,
        DATA_SIZE = 0x08921930,

        DATA_BASE_DYNAMIC = 0x00010000,
        DATA_BASE_TO_DYNAMIC = 0x06879C00,
        DATA_BASE_ALLPROC = 0x0291DD00,
        DATA_BASE_SECURITY_FLAGS = 0x066466EC,
        DATA_BASE_ROOTVNODE = 0x06853510,
        DATA_BASE_KERNEL_PMAP_STORE = 0x03398A88,
        DATA_BASE_DATA_CAVE = 0x06320000,  -- Unconfirmed
        DATA_BASE_GVMSPACE = 0x06603FB0,

        PMAP_STORE_PML4PML4I = -0x105C,
        PMAP_STORE_DMPML4I = 0x29C,
        PMAP_STORE_DMPDPI = 0x2A0,
    },

    [{ "5.50" }] = {

        DATA_BASE = 0x0C40000,
        DATA_SIZE = 0x08921930,

        DATA_BASE_DYNAMIC = 0x00010000,
        DATA_BASE_TO_DYNAMIC = 0x06879C00,
        DATA_BASE_ALLPROC = 0x0291DD00,
        DATA_BASE_SECURITY_FLAGS = 0x066466EC,
        DATA_BASE_ROOTVNODE = 0x06853510,
        DATA_BASE_KERNEL_PMAP_STORE = 0x03394A88,
        DATA_BASE_DATA_CAVE = 0x06320000,  -- Unconfirmed
        DATA_BASE_GVMSPACE = 0x06603FB0,

        PMAP_STORE_PML4PML4I = -0x105C,
        PMAP_STORE_DMPML4I = 0x29C,
        PMAP_STORE_DMPDPI = 0x2A0,
    },

    [{ "6.00", "6.02", "6.50" }] = {

        DATA_BASE = 0x0C60000,
        DATA_SIZE = 0x08861930,

        DATA_BASE_DYNAMIC = 0x00010000,
        DATA_BASE_TO_DYNAMIC = 0x067C5C10,
        DATA_BASE_ALLPROC = 0x02869D20,
        DATA_BASE_SECURITY_FLAGS = 0x065968EC,
        DATA_BASE_ROOTVNODE = 0x0679F510,
        DATA_BASE_KERNEL_PMAP_STORE = 0x032E4358,
        DATA_BASE_DATA_CAVE = 0x06270000,  -- Unconfirmed
        DATA_BASE_GVMSPACE = 0x065540F0,

        PMAP_STORE_PML4PML4I = -0x105C,
        PMAP_STORE_DMPML4I = 0x29C,
        PMAP_STORE_DMPDPI = 0x2A0,
    },

    [{ "7.00", "7.01", "7.20", "7.40", "7.60", "7.61" }] = {

        DATA_BASE = 0x0C50000,
        DATA_SIZE = 0x05191930,

        DATA_BASE_DYNAMIC = 0x00010000,
        DATA_BASE_TO_DYNAMIC = 0x030EDC40,
        DATA_BASE_ALLPROC = 0x02859D50,
        DATA_BASE_SECURITY_FLAGS = 0x00AC8064,
        DATA_BASE_ROOTVNODE = 0x030C7510,
        DATA_BASE_KERNEL_PMAP_STORE = 0x02E2C848,
        DATA_BASE_DATA_CAVE = 0x050A1000,  -- Unconfirmed
        DATA_BASE_GVMSPACE = 0x02E76090,

        PMAP_STORE_PML4PML4I = -0x10AC,
        PMAP_STORE_DMPML4I = 0x29C,
        PMAP_STORE_DMPDPI = 0x2A0,
    },
}

function get_ps5_kernel_offset()

    if PLATFORM ~= "ps5" then
        error("only ps5 is supported by now")
    end

    local koffset = nil

    for fw_list, offsets in pairs(ps5_kernel_offset_list) do
        for i, check_fw in ipairs(fw_list) do
            if check_fw == FW_VERSION then
                koffset = offsets
                break
            end
        end
    end

    if not koffset then
        errorf("failed to find offset for fw %s", FW_VERSION)
    end

    koffset.DATA_BASE_TARGET_ID = koffset.DATA_BASE_SECURITY_FLAGS + 0x09
    koffset.DATA_BASE_QA_FLAGS = koffset.DATA_BASE_SECURITY_FLAGS + 0x24
    koffset.DATA_BASE_UTOKEN_FLAGS = koffset.DATA_BASE_SECURITY_FLAGS + 0x8C

    -- static structure offsets
    -- note: the one marked with -1 will be resolved at runtime

    -- proc structure
    koffset.PROC_PID = 0xbc
    koffset.PROC_VM_SPACE = 0x200
    koffset.PROC_COMM = -1
    koffset.PROC_SYSENT = -1

    -- vmspace structure
    koffset.VMSPACE_VM_PMAP = -1
    koffset.VMSPACE_VM_VMID = -1

    -- pmap structure
    koffset.PMAP_CR3 = 0x28

    -- gpu vmspace structure
    koffset.SIZEOF_GVMSPACE = 0x100
    koffset.GVMSPACE_START_VA = 0x8
    koffset.GVMSPACE_SIZE = 0x10
    koffset.GVMSPACE_PAGE_DIR_VA = 0x38

    return koffset
end
