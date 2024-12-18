
function main()

    local pid = syscall.getpid():tonumber()

    syscall.resolve({
        getppid = 39,
    })

    local ppid = syscall.getppid():tonumber()

    print()
    print("hello world from lua!\n")
    printf("platform %s (%s)\n", PLATFORM, FW_VERSION)
    printf("pid %d ppid %d\n", pid, ppid)
    printf("eboot base @ " .. hex(eboot_base))
    printf("libc base @ " .. hex(libc_base))
    printf("libkernel base @ " .. hex(libkernel_base))

end

main()
