function check_prerequisites()
    if not memory then
        errorf("stage #1 not loaded")
    end
end

function main()
    print("hello world from lua!\n")
    printf("eboot base @ " .. hex(eboot_base))
    printf("libc base @ " .. hex(libc_base))
    printf("libkernel base @ " .. hex(libkernel_base))
    memory.write_qword(0x0000424700004343, 0)
    print("not sure you should see this")
    memory.write_qword(0x0000444800004949, 0)
    print("after 2 SIGSEGV")
end

check_prerequisites()
main()
