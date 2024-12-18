function check_prerequisites()
    if not memory then
        errorf("stage #1 not loaded")
    end
end

function main()
    memory.write_qword(0x4242424700004343, 0)
end

check_prerequisites()
main()
