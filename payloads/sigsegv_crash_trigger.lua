function check_prerequisites()
    if not memory then
        errorf("stage #1 not loaded")
    end
end

function main()
    memory.write_qword(0x0000424700004343, 0)
    memory.write_qword(0x0000444800004949, 0)
end

check_prerequisites()
main()
