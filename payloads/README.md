
Use `send_lua.py` to communicate with the loader

Examples:
* `$ python send_lua.py <IP> 9026 hello_world.lua` - Run a simple payload
* `$ python send_lua.py <IP> 9026 --disable-signal-handler` - Disable signal handler on the loader

### Payloads

| Payload | Description |
| -------- | ------- |
| hello_world.lua | Prints basic information back from the game process - its process id, the base of the eboot, libc and libkernel. |
| ftp_server.lua | Runs an FTP server on port 1337 that allows browsing the filesystem as seen by the game process, and also upload and download files. If the game process is jailbroken, it can access more files / directories on the filesystem. Use WinSCP as FTP client. FileZilla has known issues currently. |
| umtx.lua | Kernel exploit for PS5 (fw <= 7.61). Once done, it will jailbreak the game process as well as the PlayStation, allowing for more access to the system. |
| lapse.lua | Kernel exploit for PS5 (fw <= 10.01) and PS4 (5.00 <= fw <= 12.02). It will jailbreak the game process as well as the PlayStation, allowing for more access to the system. |

### Payloads after getting kernel r/w

| Payload | Target | Description |
| -------- | ------- | ------- |
| kdata_dumper.lua | PS5 | Dump content of kernel data segments over network until it crashes. (NOTE: you must modify the IP address before you run this payload) |

### Payloads after jailbroken game process

| Payload | Target | Description |
| -------- | ------- | ------- |
| read_klog.lua | PS5 | Read content of `/dev/klog`. |
| elf_loader.lua | PS5 | Rudimentary ELF loader to load from file system. By default it will try to load John Tornblom's [elfldr.elf](https://github.com/ps5-payload-dev/elfldr) shipped with savedata, or alternatively from `/data/elfldr.elf` if you need to have updated elfldr.elf (you need to place there yourself using FTP server). |
| bin_loader.lua | PS4 | Rudimentary payload loader to load from a socket on port 9021, or alternatively from `/data/payload.bin`. |
| kernel_dumper.lua | PS4 | Dump content of kernel . (NOTE: you must connect a USB drive to the PS4 before running this payload) |

### send_lua.py additional options

| Option | Description |
| -------- | ------- |
| --enable-signal-handler | Enables the option to catch signals (such as crash, etc) |
| --disable-signal-handler | Disables the option to catch signals. |