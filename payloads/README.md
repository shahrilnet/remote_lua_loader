
Use `send_lua.py` to communicate with the loader

### Payloads

1. `hello_world.lua` - Prints basic information back from the game process - its process id, the base of the eboot, libc and libkernel.
2. `sigsegv_crash_trigger.lua` - Triggers two SIGSEGV crashes in succession that should be signal handled without crashing the game process.
3. `notification_popup.lua` - Triggers a notification popup with 'Hello World' on the PlayStation.
4. `sigbus_crash_trigger.lua` - Triggers a SIGBUS crash that should be signal handled without crashing the game process.
5. `streaming_output.lua` - Prints basic information and trigger two SIGSEGV crashes in the middle, to demonstrate how streaming real-time output works.
6. `ftp_server.lua` - Runs an FTP server on port 1337 that allows browsing the filesystem as seen by the game process (e.g. limited filesystem), and also upload and download files.
7. `threading_test.lua` - Provides examples on how to run lua code in new threads
 
