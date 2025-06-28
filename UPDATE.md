### Update your existing savedata

There are 3 methods to updating your existing savedata/save files:
1. Use [Playstation-5-Save-Mounter](https://github.com/n0llptr/Playstation-5-Save-Mounter) [Recommended and easiest-to-use]
2. Edit or recreate a new save file using the steps in [SETUP.md](https://github.com/shahrilnet/remote_lua_loader/blob/main/SETUP.md) [If your FW isn't supported by the Save Mounter]
3. Restore an updated backup with new(er) savedata

#### Simple steps to use save mounter:
Make sure to read the [README.md](https://github.com/n0llptr/Playstation-5-Save-Mounter/blob/main/README.md) on the Playstation 5 Save Mounter repo.

0. If you jailbreak using one of the Artemis/Lua games, you will need to exit the game after the exploit has run. If using any other method to jailbreak, then proceed to Step 1.
    - Follow the next steps from the home menu with no games running on your console
1. After jailbreaking, you need to load [ps5debug](https://github.com/GoldHEN/ps5debug) on the console. Use at least version [v1.0b4](https://github.com/GoldHEN/ps5debug/releases) for 3.xx-6.xx.
    - Use a payload sender or load it along with the exploit chain.
2. Run the Save Mounter and enter your console's IP address -> You should see `Status: Connected` at the bottom of the Save Mounter
3. Click 'Setup' and once you see `Status: Setup Done`, then select your user from the drop down menu.
4. Click 'Get Games' and once you see `Status: Refreshed Games`, then select the CUSA according to your game.
5. Click 'Search' and you should see `Status: Found X Save Directories` (Usually X = 1, unless you have >1 save)
6. Cilck 'Mount' and you should see `Status: Save Mounted in /savedataX` (Usually X = 0, unless you mount multiple saves)
7. Now open your FTP Client and connect to your console via port 1337 (if using etaHEN) or 2121 (if using ftpsrv).
8. Navigate to `/mnt/pfs/` and you should see `savedata_<user id>_<game CUSA>_savedata` directory.
    - If the savedata directory doesn't exist there, check `/mnt/sandbox/<game CUSA>` and you should see it there.
9. In the savedata directory, you can replace the files you want to update. Usually recommended to delete the existing files and copying new ones over.
    - **WARNING**: Do not delete `sce_sys` directory for any reason. Any other file or directory is okay to delete.
10. Once done, you can go back to the Save Mounter and click 'Unmount' and wait until you see `Status: Save Unmounted`
    - **Note**: If you do not unmount the save before launching the game, it has a high chance of corrupting it.
