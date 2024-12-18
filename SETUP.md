
### Usage on jailbroken PS4 with disc version

1. Play the game for a while until you can create save data
2. Use Apollo Save Tool to export decrypted save data to USB drive
3. Copy and paste all files from savedata into USB drive (x:\PS4\APOLLO\id_{YOUR_GAME_CUSA_ID}_savedata), overwriting currently existing save data
4. Make sure that `PLATFORM` variable on top of `inject.lua` is set appropriately
5. Use Apollo Save Tool to import the new save data from USB drive
6. Run the game and check if there is a popup from lua loader
7. Use `send_lua.py` to send lua file to the loader

If you have a jailbroken PS5 with a non activated account, you can use [OffAct](https://github.com/ps5-payload-dev/websrv/releases) to offline activate the account and transfer save data with matching account ID using FTP.

### Usage on PS5/PS5 Slim/PS5 Pro

#### Requirements:
1. PSN-activated PS5/PS5 Slim/PS5 Pro. Can be non-recent offline firmware if was activated in the past.
2. A Jailbroken PS4 on a firmware version that is earlier or equivilant to the PS5/PS5 Slim/PS5 Pro. Refer to this [table](https://www.psdevwiki.com/ps5/Build_Strings). For example, PS4 9.00 can be used to create save game for PS5 >=4.00 but not below that.

#### Steps:
1. Find your logged-in PSN account id on the PS5/PS5 Slim/PS5 Pro. Either by going to the PlayStation settings or by using [this website](https://psn.flipscreen.games/).
2. Take your account ID number (~19 characters long, for PSPlay) and convert it to hex using [this website](https://www.rapidtables.com/convert/number/decimal-to-hex.html).

#### JB PS4 -
3. Play the game for a while until you can create save data.
4. Connect a USB disk to the PS4.
5. Use Apollo Save Tool to export decrypted save data to USB drive.
6. Make sure that `PLATFORM` variable on top of `inject.lua` is set appropriately
7. Copy and paste all files from savedata into USB drive (x:\PS4\APOLLO\id_{YOUR_GAME_CUSA_ID}_savedata), overwriting currently existing save data.
8. Create new fake offline account.
9. Use Apollo Save Tool to activate the new fake account using the converted hex account ID from step 2.
10. Switch to the activated fake account.
11. Import savedata from USB drive using Apollo Save Tool. (`USB Saves -> Select the game -> Copy save game -> Copy to HDD`)
12. Use the PS4 settings menu to export the encrypted save data to the USB drive. (`Settings -> Application Saved Data Management -> Saved Data in System Storage -> Copy to USB Storage Device`)

#### PSN-Activated PS5/PS5 Slim/PS5 Pro -
13. Make sure you're logged-in to the PSN-activated user.
14. Connect your USB drive to the PS5/PS5 Slim/PS5 Pro.
15. Use the PS5 settings menu to import the encrypted save data from the USB drive. (`Saved Data and Game/App Settings -> Saved Data (PS4) -> Copy or Delete from USB Drive -> Select your game and import`)
16. Run the game and check if there is a popup from lua loader.
17. Use `send_lua.py` to send lua file to the loader.