# NonUI

Boots iPhone 5s factory NonUI build 11A24580o on an Apple Silicon Mac, in QEMU.

You bring the two original files. I don't host it, and I didn't give it to you. If you got it from somewhere, that was you, and it is not my responsibility. I put this up for educational purposes, so you can see how this one NonUI build boots. On the machine I tried, SwitchBoard sat around 3 to 6 fps. (with some jumps to 12 fps) The emulator is tested to work only with that build. Use at your own risk, though no risk of device harm.

## Which builds work

<table>
<tr><th>Build</th><th>Device</th><th>What to expect</th></tr>
<tr><td>11A24580o</td><td>iPhone 5s (N51AP)</td><td>This is the one that boots. SwitchBoard comes up, and most apps open & you're able to return back home</td></tr>
<tr><td>Any other DMG or tar</td><td></td><td>Experimental. Turn it on in Settings. Prepare runs the same steps and the log says what failed. I have not seen another build boot.</td></tr>
</table>

The var tar is only `/private/var`. The DMG is the OS. You need both.

## What to install

Release 0.1.1 has `NonUI-0.1.1-macos-arm64.dmg`. Open it and drag NonUI into Applications. QEMU is already in the app.

- An Apple Silicon Mac on macOS 15
- `N51AP_11A24580o_rootfs.dmg`
- `N51AP_11A24580o_var.tar`
- About 50 GB free on the disk that holds the NonUI data. If the host check prints `WAIT`, the load is at or above the core count, or free space is under 50 GB.

## Boot

1. Open NonUI.
2. Click Choose DMG and pick `N51AP_11A24580o_rootfs.dmg`.
3. Click Choose var tar and pick `N51AP_11A24580o_var.tar`. If both files are already inside one tar or zip, use Choose Archive. You can also drop the files on the window.
4. Click Prepare. NonUI builds a disk in `~/Library/Application Support/NonUI` and leaves the originals where they are. Later boots reuse that disk. Guest writes stay in RAM for that session.
   While it prepares, it reads the N51 device tree from Apple's iOS 7.0.1 restore. Offline, click Use Local IPSW and pick `iPhone6,1_7.0.1_11A470a_Restore.ipsw`.
5. Click Boot. The display opens when SwitchBoard draws. That took about a minute here.
6. Click an icon. In QRCode, click Home, then Quit on the guest panel, and you should land back on SwitchBoard.
7. Click Stop, or close the display window, when you want QEMU to quit.

The log sits on the main window. The menu above it switches between the session, the guest console, and QEMU. Open in Window is the same log in its own window.

Clear All Data and Contents asks before it deletes the prepared disk, the runs, and the logs. The DMG and the var tar are not touched. You need both again if you want to prepare a new disk.

## Experimental

Settings, then Experimental builds. It is off unless you turn it on.

With it on, you can hand NonUI another root DMG, another tar, or a tar or zip that contains those files. Prepare tries the same steps it uses for 11A24580o. If the kernel, device tree, or boot files do not match, it stops and the log has the reason. The prepared disk is not kept. 11A24580o is still the only one set up to boot.

## Terminal

```sh
./nonui import /path/to/N51AP_11A24580o_rootfs.dmg /path/to/N51AP_11A24580o_var.tar
./nonui boot
./nonui stop
./nonui reset
```

`./nonui import --experimental` is the same switch as Settings. Run `stop` from another terminal. `./nonui --data-dir /path/to/folder` keeps a separate copy.

## Build the app

On Apple Silicon, with Xcode's command line tools selected:

```sh
./build.sh
```

That downloads QEMU from the UTM 4.7.5 release and packs the libraries the boot uses. You do not install UTM.

`dist/` gets the app, the zip, and `SHA256SUMS`. The signature is ad hoc. Other people's code is listed in [THIRD-PARTY.md](THIRD-PARTY.md).

## What the boot is doing

NonUI maps the guest kernel and a device tree for the emulated iPhone 5s. The disk builder copies the DMG into an HFSX RAM disk and merges the var tar into `/private/var`. A small C program in front of QEMU handles the timer, the RAM disk copies, and the device registers the kernel wants before userland. The window shows the guest's Core Graphics bitmap. Clicks and Home go through the guest's own handlers.
