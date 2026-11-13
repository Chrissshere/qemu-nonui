# Third-party software

Thanks to Light Touch. The disk builder logic was inspired by it. The HFSX
reader and writer NonUI calls are their FirmwareKit at commit
`5078f0a8f1aa86f512ca97a23aa4b3443a190845`. Its Swift dependencies are pinned in
`storage/Package.resolved`. The app build copies their notices into the bundle.
[Light Touch source](https://github.com/samhenrigold/LightTouchMac/tree/5078f0a8f1aa86f512ca97a23aa4b3443a190845)

The app includes CPython 3.13.18 from Python Build Standalone. Python's license
ships with the standard library in the bundle.
[CPython license](https://github.com/python/cpython/blob/v3.13.18/LICENSE),
[Python Build Standalone distribution](https://github.com/astral-sh/python-build-standalone/releases/tag/20261110)

The app includes QEMU 10.0.2 from UTM 4.7.5 build 118, and the libraries that
binary links. `./build.sh` downloads that release and changes one TCG debugger
cache-flush instruction. You do not install UTM.
[UTM release](https://github.com/utmapp/UTM/releases/tag/v4.7.5),
[QEMU source](https://github.com/utmapp/qemu/tree/v10.0.2-utm)

The guest image is assembled from the user's original files. The retail N51
DeviceTree is read from Apple's iOS 7.0.1 restore image. The firmware metadata is
documented by [The Apple Wiki](https://theapplewiki.com/wiki/InnsbruckNanshan_11A24580o).
