import os
import sys
import ctypes

# Fix NixOS dynamic library paths for C-extensions (like greenlet) and child processes (like Playwright Chromium)
nix_ld_dir = "/run/current-system/sw/share/nix-ld/lib"
if os.path.isdir(nix_ld_dir):
    libstdc = os.path.join(nix_ld_dir, "libstdc++.so.6")
    if os.path.exists(libstdc):
        try:
            ctypes.CDLL(libstdc)
        except Exception:
            pass

extra_nix_libs = [
    "/nix/store/2cf75gbn2qk5hbm4kdzgg545mky5gxh7-libxrandr-1.5.5/lib",
    "/nix/store/8pcrdazxyw8b1n3i0v9d2r3g38hrgw63-nspr-4.40/lib",
    "/nix/store/9159h1500cy22cgriydpl6mbih9rjnc2-libx11-1.8.13/lib",
    "/nix/store/a3rbzlj5wzxwjpncc0q9p6l64sc52m3y-libxcomposite-0.4.7/lib",
    "/nix/store/ala3sdcr1r34kkhsa1nd3g3daf7bxhab-at-spi2-core-2.60.6/lib",
    "/nix/store/d34lp4b2b0glnmwf7ij3ha8mrmb30l64-dbus-1.16.2-lib/lib",
    "/nix/store/firki6qp8l2y6jgpwvix2wd95bi572mi-libxext-1.3.7/lib",
    "/nix/store/kg5wp6wavf5p7v6shcccyqxy2nlzsn5s-libxdamage-1.1.7/lib",
    "/nix/store/knm96d081dl0mhbbdbmi2gwqj2sn0jbh-mesa-libgbm-26.1.3/lib",
    "/nix/store/l34g6v1iwrww50gk7rg06x1ncn5x3ifl-nss-3.130/lib",
    "/nix/store/l5y7fz08zvrqiinb90j1r922ymncb0sj-libxfixes-6.0.2/lib",
    "/nix/store/n2wqk78za8grzs9088ya5qy6vw280p8x-libxkbcommon-1.13.2/lib",
    "/nix/store/z6v6qc8cy50i90afg4kgbr4jrfg5fdnc-alsa-lib-1.2.16.1/lib",
    "/nix/store/zrkqwk0989k5wa1gn3cjb76jfga3d8i3-expat-2.8.5/lib",
    nix_ld_dir,
]
current_ld = os.environ.get("LD_LIBRARY_PATH", "")
to_add = [p for p in extra_nix_libs if os.path.isdir(p) and p not in current_ld]
if to_add:
    os.environ["LD_LIBRARY_PATH"] = ":".join(to_add) + ((":" + current_ld) if current_ld else "")
