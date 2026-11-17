import shutil
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]
img_dir = root / 'docs/images'
img_dir.mkdir(parents=True, exist_ok=True)

# Copy emulator shooting-entry screenshot
src_qemu = root / 'analysis/modified10-preflash-2026-11-13/qemu-modified10/session/shooting-entry.png'
if src_qemu.is_file():
    shutil.copy2(src_qemu, img_dir / 'qemu_simulator_liveview.png')
    print("Copied qemu_simulator_liveview.png")

# Copy emulator playback menu screenshot
src_menu = root / 'analysis/spatial-preflash-2026-11-09/qemu-menu-modified2-final/session/screen.png'
if src_menu.is_file():
    shutil.copy2(src_menu, img_dir / 'qemu_simulator_menu.png')
    print("Copied qemu_simulator_menu.png")
