# SPI Flash Auto-Unlocker

A Python utility for automatically dumping, analyzing, and modifying laptop and embedded firmware to remove BIOS/UEFI passwords.

## 🚀 Motivation
Modern laptops often store administrator and user passwords inside the UEFI firmware on the same SPI flash chip that contains the rest of the BIOS. In many cases, these passwords are held within a non-volatile variable named `AMITSESetup` in AMI firmwares. Research also shows that certain vendors, such as Lenovo, control write-protection using special variables like `cE!` inside proprietary GUID namespaces. Clearing or deleting these variables effectively resets the password and disables the lockout mechanisms. Rather than manually dumping the flash, editing the image with a hex editor and reflashing, the Auto-Unlocker automates the entire workflow with a single command.

## 🛠️ How It Works
1. **Hardware Connection**: Connect a SOIC-8 test clip onto the system's SPI ROM chip and connect it to a compatible USB programmer (CH341A or FT2232H).
2. **Flash Dump**: The script invokes the external `flashrom` utility to read the entire contents of the SPI flash and writes it to a backup file.
3. **Variable Enumeration**: The dumped image is scanned for UEFI variable headers. The parser searches for known GUIDs (e.g., the AMI `AMITSESetup` GUID) and reconstructs the variable name, attributes, and data structure.
4. **Password Removal**: For each variable identified as containing a password, the tool can either zero out the data region or mark the variable as deleted. Setting the state's delete bit (`0x3F` -> `0x3D`) follows the UEFI specification's life cycle for variable deletion.
5. **Reflash**: Finally, the patched image is written back to the SPI chip with `flashrom`, restoring a system without the old password.

## 📋 Usage
First install `flashrom`, Python 3 (stdlib only, no pip packages required). Then run the tool with appropriate options:

```bash
python3 spi_flash_auto_unlocker.py \
  --reader ch341a_spi \
  --chip W25Q128FV \
  --dump backup.bin \
  --patch patched.bin \
  --delete
```

Safe dry run with no hardware attached (parse + patch a saved image only):

```bash
python3 spi_flash_auto_unlocker.py --image backup.bin --patch patched.bin --list
python3 spi_flash_auto_unlocker.py --image backup.bin --patch patched.bin --delete
```

### Options
- `--reader`: Flashrom programmer driver name (`ch341a_spi` or `ft2232_spi`). Required unless `--image` is given.
- `--image`: Patch an existing firmware image file offline, no hardware/flashrom needed. Implies `--no-flash`.
- `--chip`: Optional flash chip name (e.g., `W25Q128FV`)
- `--dump`: Path to save the dumped firmware image (default: `flash_backup.bin`)
- `--patch`: Path to save the patched firmware image (default: `flash_patched.bin`)
- `--delete`: Mark password variables as deleted instead of (or in addition to) zeroing data
- `--no-flash`: Do not automatically reflash (safe dry run)
- `--list`: List all discovered variables and exit without making changes

## 🔌 Hardware hookup (CH341A + SOIC-8 clip)
1. Power the target board OFF, unplug battery/AC. Identify the SPI ROM (8-pin, often Winbond `W25Q*` / Macronix `MX25*` near the EC/BIOS area).
2. Clip the SOIC-8 test clip onto the chip, pin 1 to pin 1 (dot marker). Connect to the CH341A programmer.
3. On the host: `flashrom -p ch341a_spi` should detect the chip. If not, reseat the clip before retrying.
4. Always dump twice and compare checksums before patching: keep the original dump offline.

## ⚠️ Safety Warning
Flashing modified firmware can brick your device. Use this software at your own risk and only on hardware you own. Always keep the original dump in case something goes wrong. If `--list` finds no password variables, stop — do not flash a no-op image.

## 📄 License
This project is released under the **MIT License**. See the `LICENSE` file for details.
