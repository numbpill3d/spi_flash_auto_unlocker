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
First install `flashrom`, Python 3, and any other dependencies. Then run the tool with appropriate options:

```bash
python3 spi_flash_auto_unlocker.py \
  --reader ch341a_spi \
  --chip W25Q128FV \
  --dump backup.bin \
  --patch patched.bin \
  --delete
```

### Options
- `--reader`: Flashrom programmer driver name (required: `ch341a_spi` or `ft2232_spi`)
- `--chip`: Optional flash chip name (e.g., `W25Q128FV`)
- `--dump`: Path to save the dumped firmware image (default: `flash_backup.bin`)
- `--patch`: Path to save the patched firmware image (default: `flash_patched.bin`)
- `--delete`: Mark password variables as deleted instead of (or in addition to) zeroing data
- `--no-flash`: Do not automatically reflash (safe dry run)
- `--list`: List all discovered variables and exit without making changes

## ⚠️ Safety Warning
Flashing modified firmware can brick your device. Use this software at your own risk and only on hardware you own. Always keep the original dump in case something goes wrong.

## 📄 License
This project is released under the **MIT License**. See the `LICENSE` file for details.
