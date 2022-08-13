#! /usr/bin/python3

import argparse
from typing import Optional
import zipfile
import blowfish
from ctypes import c_uint32
from pathlib import Path

def get_cok6_nref(infile: Path):
    with zipfile.ZipFile(infile, 'r') as f:
        infolist = f.infolist()
        if len(infolist) > 1:
            raise RuntimeError("More than one file in the archive")
        cok6_nref = infolist[0]
        with f.open(cok6_nref, "r") as fo:
            return cok6_nref.filename.upper(), fo.read()

def decrypt(infile: Path, outdir: Optional[Path] = None):
    """
    Decrypts the asset file.
    """

    name, input_data = get_cok6_nref(infile)
    in_size = len(input_data)

    keystrings = [
        b"\x1b\xbf\x18\xcc\x86\x5d\xf4\x25\x07\xc3\xe5\xb3\xb9\x04\x5a\x14\xd7\xfc\x4c\x86\x8d\x4a\xcb\x8f",
        b"\x24\x53\x4a\x1e\xda\x06\x85\x5f\x7a\xc1\xb6\x8a\x76\x41\x20\xcb\x1f\xce\x61\xd6\xad\x74\x6b\x0f",
        b"\x77\x82\x1e\x54\x89\xd7\x87\xb6\x05\xf9\x64\xcc\x57\x0b\xcf\x8b\xf8\xd2\x35\x80\x9c\xbf\x9e\x19",
        b"\x5a\x8d\x84\x20\x6e\x90\xfb\x91\x1f\x48\xe0\xee\xc2\x03\xa2\xaf\x60\x2f\x93\xd6\xa8\x50\x2c\xe2",
    ]

    key_swap_indexes = [
        [ 8, 10, 12, 17 ],
        [ 1, 2, 10, 15 ],
        [ 0, 9, 12, 16 ],
        [ 5, 6, 11, 14 ],
    ]

    name_crc = c_uint32(0)
    for i in range(len(name)):
        name_crc = c_uint32(name_crc.value * 0x25)
        name_crc = c_uint32(name_crc.value + ord(name[i]))
    
    # Do some math on the size of the .COK6.NREF to get a value from 0 to 15
    size_tmp = c_uint32(int(in_size / 16) % 16)

    # Select one of the 4 keystrings (division of the size var by 4)
    key_indexes = key_swap_indexes[int(size_tmp.value / 4)]

    # Select one of the 4 key byte arrays (mod of the size var by 4)
    mf3b = keystrings[size_tmp.value % 4]

    key = bytearray(mf3b[0:18])

    # Swap some 4 of the bytes out of the key with values based on the name crc
    for i in key_indexes:
        key[i] = name_crc.value & 0xFF
        name_crc = c_uint32(name_crc.value >> 8)

    cipher = blowfish.Cipher(bytes(key), byte_order="little")
    blowfish_decrypted = b"".join(cipher.decrypt_ecb_cts(input_data))

    out_size = int.from_bytes(blowfish_decrypted[0x10:0x14], byteorder="little")
    out_offset = int.from_bytes(blowfish_decrypted[0x14:0x18], byteorder="little")

    if not outdir:
        outdir = infile.parent

    outfile = outdir / (name.split(".")[0] + ".swf")
    with open(outfile, 'wb') as f:
        f.write(blowfish_decrypted[out_offset : out_size])

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("infile", type=str, help=".pak file to decrypt")
    parser.add_argument("--outdir", type=str, help="output directory (default is input file's directory)")

    args = parser.parse_args()

    outdir:Path = None
    if args.outdir:
        outdir = Path(args.outdir)

    decrypt(Path(args.infile), outdir)
