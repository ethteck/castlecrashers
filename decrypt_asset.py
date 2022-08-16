#! /usr/bin/python3

import argparse
from typing import Optional
import zipfile
import blowfish
from ctypes import c_uint16, c_uint32
from pathlib import Path

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

def write_file(data: bytes, path: Path):
    with open(path, 'wb') as f:
        f.write(data)

def unzip_to_cok6_nref(infile: Path):
    with zipfile.ZipFile(infile, 'r') as f:
        infolist = f.infolist()
        if len(infolist) > 1:
            raise RuntimeError("More than one file in the archive")
        cok6_nref = infolist[0]
        with f.open(cok6_nref, "r") as fo:
            return cok6_nref.filename.upper(), fo.read()

def zip_to_cok6_nref(outfile: Path, archive_name: str, data: bytes):
    with zipfile.ZipFile(outfile, 'w') as f:
        with f.open(archive_name, "w") as fo:
            fo.write(data)

def decrypted_to_swf(data: bytes):
    """
    Convert the decrypted data to a swf file by reading the start offset and size from the header
    """
    out_size = int.from_bytes(data[0x10:0x14], byteorder="little")
    out_offset = int.from_bytes(data[0x14:0x18], byteorder="little")

    return data[out_offset:out_size + out_offset]

def get_blowfish_key(name: str, data_len: int) -> bytes:
    name_crc = c_uint32(0)
    for i in range(len(name)):
        name_crc = c_uint32(name_crc.value * 0x25)
        name_crc = c_uint32(name_crc.value + ord(name[i]))

    # Do some math on the size of the .COK6.NREF to get a value from 0 to 15
    size_tmp = c_uint32(int(data_len / 16) % 16)

    # Select one of the 4 keystrings (division of the size var by 4)
    key_indexes = key_swap_indexes[int(size_tmp.value / 4)]

    # Select one of the 4 key byte arrays (mod of the size var by 4)
    mf3b = keystrings[size_tmp.value % 4]

    key = bytearray(mf3b[0:18])

    # Swap some 4 of the bytes out of the key with values based on the name crc
    for i in key_indexes:
        key[i] = name_crc.value & 0xFF
        name_crc = c_uint32(name_crc.value >> 8)

    return bytes(key)

def blowfish_decrypt(name: str, data: bytes) -> bytes:
    key = get_blowfish_key(name, len(data))

    cipher = blowfish.Cipher(key, byte_order="little")
    return b"".join(cipher.decrypt_ecb(data))

def blowfish_encrypt(name: str, data: bytes) -> bytes:
    key = get_blowfish_key(name, len(data))

    cipher = blowfish.Cipher(key, byte_order="little")
    return b"".join(cipher.encrypt_ecb(data))

def calc_checksum(data: bytes) -> int:
    result = c_uint32(0)
    work = c_uint16(0xD971)
    for b in data:
        tmp = b ^ (work.value >> 8)
        work = c_uint16(0x58BF + 0xCE6D * (work.value + tmp))
        result = c_uint32(result.value + tmp)
    return result.value

def validate_checksum(data: bytes):
    ck1 = int.from_bytes(data[-4:], byteorder="little")
    ck2 = calc_checksum(data[:-4] + b'\0\0\0\0')
    if ck1 != ck2:
        raise RuntimeError("Checksum mismatch: {:08X} (actual) != {:08X} (computed)".format(ck1, ck2))

def decrypt_file(infile: Path, outdir: Optional[Path]):
    """
    Decrypts the asset file.
    """

    name, input_data = unzip_to_cok6_nref(infile)

    blowfish_decrypted = blowfish_decrypt(name, input_data)

    # Sanity checks: validate checksum, confirm we can properly rebuild the footer
    validate_checksum(blowfish_decrypted)

    swf_bytes = decrypted_to_swf(blowfish_decrypted)

    #print(space_out(blowfish_decrypted[:0x20].hex()) + " - " + name)

    footer_data = build_footer(swf_bytes)
    if footer_data[:-4] != blowfish_decrypted[-len(footer_data):-4]:
        raise RuntimeError("Footer mismatch")

    raw_name = name.split(".")[0]

    write_file(swf_bytes, outdir / (raw_name + ".swf"))
    write_file(blowfish_decrypted, outdir / (raw_name + ".swf.raw"))

def build_header(data: bytes) -> bytes:
    ret = b''

    ret += b'\0' * 0x80

    return ret

def build_footer(data: bytes) -> bytes:
    ret = b''

    # Add initial padding to align the file to 4 bytes
    align_4_len = 4 - (len(data) % 4)
    if align_4_len == 4:
        align_4_len = 0
    ret += b'\0' * align_4_len

    # Add 0x14, 1
    ret += b'\x14\x00\x00\x00\x01\x00\x00\x00'

    # Add padding to align the final file to 16 bytes (existing data, footer so far, int for number of zeros, int for checksum)
    align_16_len = 16 - ((len(data + ret) + 8) % 16)

    if align_16_len == 16:
        align_16_len = 0
    ret += b'\0' * align_16_len

    # Add a u32 describing the number of zeros added + 8
    ret += (align_16_len + 8).to_bytes(4, byteorder="little")

    # Add a space for the checksum
    ret += b'\0\0\0\0'

    return ret

def space_out(s):
    return ' '.join([s[i:i + 8] for i in range(0, len(s), 8)])

def encrypt_file(infile: Path, outdir: Optional[Path] = None):
    """
    Encrypts the asset file.
    """
    print("Encrypting " + infile.name)

    with open(infile, "rb") as f:
        swf_data = f.read()

    pre_compression_data = build_header(swf_data)
    pre_compression_data += swf_data
    pre_compression_data += build_footer(pre_compression_data)

    checksum = calc_checksum(pre_compression_data)

    pre_compression_data = pre_compression_data[:-4] + checksum.to_bytes(4, byteorder="little")

    archive_name = infile.stem.upper() + ".COK6.NREF"

    blowfish_encrypted = blowfish_encrypt(archive_name, pre_compression_data)

    zip_path = outdir / (infile.stem.lower() + ".pak")

    zip_to_cok6_nref(zip_path, archive_name, blowfish_encrypted)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("infile", type=str, help="input file or directory")
    parser.add_argument("outdir", type=str, help="output directory")
    parser.add_argument("--encrypt", action="store_true", help="encrypt the input file(s)")

    args = parser.parse_args()

    infile = Path(args.infile)

    if args.outdir:
        outdir = Path(args.outdir)
    else:
        outdir = infile.parent

    if args.encrypt:
        encrypt_file(infile, outdir)
    else:
        in_path = infile
        if in_path.is_dir():
            for f in in_path.rglob("*.pak"):
                decrypt_file(f, outdir)
        else:
            decrypt_file(infile, outdir)
