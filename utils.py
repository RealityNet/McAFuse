import pathlib
import logging

from struct import pack, unpack
from argparse import ArgumentParser

try:
    import faulthandler
except ImportError:
    pass
else:
    faulthandler.enable()


SECTOR_SIZE = 512 # bytes

log = logging.getLogger(__name__)


# simple struct the gather only useful info from MBR structure
class MBREntry:
    def __init__(self, entry, index):
        self.index = index
        self.status = entry[0x0]
        self.type = entry[0x4]
        self.starting_sector = bytes2int(entry[0x8:0xc])
        self.total_sectors = bytes2int(entry[0xc:])

    
    def pretty_print(self):
        print(f'[*** MBR entry {self.index} ***]')
        print(f'|-- Status: {"{:02x}".format(self.status)}')
        print(f'|--   Type: {"{:02x}".format(self.type)}')
        print(f'|--  Start: {self.starting_sector}')
        print(f'|--  Count: {self.total_sectors}\n')


# retrieve information of partitions from MBR
def get_partitions_from_mbr(mbr):
    partitions = []
    for i in range(4):
        entry = mbr[i*0x10 : i*0x10+0x10]
        if entry == b'\x00'*0x10: # skip empty entries
            continue
        partitions.append(MBREntry(entry, i))
    return partitions


# rebuild disk GUID starting from sector SafeBootDiskInfo
def build_GUID(disk_info):
    guid = []
    
    n = ''
    for i in range(0x2a, 0x26, -1):
        n += '{:02x}'.format(disk_info[i])
    guid.append(n)
    
    guid.append('{:02x}'.format(disk_info[0x2c]) + '{:02x}'.format(disk_info[0x2b]))
    guid.append('{:02x}'.format(disk_info[0x2e]) + '{:02x}'.format(disk_info[0x2d]))
    for i in range(0x2f, 0x37):
        guid.append('{:02x}'.format(disk_info[i]))

    # GUID format: XXXX-XX-XX-X-X-X-X-X-X-X-X, X == bytes in range [0x00, 0xff]
    return '-'.join(map(lambda x: str(x), guid)).upper()


# rebuild key check value (8 bytes value) starting from sector SafeBootDiskInfo
def build_keycheck(disk_info):
    return ''.join(['{:02x}'.format(b) for b in disk_info[0x4d:0x55][::-1]]).upper()


# read multiple contiguous sectors
def read_sectors(source, base, how_many):
    source.seek(base * SECTOR_SIZE)
    return source.read(how_many * SECTOR_SIZE)


# convert 4 bytes (32 bits) to an integer value
def bytes2int(b):
    return int(unpack('<I', b)[0])


# read an address directly from disk
def read_addr_in_sectors(f):
    sector_no = f.read(0x4)
    return bytes2int(sector_no)


# check if the disk starts with the signature '#SafeBoot'
def check_signature(disk_path, real_signature, sign_offset):
    with open(disk_path, 'rb') as disk:
        disk.seek(sign_offset)
        read_signature = disk.read(len(real_signature))
    
    if read_signature != real_signature:
        raise ValueError(f'|!| -- [ERROR] -- signature {real_signature} not found')


# debug logging
def init_logging(debug=False):
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d: '
                                  '%(message)s', datefmt="%Y-%m-%d %H:%M:%S")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    if debug:
        handler.setLevel(logging.DEBUG)
        root_logger.setLevel(logging.DEBUG)
    else:
        handler.setLevel(logging.INFO)
        root_logger.setLevel(logging.INFO)
    root_logger.addHandler(handler)


# handle user-provided cli arguments
def parse_args():
    parser = ArgumentParser(prog='./mcafuse.py')

    parser.add_argument('mountpoint', type=str, help='where to mount the file system')
    parser.add_argument('disk_image', type=pathlib.Path, help='image of disk encrypted with McAfee FDE')
    parser.add_argument('--debug', action='store_true', default=False, help='enable debugging output')
    parser.add_argument('-k', '--keyfile', type=pathlib.Path, default=None, help='path to the XML file containing the decryption key')
    parser.add_argument('-i', '--info', action='store_true', default=False, help='print info from SafeBootDiskInfo')
    parser.add_argument('-a', '--all', action='store_true', default=False, help='expose all disk, not only the encrypted partition')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='verbose log of info during the execution')
    
    return parser.parse_args()


# checks if parameters provided by the user exist or not
def check_if_files_exist(disk_image, keyfile, mountpoint):
    if not disk_image.is_file():
        raise FileNotFoundError('|!| -- [ERROR] -- The supplied image of the disk does not exist')
    if keyfile is not None and not keyfile.is_file():
        raise FileNotFoundError('|!| -- [ERROR] -- The supplied key file does not exist')
    if not pathlib.Path(mountpoint).is_dir():
        raise NotADirectoryError('|!| -- [ERROR] -- The supplied mountpoint does not exist or it is not a directory')