from base64 import b64decode
from Crypto.Cipher import AES
from utils import SECTOR_SIZE, pack, log
from defusedxml.ElementTree import parse, ParseError


AES_KEY_SIZE = 32


# CryptoHandler: this class handle all the cryptographic operations, in particular
#                it decrypts a sector during a read operation
#
#       Params: @xml_file: path to the McAfee generated file containing the key
#               @verbose : boolean flag to determine wether print information during execution
class CryptoHandler:
    def __init__(self, xml_file, verbose):
        self._AESkey = self._get_key_from_XML(xml_file)
        self._sector_iv_cipher = AES.new(self._AESkey, AES.MODE_ECB)

        if verbose:
            log.info(f'|++| Sector size: {SECTOR_SIZE}')
            log.info(f'|++| AES-256-CBC key instantiated: {self._AESkey}')

    
    def _find_sector(self, off):
        return off // SECTOR_SIZE

    
    def _decrypt_sector(self, source, sector_no):
        pre_iv = pack('<I', sector_no) * 4
        iv = self._sector_iv_cipher.encrypt(pre_iv)
        AEScipher = AES.new(self._AESkey, AES.MODE_CBC, iv)

        source.seek(sector_no * SECTOR_SIZE)
        encrypted_sector = source.read(SECTOR_SIZE)
        return AEScipher.decrypt(encrypted_sector)


    def _get_key_from_XML(self, path_to_xml):
        xml_file = None
        base64key = None

        try:
            xml_file = parse(path_to_xml).getroot()
        except ParseError:
            raise ValueError('|!| -- [ERROR] -- Parse error while reading XML keyfile')

        for child in xml_file:
            if child.tag == 'key':
                base64key = child.text
                break

        if not base64key:
            raise ValueError('|!| -- [ERROR] -- XML not valid: key tag not found')

        decoded_key = None
        try:
            decoded_key = b64decode(base64key)
        except:
            raise ValueError('|!| -- [ERROR] -- Key not in base64 encoding or invalid format')

        if len(decoded_key) != AES_KEY_SIZE:
            raise ValueError('|!| -- [ERROR] -- Key length is not valid')

        return decoded_key


    async def decrypt_at_offset(self, source, off, size):
        size_orig = size    # in case data are within the first sector read
        sector_no = self._find_sector(off)

        data = b''

        # first (potentially) partial sector
        clear_sector = self._decrypt_sector(source, sector_no)
        bytes_in_sector = off - sector_no * SECTOR_SIZE
        data += clear_sector[bytes_in_sector:]
        size -= SECTOR_SIZE - bytes_in_sector
        sector_no += 1

        # full sectors
        while size > SECTOR_SIZE:
            data += self._decrypt_sector(source, sector_no)
            size -= SECTOR_SIZE
            sector_no += 1        

        # last (potentially) partial sector
        clear_sector = self._decrypt_sector(source, sector_no)
        data += clear_sector[:size]

        return data[:size_orig]