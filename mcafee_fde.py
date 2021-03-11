import os
import sys
import stat
import errno
import pyfuse3

from utils import read_addr_in_sectors, SECTOR_SIZE,            \
                  bytes2int, read_sectors, build_GUID,          \
                  build_keycheck, log, get_partitions_from_mbr, \
                  check_signature


# McAfeeFde: this class implement the fs operations
#
#       Params: @disk_image: encrypted disk image to mirror
#               @crypto_hnl: crypto handler object to handle decryption
#               @info      : boolean flag to determine wether print disk info
#               @all_disk  : boolean flag to determine wether expose all disk or only a partition
#               @verbose   : boolean flag to determine wether print information during execution
class McafeeFde(pyfuse3.Operations):
    def __init__(self, disk_image, crypto_hnl, info, all_disk, verbose):
        super(McafeeFde, self).__init__()

        self._safebootdiskinf_sector = 0          # to print useful info
        self._sector_map             = dict()     # [starting_sector] -> how_many
        self._sbfsdisk_data          = b''        # safeboot fat partition
        self._partition_start        = 0          # address in secotrs of the partition considered
        self._partition_len          = 0          # length of partition in sectors
        self._all_disk               = all_disk   # consider all disk or only a partition
        self._verbose                = verbose    # determine how much information is printed in output  
        self._crypto_handler         = crypto_hnl # if None, expose only SafeBoot.disk

        # backend disk image
        self._backend_file_name = disk_image
        self._backend_file      = open(self._backend_file_name, 'rb')

        # encrypted disk
        self.encdisk_name  = b'encdisk.img'
        self.encdisk_inode = pyfuse3.ROOT_INODE + 1

        # safebootdisk
        self.sbfsdisk_name  = b'SafeBoot.disk'
        self.sbfsdisk_inode = pyfuse3.ROOT_INODE + 2
        
        # initialize values
        self._init_sector_map()
        if not self._all_disk:
            self._init_encrypted_partition()
        if info or self._verbose:
            self._print_disk_info()

    
    # adjust the offset for read operations selecting the encrypted partition
    def _init_encrypted_partition(self):
        self._backend_file.seek(0)
        first_sector = self._backend_file.read(SECTOR_SIZE)
        mbr = first_sector[0x1be:0x1fe]
        partitions = get_partitions_from_mbr(mbr)

        if self._verbose:
            log.info('\n')
            for part in partitions:
                part.pretty_print()

        # if there is only 1 partition, it is encrypted
        # if there are 2 partitions, usually the 2nd is the encrypted one
        how_many_partitions = len(partitions)
        if how_many_partitions == 1:
            self._partition_start = partitions[0].starting_sector
            self._partition_len = partitions[0].total_sectors
            if self._verbose:
                log.info(f'|++| Chosen the 1st partition.\n'
                         f'Starting address in sectors: {self._partition_start}\n'
                         f'\tLength in sectors: {self._partition_len}')
        elif how_many_partitions == 2:
            self._partition_start = partitions[1].starting_sector
            self._partition_len = partitions[1].total_sectors
            if self._verbose:
                log.info(f'|++| Chosen the 2nd partition.\n'
                         f'\tStarting address in sectors: {self._partition_start}\n'
                         f'\tLength in sectors: {self._partition_len}\n')
        else:
            # TODO: handle more than 2 partitions
            raise NotImplemented('This program currenlty does not support disks with more than 2 partitions')


    # print disk information found in the SafeBoot disk
    def _print_disk_info(self):
        self._backend_file.seek(self._safebootdiskinf_sector * SECTOR_SIZE)
        disk_info = self._backend_file.read(0x5a)
        log.info('\n')
        print('//\t|+| SafeBoot Disk Info |+|\n|')
        print(f'|----- Signature:  {disk_info[:0x10].decode()}')
        print(f'|------- Disk ID:  {disk_info[0x11]}')
        print(f'|----- Disk GUID:  {build_GUID(disk_info)}')
        print(f'|----- Algorithm:  {hex(disk_info[0x37])} (AES-256-CBC)')
        print(f'|---- Sector Map:  {bytes2int(disk_info[0x43:0x47])}')
        print(f'|-- Sector Count:  {disk_info[0x4b]}')
        print(f'|----- Key Check:  {build_keycheck(disk_info)}')
        print(f'|\n\\\\\t|+| ****************** |+|')


    # read from the sector map and rebuild Safe Boot partition
    def _read_sector_map(self):
        for base, how_many in self._sector_map.items():
            self._sbfsdisk_data += read_sectors(self._backend_file, base, how_many)


    # read from disk the sector map [starting_sector]=how_many_sectors
    def _init_sector_map(self):
        self._backend_file.seek(0x1c) # 0x1c ==> address in sectors of SafeBootDiskInf
        self._safebootdiskinf_sector = read_addr_in_sectors(self._backend_file)

        check_signature(self._backend_file_name, b'SafeBootDiskInf', self._safebootdiskinf_sector*SECTOR_SIZE)

        self._backend_file.seek(self._safebootdiskinf_sector*SECTOR_SIZE + 0x43) # 0x43 ==> start of sector map
        sectormap_start = read_addr_in_sectors(self._backend_file)
        self._backend_file.seek(sectormap_start*SECTOR_SIZE + 0x4)

        entry_no = 0
        line = self._backend_file.read(0x10)
        first = True
        while bytes2int(line[:0x4]) != 0:
            starting_sector = bytes2int(line[:0x4])
            how_many = bytes2int(line[0x8:0xc])

            # ignore first sector containing only a SafeBoot signature
            if first:
                starting_sector += 1
                how_many -= 1
                first = False

            self._sector_map[starting_sector] = how_many
            line = self._backend_file.read(0x10)

        self._read_sector_map()
    

    async def getattr(self, inode, ctx=None):
        entry = pyfuse3.EntryAttributes()

        if inode == pyfuse3.ROOT_INODE:
            entry.st_mode = (stat.S_IFDIR | 0o555) # read-only
            entry.st_size = 0
        elif inode == self.encdisk_inode:
            entry.st_mode = (stat.S_IFREG | 0o444) # read-only
            if self._all_disk: # all disk
                entry.st_size = os.stat(self._backend_file_name).st_size
            else: # only a volume
                entry.st_size = (self._partition_start + self._partition_len) * SECTOR_SIZE
        elif inode == self.sbfsdisk_inode:
            entry.st_mode = (stat.S_IFREG | 0o444) # read-only
            entry.st_size = len(self._sbfsdisk_data)
        else:
            raise pyfuse3.FUSEError(errno.ENOENT)

        # set a fake timestamp in files information
        timestamp = 824463 * 1e12
        entry.st_atime_ns = timestamp
        entry.st_ctime_ns = timestamp
        entry.st_mtime_ns = timestamp
        entry.st_gid = os.getgid()
        entry.st_uid = os.getuid()
        entry.st_ino = inode

        return entry


    async def lookup(self, parent_inode, name, ctx=None):
        if parent_inode != pyfuse3.ROOT_INODE or \
           name != self.encdisk_name or \
           name != self.sbfsdisk_name:
            raise pyfuse3.FUSEError(errno.ENOENT)

        if name == self.encdisk_name:
            return self.getattr(self.encdisk_inode)

        return self.getattr(self.sbfsdisk_inode)


    async def opendir(self, inode, ctx):
        if inode != pyfuse3.ROOT_INODE:
            raise pyfuse3.FUSEError(errno.ENOENT)

        return inode


    async def readdir(self, fh, start_id, token):
        assert fh == pyfuse3.ROOT_INODE

        if start_id == 0:
            # safeboot
            pyfuse3.readdir_reply(
                token,
                self.sbfsdisk_name,
                await self.getattr(self.sbfsdisk_inode),
                1
            )
            # encrypted disk
            if self._crypto_handler is not None:
                pyfuse3.readdir_reply(
                    token,
                    self.encdisk_name,
                    await self.getattr(self.encdisk_inode),
                    1
                )


    async def open(self, inode, flags, ctx):
        if inode != self.encdisk_inode and inode != self.sbfsdisk_inode:
            raise pyfuse3.FUSEError(errno.ENOENT)
        
        # read-only 
        if flags & os.O_RDWR or flags & os.O_WRONLY:
            raise pyfuse3.FUSEError(errno.EACCES)
        
        return pyfuse3.FileInfo(fh=inode)


    async def read(self, fh, off, size):
        if self._verbose:
            log.info(f'read: fh={fh}\toffset={off}\tn_bytes={size}')

        if fh != self.encdisk_inode and fh != self.sbfsdisk_inode:
            raise pyfuse3.FUSEError(errno.ENOENT)

        # read SafeBoot.disk
        if fh == self.sbfsdisk_inode:
            return self._sbfsdisk_data[off:off+size]

        # read encdisk.img
        return await self._crypto_handler.decrypt_at_offset(
            self._backend_file, 
            self._partition_start*SECTOR_SIZE + off, 
            size
        )