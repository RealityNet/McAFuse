#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import trio
import pyfuse3

from mcafee_fde import McafeeFde
from crypto_handler import CryptoHandler
from utils import parse_args, init_logging, log, check_signature, check_if_files_exist


def main():
    options = parse_args()
    init_logging(options.debug)

    if options.verbose:
        log.info('|++| Starting McAfuse...')

    crypto_hnl = None
    mcafee_fde = None
    try:
        check_if_files_exist(options.disk_image, options.keyfile, options.mountpoint)
        check_signature(options.disk_image, b'#SafeBoot', 0x2)
        if options.keyfile:
            crypto_hnl = CryptoHandler(options.keyfile, options.verbose)
        mcafee_fde = McafeeFde(
            options.disk_image,
            crypto_hnl,
            options.info,
            options.all,
            options.verbose
        )
    except (ValueError, FileNotFoundError, NotADirectoryError, NotImplementedError) as ex:
        log.error(ex)
        return

    fuse_options = set(pyfuse3.default_options)
    fuse_options.add('fsname=McAFuse')
    fuse_options.add('allow_other') # to allow user to navigate fuse fs
    
    try:
        pyfuse3.init(mcafee_fde, options.mountpoint, fuse_options)
        trio.run(pyfuse3.main)
    except RuntimeError as re:
        log.error(re)
        log.error('|!| -- [ERROR] -- The program need administrative privileges, try with sudo')
        return
    except:
        log.warning('|--| Terminated with CTRL-C (SIGINT)...')
        log.warning('|--| Unmounting...')
        pyfuse3.close(unmount=True)
        return

    if options.verbose:
        log.info('|++| Gracefully terminating McAfuse...')

    pyfuse3.close()


if __name__ == '__main__':
    main()