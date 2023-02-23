# sg3f_checksum_locater

- This repository contains a script meant to locate checksums in Seagete F3 drive.
- Referred to https://github.com/eurecom-s3/hdd_firmware_tools/blob/master/scripts/hdd_crc.py for how to calculate a checksum.

## Requirements
- Following modules are required
    - numpy
    - scipy

## How to use
- Please run ```python sg3f_checksum_locater.py -h```

## Example
- ```python script/sg3f_checksum_locater.py sample/FILE_A_32A_0  --start 0x70000 --end 0x75000 --strip_by_size 16 --strip_by_entropy 0.2 --strip_by_last2bytes --strip_by_last4bytes --bruteforce```
