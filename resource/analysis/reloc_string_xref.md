# Relocation-Based String Xrefs (DOS EXE)

Date: 2026-02-16

## w31/extract/mdcache.exe
- relocation_count: 627
- string_xref_hits: 57
- key_hits: 15

| rel# | ptr_file_off | target_file_off | text |
| --- | --- | --- | --- |
| 16 | 0x0c95c | 0x0cb2e |  device reported error while formatting media
 |
| 22 | 0x0c944 | 0x0ca40 | Unable to access \MDCTL
Application will abort.
 |
| 25 | 0x0c938 | 0x0c9c0 | Unable to find MD DATA device.
Application will abort.
 |
| 26 | 0x0c934 | 0x0c99f | drive is not an MD DATA device
 |
| 28 | 0x0cd00 | 0x0cee2 |   Enable/Disable/Flush write cache of MD DATA device

SYNTAX:
  mdcache [-?] [drive:] ON \| OFF |
| 29 | 0x0ccfc | 0x0ceaf | device reported error while flushing write cache
 |
| 30 | 0x0ccf8 | 0x0ce90 | write cache has been flushed
 |
| 31 | 0x0ccf4 | 0x0ce5c | device reported error while disabling write cache
 |
| 32 | 0x0ccf0 | 0x0ce42 | write cache is disabled
 |
| 33 | 0x0ccec | 0x0ce0f | device reported error while enabling write cache
 |
| 34 | 0x0cce8 | 0x0cdf6 | write cache is enabled
 |
| 36 | 0x0cce0 | 0x0cdbf | ERROR: this drive is not an MD DATA device.

 |
| 40 | 0x0ccd0 | 0x0cd04 | MDcache version 1.0, Copyright (c) 1994 Sony Corporation.

 |
| 193 | 0x0d5a0 | 0x0d78b | Exec format error |
| 203 | 0x0d578 | 0x0d6e5 | Invalid format |

## w31/extract/mdformat.exe
- relocation_count: 1382
- string_xref_hits: 142
- key_hits: 19

| rel# | ptr_file_off | target_file_off | text |
| --- | --- | --- | --- |
| 470 | 0x19244 | 0x1995c | Format completed successfully.
141,099,008 bytes available.

Would you like to format another |
| 471 | 0x19240 | 0x198f1 | Safe format requires 35 minutes.

The process can NOT be canceled during the first 34 minutes. |
| 472 | 0x1923c | 0x198c2 | Quick format requires 90 seconds

Continue?  |
| 482 | 0x19214 | 0x195cd |   Format an MD DATA disc
SYNTAX:
  mdformat drive: [-q \| -s] [-o -v:label -?]
PARAMETERS:
   |
| 483 | 0x19210 | 0x1959f | Volume Descriptor inhibits format of media.
 |
| 484 | 0x1920c | 0x1956f | media must be formatted with safe option (-s)
 |
| 485 | 0x19208 | 0x19548 | Unable to format media. Check media.
 |
| 486 | 0x19204 | 0x19509 | format completed successfully.

141,099,008 bytes available
 |
| 494 | 0x191e4 | 0x1940c | Safe format requires approximately 35 minutes
 |
| 495 | 0x191e0 | 0x193e0 | Quick format requires less than 2 minutes
 |
| 497 | 0x191d8 | 0x1938b | ERROR: unable to communicate with an MD DATA component
 |
| 503 | 0x191c0 | 0x1929f | MDformat END
 |
| 504 | 0x191bc | 0x19248 | MDformat version 1.95
Copyright (c) 1994-95 Sony Corporation. All rights reserved.

 |
| 517 | 0x199f0 | 0x19bd1 | device reported error while formatting media
 |
| 523 | 0x199d8 | 0x19ae8 | Unable to access \MDCTL
Application will abort.
 |
| 526 | 0x199cc | 0x19a68 | Unable to find MD DATA device.
Application will abort.
 |
| 527 | 0x199c8 | 0x19a47 | drive is not an MD DATA device
 |
| 941 | 0x1a7c2 | 0x1a9ad | Exec format error |
| 951 | 0x1a79a | 0x1a907 | Invalid format |

## w31/extract/mdfsck.exe
- relocation_count: 386
- string_xref_hits: 43
- key_hits: 3

| rel# | ptr_file_off | target_file_off | text |
| --- | --- | --- | --- |
| 221 | 0x0e6a0 | 0x0e5b8 |   MD DATA File System Check
SYNTAX:
  mdfsck drive: [-v?]
PARAMETERS:
  drive:  specifies dr |
| 297 | 0x0f8c2 | 0x0f8b9 | A:\MDCTL |
| 377 | 0x0fdb2 | 0x0fc95 | Exec format error |

