# WS24 MDCTL Callsite Lift

Date: 2026-02-17

| file | channel | target | call_site | push_sequence_before_call | local_header_writes_before_call |
| --- | --- | --- | --- | --- | --- |
| w31/extract/mdcache.exe | ioctl_wrapper | 0x15b6 | 0x2347 | 0x2331:cs<br>0x2341:ax<br>0x2342:word ptr [bp - 8]<br>0x2346:cs | 0x2338:mov word ptr [bp - 8], ax |
| w31/extract/mdcache.exe | ioctl_wrapper | 0x15b6 | 0x2371 | 0x2366:dx<br>0x2367:ax<br>0x236b:ax<br>0x236c:word ptr [bp - 8]<br>0x2370:cs |  |
| w31/extract/mdformat.exe | ioctl_wrapper | 0x2439 | 0x3b92 | 0x3b7c:cs<br>0x3b8c:ax<br>0x3b8d:word ptr [bp - 8]<br>0x3b91:cs | 0x3b83:mov word ptr [bp - 8], ax |
| w31/extract/mdformat.exe | ioctl_wrapper | 0x2439 | 0x3bbc | 0x3bb1:dx<br>0x3bb2:ax<br>0x3bb6:ax<br>0x3bb7:word ptr [bp - 8]<br>0x3bbb:cs |  |
| w31/extract/mdfsck.exe | transport_tx | 0x1396 | 0x39ba | 0x39a2:ss<br>0x39b0:0x4a<br>0x39b5:ss<br>0x39b6:ax<br>0x39b7:word ptr [bp + 6] | 0x39a9:mov byte ptr [bp - 0x4a], al<br>0x39ac:mov byte ptr [bp - 0x49], 2 |
| w31/extract/mdfsck.exe | transport_tx | 0x1396 | 0x3a71 | 0x3a5d:ss<br>0x3a69:0x20<br>0x3a6e:ss<br>0x3a6f:ax<br>0x3a70:si | 0x3a61:mov byte ptr [bp - 0x20], 2<br>0x3a65:mov byte ptr [bp - 0x1f], 4 |
| w31/extract/mdfsck.exe | transport_tx | 0x1396 | 0x3b14 | 0x3afc:ds<br>0x3b0a:0x20<br>0x3b0f:ss<br>0x3b10:ax<br>0x3b11:word ptr [bp + 6] |  |
| w31/extract/mdfsck.exe | transport_tx | 0x1396 | 0x3baa | 0x3b92:ss<br>0x3ba0:0x208<br>0x3ba7:ss<br>0x3ba8:ax<br>0x3ba9:si | 0x3b96:mov byte ptr [bp - 0x208], 2<br>0x3b9b:mov byte ptr [bp - 0x207], 6 |
| w31/extract/mdfsck.exe | transport_tx | 0x1396 | 0x3c58 | 0x3c3d:ds<br>0x3c4c:0x208<br>0x3c53:ss<br>0x3c54:ax<br>0x3c55:word ptr [bp + 6] |  |
| w31/extract/mdfsck.exe | transport_tx | 0x1396 | 0x3d6e | 0x3d62:word ptr [bp - 6]<br>0x3d65:0x5cb<br>0x3d68:0<br>0x3d6b:word ptr [bp + 6] |  |
| w31/extract/mdfsck.exe | transport_tx | 0x1396 | 0x3e98 | 0x3e83:ss<br>0x3e90:0x11<br>0x3e95:ss<br>0x3e96:ax<br>0x3e97:si | 0x3e88:mov byte ptr [bp - 0x12], 2<br>0x3e8c:mov byte ptr [bp - 0x11], 8 |
| w31/extract/mdfsck.exe | transport_tx | 0x1396 | 0x3f18 | 0x3efd:ss<br>0x3f0e:0x17<br>0x3f13:ss<br>0x3f14:ax<br>0x3f15:word ptr [bp + 6] | 0x3f02:mov byte ptr [bp - 0x18], 1<br>0x3f06:mov byte ptr [bp - 0x17], 0x24<br>0x3f0a:mov byte ptr [bp - 7], 2 |
| w31/extract/mdfsck.exe | transport_tx | 0x1396 | 0x3f6d | 0x3f57:ss<br>0x3f63:0x10<br>0x3f68:ss<br>0x3f69:ax<br>0x3f6a:word ptr [bp + 6] | 0x3f5b:mov byte ptr [bp - 0x10], 1<br>0x3f5f:mov byte ptr [bp - 0xf], 7 |
| w31/extract/mdfsck.exe | transport_tx | 0x1396 | 0x49f3 | 0x49e6:ax<br>0x49e7:word ptr [si + 8]<br>0x49ea:word ptr [si + 6]<br>0x49f2:ax | 0x49df:mov word ptr [bp - 2], ax |
| w31/extract/mdfsck.exe | transport_tx | 0x1396 | 0x56d5 | 0x56c1:es<br>0x56c2:bx<br>0x56cb:ax<br>0x56cc:word ptr [bp + 8]<br>0x56cf:word ptr [bp + 6]<br>0x56d4:ax |  |
| w31/extract/mdfsck.exe | transport_tx | 0x1396 | 0x56e8 | 0x56cf:word ptr [bp + 6]<br>0x56d4:ax<br>0x56df:ax<br>0x56e3:ds<br>0x56e4:ax<br>0x56e7:ax |  |
| w31/extract/mdfsck.exe | transport_tx | 0x1396 | 0x5733 | 0x5721:dx<br>0x5722:ax<br>0x572b:ax<br>0x572c:word ptr [bp + 8]<br>0x572f:word ptr [bp + 6]<br>0x5732:si |  |
| w31/extract/mdfsck.exe | transport_tx | 0x1396 | 0x5745 | 0x572b:ax<br>0x572c:word ptr [bp + 8]<br>0x572f:word ptr [bp + 6]<br>0x5732:si<br>0x573e:ax<br>0x5742:ds<br>0x5743:ax<br>0x5744:si |  |
| w31/extract/mdfsck.exe | transport_rx | 0x1298 | 0x3a05 | 0x39fb:0x4a<br>0x3a00:ss<br>0x3a01:ax<br>0x3a02:word ptr [bp + 6] |  |
| w31/extract/mdfsck.exe | transport_rx | 0x1298 | 0x3aaa | 0x3aa2:0x20<br>0x3aa7:ss<br>0x3aa8:ax<br>0x3aa9:si |  |
| w31/extract/mdfsck.exe | transport_rx | 0x1298 | 0x3b4e | 0x3b44:0x20<br>0x3b49:ss<br>0x3b4a:ax<br>0x3b4b:word ptr [bp + 6] |  |
| w31/extract/mdfsck.exe | transport_rx | 0x1298 | 0x3be6 | 0x3bdc:0x208<br>0x3be3:ss<br>0x3be4:ax<br>0x3be5:si |  |
| w31/extract/mdfsck.exe | transport_rx | 0x1298 | 0x3c96 | 0x3c8a:0x208<br>0x3c91:ss<br>0x3c92:ax<br>0x3c93:word ptr [bp + 6] |  |
| w31/extract/mdfsck.exe | transport_rx | 0x1298 | 0x3da3 | 0x3d9b:si<br>0x3d9c:ax<br>0x3d9d:0<br>0x3da0:word ptr [bp + 6] |  |
| w31/extract/mdfsck.exe | transport_rx | 0x1298 | 0x3ed0 | 0x3ec8:0x11<br>0x3ecd:ss<br>0x3ece:ax<br>0x3ecf:si |  |

## Notes
- DOS wrappers (`mdcache`/`mdformat`) show caller-supplied push lanes into wrapper callsites.
- `mdfsck` rows capture transport callsites and nearby local frame writes as static schema candidates.
- This is static lift only; definitive field semantics require WS25 runtime buffer capture.
