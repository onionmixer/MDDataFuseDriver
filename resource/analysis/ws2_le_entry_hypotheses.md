# WS2 LE Entry Hypotheses

Date: 2026-02-16

## w95/extract/us/mdmgr.vxd ord 1-1
- raw: `01 00 03 20 03`
- flags: `1`
- candidate `u32_le(raw[1:5])`: `52429568` (`0x03200300`)
- candidate `u32_be(raw[1:5])`: `204803` (`0x00032003`)
- candidate pairs:
  - b1..2 LE `768` / BE `3`
  - b3..4 LE `800` / BE `8195`

## w95/extract/us/mdhlp.vxd ord 1-1
- raw: `01 00 03 bc 02`
- flags: `1`
- candidate `u32_le(raw[1:5])`: `45875968` (`0x02bc0300`)
- candidate `u32_be(raw[1:5])`: `244738` (`0x0003bc02`)
- candidate pairs:
  - b1..2 LE `768` / BE `3`
  - b3..4 LE `700` / BE `48130`

## w95/extract/us/mdfsd.vxd ord 1-1
- raw: `01 00 03 00 52`
- flags: `1`
- candidate `u32_le(raw[1:5])`: `1375732480` (`0x52000300`)
- candidate `u32_be(raw[1:5])`: `196690` (`0x00030052`)
- candidate pairs:
  - b1..2 LE `768` / BE `3`
  - b3..4 LE `20992` / BE `82`

