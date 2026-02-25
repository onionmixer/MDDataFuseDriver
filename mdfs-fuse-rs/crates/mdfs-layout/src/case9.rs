use mdfs_index::{Case9Record, Case9Tag};

#[derive(Debug, Clone, Copy)]
pub struct RequestFrame<'a> {
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Case9Error {
    TooShort,
    UnsupportedReq1(u8),
}

impl<'a> RequestFrame<'a> {
    pub fn get(&self, off: usize) -> Result<u8, Case9Error> {
        self.bytes.get(off).copied().ok_or(Case9Error::TooShort)
    }
}

pub fn parse_case9(req: RequestFrame<'_>) -> Result<Case9Record, Case9Error> {
    let req1 = req.get(1)?;
    if req1 != 9 {
        return Err(Case9Error::UnsupportedReq1(req1));
    }

    let k17 = req.get(0x17)?;
    let b10 = req.get(0x10)?;
    let b11 = req.get(0x11)?;
    let b12 = req.get(0x12)?;
    let b13 = req.get(0x13)?;
    let b14 = req.get(0x14)?;
    let b15 = req.get(0x15)?;

    let rec = if k17 == 0 {
        Case9Record {
            tag: Case9Tag::Tag45,
            out2: b13,
            out3: b12,
            out4: b11,
            out5: b10,
            out7: b15,
            out8: b14,
        }
    } else {
        Case9Record {
            tag: Case9Tag::Tag48,
            out2: 0,
            out3: 0,
            out4: b10,
            out5: 0,
            out7: b10.wrapping_add(b14),
            out8: 0,
        }
    };

    Ok(rec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdfs_index::Case9Tag;

    fn mk_req(req1: u8, req17: u8) -> [u8; 0x18] {
        let mut b = [0u8; 0x18];
        b[1] = req1;
        b[0x10] = 0x11;
        b[0x11] = 0x22;
        b[0x12] = 0x33;
        b[0x13] = 0x44;
        b[0x14] = 0x55;
        b[0x15] = 0x66;
        b[0x17] = req17;
        b
    }

    #[test]
    fn parses_tag45_variant() {
        let req = mk_req(9, 0);
        let rec = parse_case9(RequestFrame { bytes: &req }).expect("parse ok");
        assert_eq!(rec.tag, Case9Tag::Tag45);
        assert_eq!(rec.out2, 0x44);
        assert_eq!(rec.out3, 0x33);
        assert_eq!(rec.out4, 0x22);
        assert_eq!(rec.out5, 0x11);
        assert_eq!(rec.out7, 0x66);
        assert_eq!(rec.out8, 0x55);
    }

    #[test]
    fn parses_tag48_variant() {
        let req = mk_req(9, 1);
        let rec = parse_case9(RequestFrame { bytes: &req }).expect("parse ok");
        assert_eq!(rec.tag, Case9Tag::Tag48);
        assert_eq!(rec.out4, 0x11);
        assert_eq!(rec.out7, 0x66);
    }

    #[test]
    fn rejects_non_case9() {
        let req = mk_req(8, 0);
        let err = parse_case9(RequestFrame { bytes: &req }).expect_err("must fail");
        assert_eq!(err, Case9Error::UnsupportedReq1(8));
    }
}
