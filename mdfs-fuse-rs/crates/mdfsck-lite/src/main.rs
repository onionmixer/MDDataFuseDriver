use mdfs_fuse::{route_request, RouteOutcome, UnknownPathPolicy};
use mdfs_layout::{parse_case9, RequestFrame};

fn usage() -> &'static str {
    "Usage: mdfsck-lite --case9-hex <hex-bytes> [--unknown-policy eio|enotsup]"
}

fn parse_unknown_policy(s: &str) -> Result<UnknownPathPolicy, String> {
    match s {
        "eio" => Ok(UnknownPathPolicy::FailClosedEio),
        "enotsup" => Ok(UnknownPathPolicy::FeatureEnotsup),
        _ => Err(format!("invalid --unknown-policy: {s}")),
    }
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let compact: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',' && *c != '_' && *c != ':')
        .collect();
    if compact.is_empty() {
        return Err("empty hex payload".to_string());
    }
    if compact.len() % 2 != 0 {
        return Err("hex payload length must be even".to_string());
    }

    let mut out = Vec::with_capacity(compact.len() / 2);
    let mut i = 0usize;
    while i < compact.len() {
        let chunk = &compact[i..i + 2];
        let v = u8::from_str_radix(chunk, 16).map_err(|_| format!("invalid hex byte: {chunk}"))?;
        out.push(v);
        i += 2;
    }
    Ok(out)
}

fn run_case9_check(req: &[u8], unknown_policy: UnknownPathPolicy) -> String {
    match route_request(req, unknown_policy) {
        RouteOutcome::ParsedCase9 => {
            let rec = parse_case9(RequestFrame { bytes: req }).expect("route+parse must match");
            format!(
                "status=ok tag={:?} out2=0x{:02x} out3=0x{:02x} out4=0x{:02x} out5=0x{:02x} out7=0x{:02x} out8=0x{:02x}",
                rec.tag, rec.out2, rec.out3, rec.out4, rec.out5, rec.out7, rec.out8
            )
        }
        RouteOutcome::Rejected { errno, log_line } => {
            format!("status=rejected errno={:?} {log_line}", errno)
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut hex_input: Option<String> = None;
    let mut unknown_policy = UnknownPathPolicy::FailClosedEio;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--case9-hex" => {
                hex_input = args.next();
            }
            "--unknown-policy" => {
                let p = args.next().unwrap_or_default();
                match parse_unknown_policy(&p) {
                    Ok(v) => unknown_policy = v,
                    Err(e) => {
                        eprintln!("{e}");
                        eprintln!("{}", usage());
                        std::process::exit(2);
                    }
                }
            }
            "-h" | "--help" => {
                println!("{}", usage());
                return;
            }
            _ => {
                eprintln!("unknown arg: {arg}");
                eprintln!("{}", usage());
                std::process::exit(2);
            }
        }
    }

    let hex = match hex_input {
        Some(v) => v,
        None => {
            eprintln!("missing --case9-hex");
            eprintln!("{}", usage());
            std::process::exit(2);
        }
    };

    let req = match parse_hex_bytes(&hex) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    println!("{}", run_case9_check(&req, unknown_policy));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_with_separators() {
        let b = parse_hex_bytes("00 09,11_22:33").expect("parse");
        assert_eq!(b, vec![0x00, 0x09, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn rejects_odd_hex_len() {
        let err = parse_hex_bytes("009").expect_err("must fail");
        assert!(err.contains("even"));
    }

    #[test]
    fn accepts_case9_and_emits_ok_status() {
        let mut req = vec![0u8; 0x18];
        req[1] = 9;
        req[0x10] = 1;
        req[0x11] = 2;
        req[0x12] = 3;
        req[0x13] = 4;
        req[0x14] = 5;
        req[0x15] = 6;
        req[0x17] = 0;
        let out = run_case9_check(&req, UnknownPathPolicy::FailClosedEio);
        assert!(out.starts_with("status=ok"));
        assert!(out.contains("tag=Tag45"));
    }

    #[test]
    fn unknown_lane_can_emit_enotsup() {
        let req = vec![0u8; 0x18];
        let out = run_case9_check(&req, UnknownPathPolicy::FeatureEnotsup);
        assert!(out.contains("status=rejected"));
        assert!(out.contains("errno=Enotsup"));
    }
}
