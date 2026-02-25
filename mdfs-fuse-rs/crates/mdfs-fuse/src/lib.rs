use mdfs_layout::{parse_case9, Case9Error, RequestFrame};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchPolicy {
    SupportedCase9,
    UnknownPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownPathPolicy {
    /// Conservative default: unknown protocol lanes are treated as hard I/O faults.
    FailClosedEio,
    /// Feature-probe mode: unknown lane is marked unsupported without implying media damage.
    FeatureEnotsup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuseErrno {
    Eio,
    Enotsup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownPathEvent {
    pub req1: u8,
    pub req_len: usize,
    pub policy: UnknownPathPolicy,
    pub errno: FuseErrno,
    pub reason: &'static str,
}

impl UnknownPathEvent {
    pub fn log_line(&self) -> String {
        format!(
            "level=WARN event=unknown_path req1=0x{req1:02x} req_len={req_len} policy={policy} errno={errno} reason={reason}",
            req1 = self.req1,
            req_len = self.req_len,
            policy = match self.policy {
                UnknownPathPolicy::FailClosedEio => "fail_closed_eio",
                UnknownPathPolicy::FeatureEnotsup => "feature_enotsup",
            },
            errno = match self.errno {
                FuseErrno::Eio => "EIO",
                FuseErrno::Enotsup => "ENOTSUP",
            },
            reason = self.reason,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOutcome {
    ParsedCase9,
    Rejected { errno: FuseErrno, log_line: String },
}

pub fn classify_req1(req1: u8) -> DispatchPolicy {
    if req1 == 9 {
        DispatchPolicy::SupportedCase9
    } else {
        DispatchPolicy::UnknownPath
    }
}

pub fn map_unknown_path_errno(policy: UnknownPathPolicy) -> FuseErrno {
    match policy {
        UnknownPathPolicy::FailClosedEio => FuseErrno::Eio,
        UnknownPathPolicy::FeatureEnotsup => FuseErrno::Enotsup,
    }
}

pub fn route_request(req: &[u8], unknown_policy: UnknownPathPolicy) -> RouteOutcome {
    if req.len() < 2 {
        let event = UnknownPathEvent {
            req1: 0,
            req_len: req.len(),
            policy: UnknownPathPolicy::FailClosedEio,
            errno: FuseErrno::Eio,
            reason: "frame_too_short_for_req1",
        };
        return RouteOutcome::Rejected {
            errno: event.errno,
            log_line: event.log_line(),
        };
    }

    let req1 = req.get(1).copied().unwrap_or(0);
    if classify_req1(req1) == DispatchPolicy::UnknownPath {
        let event = UnknownPathEvent {
            req1,
            req_len: req.len(),
            policy: unknown_policy,
            errno: map_unknown_path_errno(unknown_policy),
            reason: "req1_not_in_supported_subset",
        };
        return RouteOutcome::Rejected {
            errno: event.errno,
            log_line: event.log_line(),
        };
    }

    match parse_case9(RequestFrame { bytes: req }) {
        Ok(_) => RouteOutcome::ParsedCase9,
        Err(err) => {
            let reason = match err {
                Case9Error::TooShort => "case9_too_short",
                Case9Error::UnsupportedReq1(_) => "case9_req1_mismatch",
            };
            let event = UnknownPathEvent {
                req1,
                req_len: req.len(),
                policy: UnknownPathPolicy::FailClosedEio,
                errno: FuseErrno::Eio,
                reason,
            };
            RouteOutcome::Rejected {
                errno: event.errno,
                log_line: event.log_line(),
            }
        }
    }
}

pub fn try_parse_case9(req: &[u8]) -> bool {
    parse_case9(RequestFrame { bytes: req }).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_case9() -> [u8; 0x18] {
        let mut b = [0u8; 0x18];
        b[1] = 9;
        b[0x10] = 0x11;
        b[0x11] = 0x22;
        b[0x12] = 0x33;
        b[0x13] = 0x44;
        b[0x14] = 0x55;
        b[0x15] = 0x66;
        b[0x17] = 0;
        b
    }

    #[test]
    fn maps_unknown_to_eio_in_fail_closed_mode() {
        let req = [0u8; 0x18];
        let out = route_request(&req, UnknownPathPolicy::FailClosedEio);
        assert_eq!(
            out,
            RouteOutcome::Rejected {
                errno: FuseErrno::Eio,
                log_line: "level=WARN event=unknown_path req1=0x00 req_len=24 policy=fail_closed_eio errno=EIO reason=req1_not_in_supported_subset".to_string(),
            }
        );
    }

    #[test]
    fn maps_unknown_to_enotsup_in_feature_mode() {
        let mut req = [0u8; 0x18];
        req[1] = 0x0a;
        let out = route_request(&req, UnknownPathPolicy::FeatureEnotsup);
        assert_eq!(
            out,
            RouteOutcome::Rejected {
                errno: FuseErrno::Enotsup,
                log_line: "level=WARN event=unknown_path req1=0x0a req_len=24 policy=feature_enotsup errno=ENOTSUP reason=req1_not_in_supported_subset".to_string(),
            }
        );
    }

    #[test]
    fn parses_supported_case9() {
        let req = mk_case9();
        assert_eq!(
            route_request(&req, UnknownPathPolicy::FailClosedEio),
            RouteOutcome::ParsedCase9
        );
    }

    #[test]
    fn short_case9_is_hard_eio() {
        let mut req = [0u8; 2];
        req[1] = 9;
        let out = route_request(&req, UnknownPathPolicy::FeatureEnotsup);
        assert_eq!(
            out,
            RouteOutcome::Rejected {
                errno: FuseErrno::Eio,
                log_line: "level=WARN event=unknown_path req1=0x09 req_len=2 policy=fail_closed_eio errno=EIO reason=case9_too_short".to_string(),
            }
        );
    }

    #[test]
    fn truncated_case9_body_is_hard_eio() {
        let mut req = [0u8; 10];
        req[1] = 9;
        let out = route_request(&req, UnknownPathPolicy::FeatureEnotsup);
        assert_eq!(
            out,
            RouteOutcome::Rejected {
                errno: FuseErrno::Eio,
                log_line: "level=WARN event=unknown_path req1=0x09 req_len=10 policy=fail_closed_eio errno=EIO reason=case9_too_short".to_string(),
            }
        );
    }
}
