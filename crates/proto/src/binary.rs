//! Binary frames: `u8 kind | u32 stream | u32 seq | payload`, integers big-endian.

/// The largest payload one binary frame carries. Bigger data goes in several frames.
pub const MAX_CHUNK: usize = 64 * 1024;
/// Length of the fixed header before the payload.
pub const HEADER_LEN: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    /// Device to portal: output of a running `exec.start` (stdout and stderr merged).
    ExecOutput = 1,
    /// Device to portal: the content of an `fs.read`, sent before its result.
    FileData = 2,
    /// Portal to device: the content of an `fs.write`, sent after its request.
    FileUpload = 3,
}

impl FrameKind {
    pub fn from_u8(v: u8) -> Option<FrameKind> {
        match v {
            1 => Some(FrameKind::ExecOutput),
            2 => Some(FrameKind::FileData),
            3 => Some(FrameKind::FileUpload),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryFrame {
    pub kind: FrameKind,
    pub stream: u32,
    pub seq: u32,
    pub payload: Vec<u8>,
}

impl BinaryFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.push(self.kind as u8);
        out.extend_from_slice(&self.stream.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> Result<BinaryFrame, String> {
        if data.len() < HEADER_LEN {
            return Err(format!("binary frame of {} bytes is too short", data.len()));
        }
        if data.len() - HEADER_LEN > MAX_CHUNK {
            return Err(format!(
                "binary frame payload of {} bytes is over {MAX_CHUNK}",
                data.len() - HEADER_LEN
            ));
        }
        let kind =
            FrameKind::from_u8(data[0]).ok_or_else(|| format!("unknown frame kind {}", data[0]))?;
        let stream = u32::from_be_bytes(data[1..5].try_into().unwrap());
        let seq = u32::from_be_bytes(data[5..9].try_into().unwrap());
        Ok(BinaryFrame {
            kind,
            stream,
            seq,
            payload: data[HEADER_LEN..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let f = BinaryFrame {
            kind: FrameKind::ExecOutput,
            stream: 0x01020304,
            seq: 5,
            payload: b"hi".to_vec(),
        };
        let bytes = f.encode();
        assert_eq!(&bytes[..9], &[1, 1, 2, 3, 4, 0, 0, 0, 5]);
        assert_eq!(BinaryFrame::decode(&bytes).unwrap(), f);
    }

    #[test]
    fn refuses_bad_frames() {
        assert!(BinaryFrame::decode(&[1, 0, 0]).is_err());
        assert!(BinaryFrame::decode(&[9, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        let mut big = vec![3u8, 0, 0, 0, 1, 0, 0, 0, 0];
        big.resize(HEADER_LEN + MAX_CHUNK + 1, 0);
        assert!(BinaryFrame::decode(&big).is_err());
    }
}
