// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! UDP-Lite headers.
//!
//! RFC 3828: The Lightweight User Datagram Protocol (UDP-Lite).
//!
//! UDP-Lite has the same 8-byte layout as UDP, except that the `length`
//! field is replaced by a `coverage` field: the number of octets (counted
//! from the first octet of the UDP-Lite header) that the checksum covers.
//! The datagram length comes from the IP layer instead.
//!
//! A coverage of `0` means the checksum covers the entire datagram. Values
//! of `1..=7` are invalid, as the header must always be covered. Unlike UDP,
//! a transmitted checksum of `0` is not permitted.

use ingot::Ingot;
use ingot::ip::IpProtocol;
use ingot::types::primitives::u16be;

/// The IP protocol number assigned to UDP-Lite (RFC 3828, section 3).
pub const IPPROTO_UDPLITE: IpProtocol = IpProtocol(136);

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct UdpLite {
    pub source: u16be,
    pub destination: u16be,
    /// Number of octets covered by the checksum, from the start of this
    /// header. `0` means the whole datagram.
    pub coverage: u16be,
    pub checksum: u16be,
}

impl UdpLite {
    /// The size of a UDP-Lite header in bytes.
    pub const MINIMUM_LENGTH: usize = 8;
}

/// A transmitted UDP-Lite checksum of zero is invalid (RFC 3828, section
/// 3.1), so a computed checksum of zero is sent as all ones instead.
#[inline]
pub fn nonzero_checksum(csum: u16) -> u16 {
    if csum == 0 { 0xFFFF } else { csum }
}

/// Returns the part of a UDP-Lite datagram's body that the checksum covers.
///
/// `coverage` is counted from the first octet of the UDP-Lite header, so the
/// header's own octets are subtracted to find how much of `body` is covered.
/// A coverage of zero means the entire body is covered.
#[inline]
pub fn covered_body(coverage: u16, body: &[u8]) -> &[u8] {
    if coverage == 0 {
        return body;
    }

    let covered = usize::from(coverage).saturating_sub(UdpLite::MINIMUM_LENGTH);
    &body[..covered.min(body.len())]
}

#[cfg(test)]
mod test {
    use super::*;
    use ingot::types::Emit;
    use ingot::types::HeaderParse;

    #[test]
    fn header_is_eight_bytes_in_network_order() {
        let hdr = UdpLite {
            source: 5000,
            destination: 5001,
            coverage: 16,
            checksum: 0xA1B0,
        };

        let bytes = hdr.emit_vec();
        assert_eq!(bytes, [0x13, 0x88, 0x13, 0x89, 0x00, 0x10, 0xA1, 0xB0]);
        assert_eq!(bytes.len(), UdpLite::MINIMUM_LENGTH);

        let (parsed, ..) = ValidUdpLite::parse(&bytes[..]).unwrap();
        assert_eq!(parsed.source(), 5000);
        assert_eq!(parsed.destination(), 5001);
        assert_eq!(parsed.coverage(), 16);
        assert_eq!(parsed.checksum(), 0xA1B0);
    }

    #[test]
    fn protocol_number_is_136() {
        assert_eq!(IPPROTO_UDPLITE.0, 136);
    }

    #[test]
    fn zero_checksum_is_sent_as_all_ones() {
        assert_eq!(nonzero_checksum(0), 0xFFFF);
        assert_eq!(nonzero_checksum(1), 1);
        assert_eq!(nonzero_checksum(0xFFFF), 0xFFFF);
    }

    #[test]
    fn covered_body_follows_coverage() {
        let body = b"hey bro where is my id";

        // Zero coverage means the whole datagram.
        assert_eq!(covered_body(0, body), &body[..]);
        // Coverage counts the 8 header octets, so 8 covers no body at all.
        assert_eq!(covered_body(8, body), b"");
        // 16 = 8 header octets + the first 8 octets of the body.
        assert_eq!(covered_body(16, body), b"hey bro ");
        // Coverage past the end of the body cannot read beyond it.
        assert_eq!(covered_body(u16::MAX, body), &body[..]);
        // Invalid coverage (1..=7) is rejected at parse time, but must never
        // underflow if it ever reaches here.
        assert_eq!(covered_body(5, body), b"");
    }
}
