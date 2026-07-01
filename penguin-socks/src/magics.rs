//! SOCKS protocol magic constants.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

/// Field `VN` of a `SOCKSv4` request
pub const VER_4: u8 = 0x04;
/// Field `VER` of a `SOCKSv5` request
pub const VER_5: u8 = 0x05;
/// Field `VN` of a `SOCKSv4` response
pub const VER_REP_4: u8 = 0x00;

/// Command `CONNECT`
pub const CMD_CONNECT: u8 = 0x01;
/// Command `BIND`
pub const CMD_BIND: u8 = 0x02;
/// Command `UDP ASSOCIATE`
pub const CMD_ASSOC: u8 = 0x03;

/// Address type `IP V4 address`
pub const ATYP_IPV4: u8 = 0x01;
/// Address type `DOMAINNAME`
pub const ATYP_DOMAIN: u8 = 0x03;
/// Address type `IP V6 address`
pub const ATYP_IPV6: u8 = 0x04;

/// Authentication method `NO AUTHENTICATION REQUIRED`
pub const AUTH_NOAUTH: u8 = 0x00;
/// Authentication method `GSSAPI`
pub const AUTH_GSSAPI: u8 = 0x01;
/// Authentication method `USERNAME/PASSWORD`
pub const AUTH_USERPASS: u8 = 0x02;
/// Authentication method `NO ACCEPTABLE METHODS`
pub const AUTH_NOACCEPT: u8 = 0xff;

/// Reply field `succeeded`
pub const REP_SUCC: u8 = 0x00;
/// Reply field `general SOCKS server failure`
pub const REP_GENFAIL: u8 = 0x01;
/// Reply field `connection not allowed by ruleset`
pub const REP_NOTALLOWED: u8 = 0x02;
/// Reply field `network unreachable`
pub const REP_NETUNRE: u8 = 0x03;
/// Reply field `host unreachable`
pub const REP_HOSTUNRE: u8 = 0x04;
/// Reply field `connection refused`
pub const REP_CONNREF: u8 = 0x05;
/// Reply field `TTL expired`
pub const REP_TTLEXP: u8 = 0x06;
/// Reply field `command not supported`
pub const REP_CMDUNSUP: u8 = 0x07;
/// Reply field `address type not supported`
pub const REP_ATYPUNSUP: u8 = 0x08;

/// `SOCKSv4` reply field `request granted`
pub const REP_V4_SUCC: u8 = 90;
/// `SOCKSv4` reply field `request rejected or failed`
pub const REP_V4_FAIL: u8 = 91;
/// `SOCKSv4` reply field `request rejected because SOCKS server cannot connect to identd on the client`
pub const REP_V4_NOIDENT: u8 = 92;
/// `SOCKSv4` reply field `request rejected because the client program and identd report different user-ids`
pub const REP_V4_DIFFIDENT: u8 = 93;

/// Reserved all-zero field
pub const RESERVED: u8 = 0x00;
