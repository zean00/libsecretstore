// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

//! RPC Error codes and error objects

use std::fmt;

use jsonrpc_core::{Error, ErrorCode, Value};

mod codes {
	// NOTE [ToDr] Codes from [-32099, -32000]
	pub const ENCRYPTION_ERROR: i64 = -32055;
}

pub fn invalid_params<T: fmt::Debug>(param: &str, details: T) -> Error {
	Error {
		code: ErrorCode::InvalidParams,
		message: format!("Couldn't parse parameters: {}", param),
		data: Some(Value::String(format!("{:?}", details))),
	}
}

pub fn encryption<T: fmt::Debug>(error: T) -> Error {
	Error {
		code: ErrorCode::ServerError(codes::ENCRYPTION_ERROR),
		message: "Encryption error.".into(),
		data: Some(Value::String(format!("{:?}", error))),
	}
}
