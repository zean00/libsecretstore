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

use ethereum_types::H512;
use bytes::Bytes;
use serde::Serialize;

/// Encrypted document key.
#[derive(Default, Debug, Serialize, PartialEq)]
pub struct EncryptedDocumentKey {
	/// Common encryption point. Pass this to Secret Store 'Document key storing session'
	pub common_point: H512,
	/// Encrypted point. Pass this to Secret Store 'Document key storing session'.
	pub encrypted_point: H512,
	/// Document key itself, encrypted with passed account public. Pass this to 'secretstore_encrypt'.
	pub encrypted_key: Bytes,
}
