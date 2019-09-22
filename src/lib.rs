extern crate parity_bytes as bytes;
extern crate parity_crypto as crypto;

mod helpers;
mod types;

use crypto::DEFAULT_MAC;
use ethereum_types::{H256, H512};
use ethkey::{Secret, KeyPair, sign};

use helpers::secretstore::{generate_document_key, encrypt_document,
	decrypt_document, decrypt_document_with_shadow, decrypt_with_shadow_coefficients};
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::str::FromStr;
use hex;
//use std::ptr;
use std::boxed::Box;
use std::convert::TryFrom;
use secp256k1::key;
use secp256k1::ecdh::SharedSecret;
use std::ops::Index;
use std::ops;

macro_rules! trychar {
    ($e:expr) => (match $e {
        Ok(val) => val,
        Err(_) => {
            let res = CString::new("").unwrap();
            let r = res.as_ptr();
            std::mem::forget(res);
            return r;
        },
    });
}

macro_rules! trybox {
    ($e:expr) => (match $e {
        Ok(val) => val,
        Err(_) => return Box::into_raw(Box::new(DocumentKey::default())),
    });
}

#[repr(C)]
pub struct DocumentKey {
	/// Common encryption point. Pass this to Secret Store 'Document key storing session'
	pub common_point: *const c_char,
	/// Encrypted point. Pass this to Secret Store 'Document key storing session'.
	pub encrypted_point: *const c_char,
	/// Document key itself, encrypted with passed account public. Pass this to 'secretstore_encrypt'.
	pub encrypted_key: *const c_char,
}

impl Default for DocumentKey {
    fn default () -> DocumentKey {
        let nstr = CString::new("").unwrap();
        let npr = nstr.as_ptr();
        std::mem::forget(nstr);
        let doc = DocumentKey{
            common_point: npr,
            encrypted_point: npr,
            encrypted_key: npr,
        };
        return doc;
    }
}

#[no_mangle]
pub unsafe extern "C" fn ss_echo(val: *const c_char) -> *const c_char {
   return val;
}

#[no_mangle]
pub unsafe extern "C" fn ss_shared_secret(public: *const c_char, secret: *const c_char) -> *const c_char {
    let s_str = trychar!(CStr::from_ptr(secret).to_str());
    let sec = trychar!(Secret::from_str(s_str));
    let sk = trychar!(sec.to_secp256k1_secret());

    let p_str = trychar!(CStr::from_ptr(public).to_str());
    let pubk = trychar!(hex::decode(p_str));
    let pk = trychar!(key::PublicKey::from_slice(&ethkey::SECP256K1, pubk.as_ref()));
    
    let sec = SharedSecret::new(&ethkey::SECP256K1, &pk, &sk);
    let hs = hex::encode(sec.index(ops::RangeFull{}));
    let res = trychar!(CString::new(hs));
    let r = res.as_ptr();
    std::mem::forget(res);
    std::mem::forget(secret);
    std::mem::forget(public);
    r
}


#[no_mangle]
pub unsafe extern "C" fn ss_get_document_key(secret: *const c_char, public: *const c_char) -> *const DocumentKey {  
    let s_str = trybox!(CStr::from_ptr(secret).to_str());
    let sk = trybox!(Secret::from_str(s_str));
    let p_str = trybox!(CStr::from_ptr(public).to_str());
    let pk = trybox!(H512::from_str(p_str));
    let kp = trybox!(KeyPair::from_secret(sk));
    let eset = trybox!(generate_document_key(*kp.public(), pk));
    let cp = hex::encode(eset.common_point);
    let cpres = trybox!(CString::new(cp));
    //let cpres = CStr::from_bytes_with_nul_unchecked(&cp.as_ref());
    let cpr = cpres.as_ptr();
    std::mem::forget(cpres);

    let ep = hex::encode(eset.encrypted_point);
    let epres = trybox!(CString::new(ep));
    //let epres = CStr::from_bytes_with_nul_unchecked(&ep.as_ref());
    let epr = epres.as_ptr();
    std::mem::forget(epres);
    

    let ek = hex::encode(eset.encrypted_key);
    let ekres = trybox!(CString::new(ek));
    //let ekres = CStr::from_bytes_with_nul_unchecked(&ek.as_bytes());
    let ekr = ekres.as_ptr();
    std::mem::forget(ekres);
    std::mem::forget(secret);
    std::mem::forget(public);
    
    Box::into_raw(Box::new(DocumentKey {
		common_point: cpr,
		encrypted_point: epr,
		encrypted_key: ekr,
	}))
}

#[no_mangle]
pub unsafe extern "C" fn ss_sign_hash(secret: *const c_char, hash: *const c_char) -> *const c_char { 
    let s_str = trychar!(CStr::from_ptr(secret).to_str());
    let sk = trychar!(Secret::from_str(s_str));

    let h_str = trychar!(CStr::from_ptr(hash).to_str());
    let hs = trychar!(H256::from_str(h_str));
    let sig = trychar!(sign(&sk, &hs));
    
    let sg = format!("{}", sig);
    let res = trychar!(CString::new(sg));
    let r = res.as_ptr();
    std::mem::forget(res);
    std::mem::forget(secret);
    std::mem::forget(hash);
    r
}

#[no_mangle]
pub unsafe extern "C" fn ss_encrypt(secret: *const c_char, ekey: *const c_char, data: *const c_char) -> *const c_char {
    let s_str = trychar!(CStr::from_ptr(secret).to_str());
    let sk = trychar!(Secret::from_str(s_str));

    let k_str = trychar!(CStr::from_ptr(ekey).to_str());
    let bkey = trychar!(hex::decode(k_str));
    let key = trychar!(ethkey::crypto::ecies::decrypt(&sk, &DEFAULT_MAC, bkey.as_ref()));

    let dt_str = trychar!(CStr::from_ptr(data).to_str());
    let dd = trychar!(hex::decode(dt_str));

    let enc = trychar!(encrypt_document(key, dd));
    let ek = hex::encode(enc);
    let res = trychar!(CString::new(ek));
    let r = res.as_ptr();
    std::mem::forget(res);
    std::mem::forget(secret);
    std::mem::forget(data);
    std::mem::forget(ekey);
    r
}

#[no_mangle]
pub unsafe extern "C" fn ss_decrypt_shadow(secret: *const c_char, decrypted_secret: *const c_char, common_point: *const c_char, decrypt_shadows: *const *const c_char, shadow_len : usize, data: *const c_char) -> *const c_char {
    let s_str = trychar!(CStr::from_ptr(secret).to_str());
    let sk = trychar!(Secret::from_str(s_str));

    let d_str = trychar!(CStr::from_ptr(decrypted_secret).to_str());
    let ds = trychar!(H512::from_str(d_str));

    let c_str = trychar!(CStr::from_ptr(common_point).to_str());
    let cp = trychar!(H512::from_str(c_str));

    let dt_str = trychar!(CStr::from_ptr(data).to_str());
    let dd = trychar!(hex::decode(dt_str));

    let mut shadows = Vec::new();
    let len = trychar!(isize::try_from(shadow_len));
    for i in 0 ..len {
        let sh: *const c_char = *(decrypt_shadows.offset(i));
        let sh_str = trychar!(CStr::from_ptr(sh).to_str());
        let dsh = trychar!(hex::decode(sh_str));
        let dec = trychar!(ethkey::crypto::ecies::decrypt(&sk, &DEFAULT_MAC, dsh.as_ref()));
        let sc = trychar!(Secret::from_unsafe_slice(dec.as_ref()));
        std::mem::forget(sh);
        shadows.push(sc);
    }
    let dec = trychar!(decrypt_document_with_shadow(ds, cp, shadows, dd));
    let ded = hex::encode(dec);
    let res = trychar!(CString::new(ded));
    let r = res.as_ptr();
    std::mem::forget(res);
    std::mem::forget(secret);
    std::mem::forget(decrypted_secret);
    std::mem::forget(common_point);
    std::mem::forget(data);
    std::mem::forget(decrypt_shadows);
    r
}

#[no_mangle]
pub unsafe extern "C" fn ss_decrypt(key: *const c_char, data: *const c_char) -> *const c_char {
    let k_str = trychar!(CStr::from_ptr(key).to_str());
    let ky = trychar!(hex::decode(k_str));

    let dt_str = trychar!(CStr::from_ptr(data).to_str());
    let dd = trychar!(hex::decode(dt_str));
    let dec = trychar!(decrypt_document(ky, dd));
    let ded = hex::encode(dec);
    let res = trychar!(CString::new(ded));
    let r = res.as_ptr();
    std::mem::forget(res);
    std::mem::forget(key);
    std::mem::forget(data);
    r
}

#[no_mangle]
pub unsafe extern "C" fn ss_decrypt_key(secret: *const c_char, decrypted_secret: *const c_char, common_point: *const c_char, decrypt_shadows: *const *const c_char, shadow_len : usize) -> *const c_char {
    let s_str = trychar!(CStr::from_ptr(secret).to_str());
    let sk = trychar!(Secret::from_str(s_str));

    let d_str = trychar!(CStr::from_ptr(decrypted_secret).to_str());
    let ds = trychar!(H512::from_str(d_str));

    let c_str = trychar!(CStr::from_ptr(common_point).to_str());
    let cp = trychar!(H512::from_str(c_str));
    
    let mut shadows = Vec::new();
    let len = trychar!(isize::try_from(shadow_len));
    for i in 0 ..len {
        let sh: *const c_char = *(decrypt_shadows.offset(i));
        let sh_str = trychar!(CStr::from_ptr(sh).to_str());
        let dsh = trychar!(hex::decode(sh_str));
        let dec = trychar!(ethkey::crypto::ecies::decrypt(&sk, &DEFAULT_MAC, dsh.as_ref()));
        let sc = trychar!(Secret::from_unsafe_slice(dec.as_ref()));
        std::mem::forget(sh);
        shadows.push(sc);
    }
    
    let dec = trychar!(decrypt_with_shadow_coefficients(ds, cp, shadows));
    let ded = hex::encode(dec);
    let res = trychar!(CString::new(ded));
    let r = res.as_ptr();
    std::mem::forget(res);
    std::mem::forget(secret);
    std::mem::forget(decrypted_secret);
    std::mem::forget(common_point);
    std::mem::forget(decrypt_shadows);
    r
}
