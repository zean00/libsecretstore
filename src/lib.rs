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

#[repr(C)]
pub struct DocumentKey {
	/// Common encryption point. Pass this to Secret Store 'Document key storing session'
	pub common_point: *const c_char,
	/// Encrypted point. Pass this to Secret Store 'Document key storing session'.
	pub encrypted_point: *const c_char,
	/// Document key itself, encrypted with passed account public. Pass this to 'secretstore_encrypt'.
	pub encrypted_key: *const c_char,
}

#[no_mangle]
pub unsafe extern "C" fn get_document_key(secret: *const c_char, public: *const c_char) -> *const DocumentKey {  
    let s_str = CStr::from_ptr(secret).to_str().unwrap();
    let sk = Secret::from_str(s_str).unwrap();
    let p_str = CStr::from_ptr(public).to_str().unwrap();
    let pk = H512::from_str(p_str).unwrap();
    let kp = KeyPair::from_secret(sk).unwrap();
    let eset = generate_document_key(*kp.public(), pk).unwrap();
    let cp = hex::encode(eset.common_point);
    let cpres = CString::new(cp).unwrap();
    //let cpres = CStr::from_bytes_with_nul_unchecked(&cp.as_ref());
    let cpr = cpres.as_ptr();
    std::mem::forget(cpres);

    let ep = hex::encode(eset.encrypted_point);
    let epres = CString::new(ep).unwrap();
    //let epres = CStr::from_bytes_with_nul_unchecked(&ep.as_ref());
    let epr = epres.as_ptr();
    std::mem::forget(epres);
    

    let ek = hex::encode(eset.encrypted_key);
    let ekres = CString::new(ek).unwrap();
    //let ekres = CStr::from_bytes_with_nul_unchecked(&ek.as_bytes());
    let ekr = ekres.as_ptr();
    std::mem::forget(ekres);
    
    Box::into_raw(Box::new(DocumentKey {
		common_point: cpr,
		encrypted_point: epr,
		encrypted_key: ekr,
	}))
}

#[no_mangle]
pub unsafe extern "C" fn sign_hash(secret: *const c_char, hash: *const c_char) -> *const c_char { 
    let s_str = CStr::from_ptr(secret).to_str().unwrap();
    let sk = Secret::from_str(s_str).unwrap();

    let h_str = CStr::from_ptr(hash).to_str().unwrap();
    let hs = H256::from_str(h_str).unwrap();
    let sig = sign(&sk, &hs).unwrap();
    
    let sg = format!("{}", sig);
    //let sg = hex::encode(sig.to_vec());
    //let res = CStr::from_bytes_with_nul(&sg.as_bytes()).unwrap();
    let res = CString::new(sg).unwrap();
    let r = res.as_ptr();
    std::mem::forget(res);
    r
}

#[no_mangle]
pub unsafe extern "C" fn encrypt(secret: *const c_char, key: *const c_char, data: *const c_char) -> *const c_char {
    let s_str = CStr::from_ptr(secret).to_str().unwrap();
    let sk = Secret::from_str(s_str).unwrap();

    let k_str = CStr::from_ptr(key).to_str().unwrap();
    let key = ethkey::crypto::ecies::decrypt(&sk, &DEFAULT_MAC, hex::decode(k_str).unwrap().as_ref()).unwrap();

    let d_str = CStr::from_ptr(data).to_str().unwrap();
    let dd = String::from_str(d_str).unwrap();

    let enc = encrypt_document(key, dd.into_bytes()).unwrap();
    let ek = hex::encode(enc);
    let res = CString::new(ek).unwrap();
    let r = res.as_ptr();
    std::mem::forget(res);
    r
}

#[no_mangle]
pub unsafe extern "C" fn decrypt_shadow(secret: *const c_char, decrypted_secret: *const c_char, common_point: *const c_char, decrypt_shadows: *const *const c_char, shadow_len : usize, data: *const c_char) -> *const c_char {
    let s_str = CStr::from_ptr(secret).to_str().unwrap();
    let sk = Secret::from_str(s_str).unwrap();

    let d_str = CStr::from_ptr(decrypted_secret).to_str().unwrap();
    let ds = H512::from_str(d_str).unwrap();

    let c_str = CStr::from_ptr(common_point).to_str().unwrap();
    let cp = H512::from_str(c_str).unwrap();

    let dt_str = CStr::from_ptr(data).to_str().unwrap();

    let dd = hex::decode(dt_str).unwrap();
    let mut shadows = Vec::new();
    let len = isize::try_from(shadow_len).unwrap();
    for i in 0 ..len {
        let sh: *const c_char = *(decrypt_shadows.offset(i));
        let sh_str = CStr::from_ptr(sh).to_str().unwrap();
        let dec = ethkey::crypto::ecies::decrypt(&sk, &DEFAULT_MAC, hex::decode(sh_str).unwrap().as_ref()).unwrap();
        shadows.push(Secret::from_unsafe_slice(dec.as_ref()).unwrap());
    }
    let dec = decrypt_document_with_shadow(ds, cp, shadows, dd);
    let ded = hex::encode(dec.unwrap());
    let res = CString::new(ded).unwrap();
    let r = res.as_ptr();
    std::mem::forget(res);
    r
}

#[no_mangle]
pub unsafe extern "C" fn decrypt(key: *const c_char, data: *const c_char) -> *const c_char {
    let k_str = CStr::from_ptr(key).to_str().unwrap();
    let ky = hex::decode(k_str).unwrap();

    let dt_str = CStr::from_ptr(data).to_str().unwrap();
    let dd = hex::decode(dt_str).unwrap();
    let dec = decrypt_document(ky, dd).unwrap();
    let ded = hex::encode(dec);
    let res = CString::new(ded).unwrap();
    let r = res.as_ptr();
    std::mem::forget(res);
    r
}

#[no_mangle]
pub unsafe extern "C" fn decrypt_key(secret: *const c_char, decrypted_secret: *const c_char, common_point: *const c_char, decrypt_shadows: *const *const c_char, shadow_len : usize) -> *const c_char {
    let s_str = CStr::from_ptr(secret).to_str().unwrap();
    let sk = Secret::from_str(s_str).unwrap();

    let d_str = CStr::from_ptr(decrypted_secret).to_str().unwrap();
    let ds = H512::from_str(d_str).unwrap();

    let c_str = CStr::from_ptr(common_point).to_str().unwrap();
    let cp = H512::from_str(c_str).unwrap();
    
    let mut shadows = Vec::new();
    let len = isize::try_from(shadow_len).unwrap();
    for i in 0 ..len {
        let sh: *const c_char = *(decrypt_shadows.offset(i));
        let sh_str = CStr::from_ptr(sh).to_str().unwrap();
        let dec = ethkey::crypto::ecies::decrypt(&sk, &DEFAULT_MAC, hex::decode(sh_str).unwrap().as_ref()).unwrap();
        shadows.push(Secret::from_unsafe_slice(dec.as_ref()).unwrap());
    }
    
    let dec = decrypt_with_shadow_coefficients(ds, cp, shadows).unwrap();
    let ded = hex::encode(dec);
    let res = CString::new(ded).unwrap();
    let r = res.as_ptr();
    std::mem::forget(res);
    r
}
