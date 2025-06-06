// This file was autogenerated by some hot garbage in the `uniffi` crate.
// Trust me, you don't want to mess with it!


::uniffi::setup_scaffolding!("bbs_core");


/// Export info about the UDL while used to create us
/// See `uniffi_bindgen::macro_metadata` for how this is used.

// ditto for info about the UDL which spawned us.

const UNIFFI_META_CONST_UDL_BBS_CORE: ::uniffi::MetadataBuffer = ::uniffi::MetadataBuffer::from_code(::uniffi::metadata::codes::UDL_FILE)
    .concat_str("bbs_core")
    .concat_str("bbs_core")
    .concat_str("lib");

#[doc(hidden)]
#[no_mangle]
pub static UNIFFI_META_UDL_BBS_CORE: [u8; UNIFFI_META_CONST_UDL_BBS_CORE.size] = UNIFFI_META_CONST_UDL_BBS_CORE.into_array();

















// Record definitions, implemented as method-less structs, corresponding to `dictionary` objects.



#[::uniffi::udl_derive(Record)]
struct r#KeyPair {
    r#dpub_key_bytes: ::std::vec::Vec<u8>,
    r#priv_key_bytes: ::std::vec::Vec<u8>,
}



#[::uniffi::udl_derive(Record)]
struct r#ProofResult {
    r#nonce_bytes: ::std::vec::Vec<u8>,
    r#proof_request_bytes: ::std::vec::Vec<u8>,
    r#proof_bytes: ::std::vec::Vec<u8>,
}



#[::uniffi::udl_derive(Record)]
struct r#SignResult {
    r#pub_key_bytes: ::std::vec::Vec<u8>,
    r#signature: ::std::vec::Vec<u8>,
}


// Top level functions, corresponding to UDL `namespace` functions.// Object definitions, corresponding to UDL `interface` definitions.


#[::uniffi::udl_derive(Object)]
struct r#GenerateKeyPair { }
#[::uniffi::export_for_udl]
impl r#GenerateKeyPair {
    #[uniffi::constructor]
    pub fn r#new(
    ) -> ::std::sync::Arc<r#GenerateKeyPair>
    {
        unreachable!()
    }
}
#[::uniffi::export_for_udl]
impl r#GenerateKeyPair {
    pub fn r#generate_key_pair(
        &self,
    ) -> r#KeyPair
    {
        unreachable!()
    }
}




#[::uniffi::udl_derive(Object)]
struct r#GenerateProofRequest { }
#[::uniffi::export_for_udl]
impl r#GenerateProofRequest {
    #[uniffi::constructor]
    pub fn r#new(
        r#pub_key_bytes: ::std::vec::Vec<u8>,
        r#signature_bytes: ::std::vec::Vec<u8>,
        r#revealed_indices: std::vec::Vec<u64>,
        r#messages: std::vec::Vec<::std::string::String>,
    ) -> ::std::sync::Arc<r#GenerateProofRequest>
    {
        unreachable!()
    }
}
#[::uniffi::export_for_udl]
impl r#GenerateProofRequest {
    pub fn r#generate_proof(
        &self,
    ) -> r#ProofResult
    {
        unreachable!()
    }
}




#[::uniffi::udl_derive(Object)]
struct r#SignRequest { }
#[::uniffi::export_for_udl]
impl r#SignRequest {
    #[uniffi::constructor]
    pub fn r#new(
        r#messages: std::vec::Vec<::std::string::String>,
        r#dpub_key_bytes: ::std::vec::Vec<u8>,
        r#priv_key_bytes: ::std::vec::Vec<u8>,
    ) -> ::std::sync::Arc<r#SignRequest>
    {
        unreachable!()
    }
}
#[::uniffi::export_for_udl]
impl r#SignRequest {
    pub fn r#sign_messages(
        &self,
    ) -> r#SignResult
    {
        unreachable!()
    }
}




#[::uniffi::udl_derive(Object)]
struct r#VerifyRequest { }
#[::uniffi::export_for_udl]
impl r#VerifyRequest {
    #[uniffi::constructor]
    pub fn r#new(
        r#nonce_bytes: ::std::vec::Vec<u8>,
        r#proof_request_bytes: ::std::vec::Vec<u8>,
        r#proof_bytes: ::std::vec::Vec<u8>,
        r#disclosed_messages: std::vec::Vec<::std::string::String>,
        r#dpub_key_bytes: ::std::vec::Vec<u8>,
        r#total_message_count: u64,
    ) -> ::std::sync::Arc<r#VerifyRequest>
    {
        unreachable!()
    }
}
#[::uniffi::export_for_udl]
impl r#VerifyRequest {
    pub fn r#is_valid(
        &self,
    ) -> ::std::string::String
    {
        unreachable!()
    }
}




// Callback Interface definitions, corresponding to UDL `callback interface` definitions.


// External and Wrapped types
// Support for external types.

// Types with an external `FfiConverter`...


// We generate support for each Custom Type and the builtin type it uses.

// Export scaffolding checksums for UDL items

#[no_mangle]
#[doc(hidden)]
pub extern "C" fn r#uniffi_bbs_core_checksum_method_generatekeypair_generate_key_pair() -> u16 {
    45700
}
#[no_mangle]
#[doc(hidden)]
pub extern "C" fn r#uniffi_bbs_core_checksum_method_generateproofrequest_generate_proof() -> u16 {
    1809
}
#[no_mangle]
#[doc(hidden)]
pub extern "C" fn r#uniffi_bbs_core_checksum_method_signrequest_sign_messages() -> u16 {
    17085
}
#[no_mangle]
#[doc(hidden)]
pub extern "C" fn r#uniffi_bbs_core_checksum_method_verifyrequest_is_valid() -> u16 {
    44170
}
#[no_mangle]
#[doc(hidden)]
pub extern "C" fn r#uniffi_bbs_core_checksum_constructor_generatekeypair_new() -> u16 {
    21810
}
#[no_mangle]
#[doc(hidden)]
pub extern "C" fn r#uniffi_bbs_core_checksum_constructor_generateproofrequest_new() -> u16 {
    18432
}
#[no_mangle]
#[doc(hidden)]
pub extern "C" fn r#uniffi_bbs_core_checksum_constructor_signrequest_new() -> u16 {
    2132
}
#[no_mangle]
#[doc(hidden)]
pub extern "C" fn r#uniffi_bbs_core_checksum_constructor_verifyrequest_new() -> u16 {
    22124
}