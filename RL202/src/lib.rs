#![allow(dead_code, unused)]
#![allow(non_snake_case)]

pub mod RevocationList2020Status;

use RevocationList2020Status::*;

use base64::{decode_config, encode_config, STANDARD};
use std::fmt::{Display, Formatter};
use std::io::Write;
use std::io::Read;
use std::io::prelude::*;
use serde_derive::{Deserialize, Serialize};
use std::vec::Vec;
use std::str::FromStr;

use dataurl::DataUrl;
use flate2::write::ZlibDecoder as OtherZlibDecoder;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use identity_core::common::Url;
use identity_core::utils::Base;
use identity_core::utils::BaseEncoding;

use identity_did::did::DID;
use identity_did::error::Error;
use identity_did::error::Result;
use identity_did::service::Service;
use identity_did::service::ServiceEndpoint;



//Costanti tipo
pub const REVOCATION_LIST_2020_TYPE: &str = "RevocationList2020";
const REVOCATION_LIST_2020_STATUS_TYPE: &str = "RevocationList2020Status";

//Minimum bitstring size is 16kb
const MIN_BITSTRING_SIZE_KN: usize = 16;

//Maximum bistsring size is 128kb
const MAX_BITSTRING_SIZE_KB: usize = 128;




//CredentialError

#[derive(Debug)]
pub struct CredentialError 
{
    message: String,
}

impl CredentialError 
{
    pub fn new(msg: &str) -> Self 
	{
        CredentialError 
		{
            message: String::from(msg),
        }
    }
}

impl Display for CredentialError 
{
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        // Write strictly the first element into the supplied output
        // stream: `f`. Returns `fmt::Result` which indicates whether the
        // operation succeeded or failed. Note that `write!` uses syntax which
        // is very similar to `println!`.
        write!(f, "{}", self.message)
    }
}




//RevocationStatus

#[derive(Debug, PartialEq)]
pub enum RevocationStatus 
{
    Revoke,
    Reset,
}








//A revocation list for managing credential revocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationList2020 
{
    #[serde(rename = "id")]
    id: String,
	
    #[serde(rename = "type")]
    typ: String,
    
	#[serde(rename = "encodedList")]
    encoded_list: String,
    
	#[serde(rename = "bitSet")]
    bit_set: Vec<u8>,
}


//Implementazione totale della lista
impl RevocationList2020 
{
    //The name of the service type
    pub const TYPE: &'static str = "RevocationList2020";

    pub fn get_encList(&self) -> String
    {
        self.encoded_list.clone()
    }

  
    fn pack(data: &Vec<u8>) -> Result<String, CredentialError> 
	{
        //compress the data
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
		
        e.write_all(data).map_err(|e| CredentialError::new(&e.to_string()))?;
		
        let compressed = e.finish().map_err(|e| CredentialError::new(&e.to_string()))?;
		
        //encode the data
        Ok(encode_config(&compressed, STANDARD))
    }


    fn unpack(data: &String) -> Result<Vec<u8>, CredentialError> 
	{
        let bin = decode_config(&data, STANDARD).map_err(|e| CredentialError::new(&e.to_string()))?;
        let mut d = ZlibDecoder::new(&*bin);
        let mut buf = Vec::new();
        d.read_to_end(&mut buf).map_err(|e| CredentialError::new(&e.to_string()))?;
        Ok(buf)
    }


    fn check_bounds(&self, index: u64) -> Result<(), CredentialError> 
	{
        match index 
		{
            i if (i as usize) >= self.capacity() => Err(CredentialError::new(&format!(
                "max indexable element is {}, provided index {} is out of range",
                self.capacity(),
                i,
            ))),
            _ => Ok(()),
        }
    }
	
	
	//Returns numero di entry/bit disponibili, 1024 x 16 x 8 (bit per cella)
    pub fn capacity(&self) -> usize 
	{
        self.bit_set.len() * 8
    }

    //Size returns the size of the bitset int kb
    pub fn size(&self) -> usize 
	{
        return self.bit_set.len() / 1024;
    }
	


    // Constructs a new empty [`RevocationList2020`].
    pub fn new(id: &str, size: usize) -> Result<Self, CredentialError> 
	{
        if size < MIN_BITSTRING_SIZE_KN 
		{
            return Err(CredentialError::new(&format!(
                "Minimum credential size is {}, got {}",
                MIN_BITSTRING_SIZE_KN, size
            )));
        }
		
        if size > MAX_BITSTRING_SIZE_KB 
		{
            return Err(CredentialError::new(&format!(
                "Maximum credential size is {}, got {}",
                MIN_BITSTRING_SIZE_KN, size
            )));
        }
		
        if id.trim().is_empty() 
		{
            return Err(CredentialError::new("Revocation list id cannot be empty"));
        }
		
		
        //initialize the bitset
        let bs = vec![0; size * 1024];
        let el = Self::pack(&bs)?;

        Ok(RevocationList2020 
		    {
            id: String::from(id),
            typ: String::from(REVOCATION_LIST_2020_TYPE),
            encoded_list: el,
            bit_set: bs,
            })
			
    }


    //Crea lista settando la encodedList
    pub fn new_withList(id: &str, encList: &String) -> Result<Self, CredentialError> 
	{
		let el = encList.clone();

        if id.trim().is_empty() 
		{
            return Err(CredentialError::new("Revocation list id cannot be empty"));
        }
		
		
        //initialize the bitset
        let bin = decode_config(&encList, STANDARD).map_err(|e| CredentialError::new(&e.to_string()))?;
        let mut d = ZlibDecoder::new(&*bin);
        let mut buf = Vec::new();
        d.read_to_end(&mut buf).map_err(|e| CredentialError::new(&e.to_string()))?;
        

        Ok(RevocationList2020 
		    {
            id: String::from(id),
            typ: String::from(REVOCATION_LIST_2020_TYPE),
            encoded_list: el,
            bit_set: buf,
            })
			
    }



    //Returns `true` if the credential at the given `index` is revoked.
    pub fn is_revoked(&self, i: u64) -> Result<bool, CredentialError> 
	{
        self.get(i).map(|x| match x 
			{
                RevocationStatus::Revoke => true,
                RevocationStatus::Reset => false,
            })
    }
	
	
	//Setta il bit a 1, revocato
	pub fn revoke(&mut self, index: u64) -> Result<(), CredentialError> 
	{
        self.update(RevocationStatus::Revoke, index)
    }
	
	
	//Resetta il bit a 0, ovvero non revocato
	pub fn reset(&mut self, index: u64) -> Result<(), CredentialError> 
	{
      self.update(RevocationStatus::Reset, index)
    }
	
	
	//Cambio un bit nella lista
	pub fn update(&mut self, action: RevocationStatus, index: u64) -> Result<(), CredentialError> 
	{
        self.check_bounds(index)?;

        let pos = (index / 8) as usize;
        let j = (index % 8) as u8;

        match action 
		{
            RevocationStatus::Revoke => self.bit_set[pos] |= 1 << j,
            RevocationStatus::Reset => self.bit_set[pos] &= !(1 << j),
        };
		
        self.encoded_list = Self::pack(&self.bit_set)?;
        Ok(())
    }


	//Ottengo lo status del bit in quella posizione
    pub fn get(&self, index: u64) -> Result<RevocationStatus, CredentialError> 
	{
        self.check_bounds(index)?;

        let pos = (index / 8) as usize;
        let j = (index % 8) as u8;

        match self.bit_set[pos] & (1 << j) 
		{
            0 => Ok(RevocationStatus::Reset),
            _ => Ok(RevocationStatus::Revoke),
        }
    }
	  

  
    //DESERIALIZZAZIONE
  
    //Deserializes a compressed [`RevocationList2020`] base64-encoded `data`.
    pub(crate) fn deserialize_compressed_base64<T>(data: &T) -> Result<Self>
    where
    T: AsRef<str> + ?Sized,
    {
        let decoded_data: Vec<u8> = BaseEncoding::decode(data, Base::Base64Url)
        .map_err(|e| Error::Base64DecodingError(data.as_ref().to_owned(), e))?;
        let decompressed_data: Vec<u8> = Self::decompress_zlib(decoded_data)?;
        Self::deserialize_slice(&decompressed_data)
    }

    //Deserializes [`RevocationList`] from a slice of bytes.
    fn deserialize_slice(data: &[u8]) -> Result<Self> 
    {
        let decoded : RevocationList2020 = bincode::deserialize(data).unwrap();
        Ok(decoded)
    }



    //SERIALIZZAZIONE


    //Serializes and compressess [`RevocationList`] as a base64-encoded `String`.
    //Qui avviene l'encoding
    pub(crate) fn serialize_compressed_base64(&self) -> Result<String> 
    {
        let serialized_data: Vec<u8> = self.serialize_vec()?;
        Self::compress_zlib(&serialized_data).map(|data| BaseEncoding::encode(&data, Base::Base64Url))
    }


    //Serializes a [`RevocationList`] as a vector of bytes.
    //Devo trasformare la lista in un vettore di bytes per poterla comprimere
    fn serialize_vec(&self) -> Result<Vec<u8>> 
    {
        let mut output: Vec<u8> = Vec::with_capacity(self.capacity());
        
        //Trasformazione struct in bytes
        output = bincode::serialize(self).unwrap();
        
        Ok(output)
    }



    //Algoritmi di compressione/decompressione e tryFrom per passare da service a RevocationList

    fn compress_zlib<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>> 
    {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input.as_ref()).map_err(Error::BitmapEncodingError)?;
        encoder.finish().map_err(Error::BitmapEncodingError)
    }

    fn decompress_zlib<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>> 
    {
        let mut writer = Vec::new();
        let mut decoder = OtherZlibDecoder::new(writer);
        decoder.write_all(input.as_ref()).map_err(Error::BitmapDecodingError)?;
        writer = decoder.finish().map_err(Error::BitmapDecodingError)?;
        Ok(writer)
    }
	
}

