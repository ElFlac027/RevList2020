#![allow(dead_code, unused)]
#![allow(non_snake_case)]

use std::str::FromStr;

use identity_core::common::Object;
use identity_core::common::Url;
use identity_core::common::Value;
use identity_did::did::DIDUrl;
use identity_did::did::DID;

use identity_credential::credential::Status;
use identity_credential::error::Error;
use identity_credential::error::Result;



//Information used to determine the current status of a [`Credential`][identity_credential::credential::Credential].
#[derive(Clone, Debug, PartialEq)]
pub struct RevocationList2020Status(Status);



impl RevocationList2020Status 
{
  const INDEX_PROPERTY_NAME: &'static str = "revocationListIndex";
  
  
  //The type name of the revocation list.
  pub const TYPE: &'static str = "RevocationList2020";

  //Creates a new `RevocationList2020Status`
  pub fn new<D: DID>(id: DIDUrl<D>, index: u32, urlLista: &str) -> Self 
  {
    let mut object = Object::new();
    object.insert(Self::INDEX_PROPERTY_NAME.to_owned(), Value::String(index.to_string()));
	  object.insert("revocationListCredential".to_string(), Value::String(urlLista.to_string()));
	
	
    RevocationList2020Status(Status::new_with_properties(
      Url::from(id),
      Self::TYPE.to_owned(),
      object,
    ))
  }

  //Returns the [`DIDUrl`] of the revlist status.
  pub fn id<D: DID>(&self) -> Result<DIDUrl<D>> 
  {
    DIDUrl::parse(self.0.id.as_str())
      .map_err(|err| Error::InvalidStatus(format!("invalid DID Url '{}': {:?}", self.0.id, err)))
  }




  //Returns the index of the credential in the issuer's revocation list if it can be decoded.
  pub fn index(&self) -> Result<u32> 
  {
    if let Some(Value::String(index)) = self.0.properties.get(Self::INDEX_PROPERTY_NAME) 
	{
      u32::from_str(index).map_err(|err| 
	  {
        Error::InvalidStatus(format!(
          "expected {} to be an unsigned 32-bit integer: {}",
          Self::INDEX_PROPERTY_NAME,
          err
        ))
      })
    } 
	else 
	{
      Err(Error::InvalidStatus(format!(
        "expected {} to be an unsigned 32-bit integer expressed as a string",
        Self::INDEX_PROPERTY_NAME
      )))
    }
  }
}



impl TryFrom<Status> for RevocationList2020Status 
{
  type Error = Error;

  fn try_from(status: Status) -> Result<Self> 
  {
    if status.type_ != Self::TYPE 
	{
      Err(Error::InvalidStatus(format!(
        "expected type '{}', got '{}'",
        Self::TYPE,
        status.type_
      )))
    } 
	else if !status.properties.contains_key(Self::INDEX_PROPERTY_NAME) 
	{
      Err(Error::InvalidStatus(format!(
        "missing required property '{}'",
        Self::INDEX_PROPERTY_NAME
      )))
    }
	else if !status.properties.contains_key("revocationListCredential") 
	{
      Err(Error::InvalidStatus(format!(
        "missing required property '{}'",
        "revocationListCredential"
      )))
    } 	
	else 
	{
      Ok(Self(status))
    }
  }
}

impl From<RevocationList2020Status> for Status 
{
  fn from(status: RevocationList2020Status) -> Self 
  {
    status.0
  }
}