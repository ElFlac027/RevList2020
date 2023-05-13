#![allow(dead_code, unused)]
#![allow(non_snake_case)]


use std::str;
use std::str::FromStr;
use std::path::PathBuf;

use identity_iota::account_storage::Stronghold;
use identity_iota::account_storage::Storage;

use iota_client::{Client as ClientDev, Result as ClientResult};
use bee_message::prelude::MessageId;
use bee_common::packable::Packable;

use identity_iota::client::Client;
use identity_iota::client::ExplorerUrl;
use identity_iota::client::ResolvedIotaDocument;
use identity_iota::client::Resolver;
use identity_iota::client::CredentialValidationOptions;
use identity_iota::client::CredentialValidator;
use identity_iota::client::FailFast;
use identity_iota::client::ValidationError;

use identity_iota::account::Account;
use identity_iota::account::AccountBuilder;
use identity_iota::account::Result;
use identity_iota::account::IdentitySetup;
use identity_iota::account::MethodContent;
use identity_iota::did::DID;
use identity_iota::iota_core::IotaDID;
use identity_iota::core::Value;
use identity_iota::core::Timestamp;
use identity_iota::core::Url;
use identity_iota::core::json;
use identity_iota::core::FromJson;
use identity_iota::core::ToJson;
use identity_iota::credential::Status;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::Subject;
use identity_iota::crypto::ProofOptions;

use RevocationList2020;
use RevocationList2020::RevocationList2020Status;


#[tokio::main]
async fn main() -> Result<()> 
{
  //Gestione DB
  let stronghold_path: PathBuf = "./stronghold_file.hold".into();
  let password: String = "password27".to_owned();
  let stronghold: Stronghold = Stronghold::new(&stronghold_path, password, None).await?;

  //Creo account handler per l'Identity dell'issuer
  let mut issuer: Account = Account::builder()
  .storage(stronghold)
  .load_identity(IotaDID::parse("did:iota:FGZTMJSQZoGJxE416TmFnEjCDRJWFE5uTmEMEm5vBypv")?)
  .await?;

  ////////////////////////////////////Creazione soggetti e status per le VC revocabili
  
  //Indice dei messaggi da pubblicare sulla Tangle
  let mut index_VC_list = "RL2020_MyList";
  
  
  //Subject 1: Alice
  let sub1: Subject = Subject::from_json_value(json!({
    "id": "did:iota:GYR6iDwMrNHDXRMZyKztFf2RQ14jzJC9u1iXTVKPdV9B",
    "name" : "Alice",
    "public_key": "zH8P9Nu9zpgZutEFeb2RC5VVFr3V4ZhWspYZx7SGP5TPa",
  }))?;


  //Subject 2: Bob
  let sub2: Subject = Subject::from_json_value(json!({
    "id": "did:iota:Cn3xod8v3Yk4WHFiKXxfVzVm5E7T2PWMzRrAWAmWps2",
    "name": "Bob",
    "public_key": "zGqGKuMEpAUhpqpJJoPx4e9xWxz4K5zjbyh5DKctk5NbA",
  }))?;


  //Subject 3: Mark
  let sub3: Subject = Subject::from_json_value(json!({
    "id": "did:iota:fHiyTrBiGHeszGBiWCXUpasMoY9oM1eqVgQRsH3ZKeW ",
    "name" : "Mark",
    "public_key": "zFvZEpKBebFi6yGH4NAtpTT7794row5TNqQPXMkhJQExY",
  }))?;
  

  //Status Alice
  let service_url = issuer.did().clone().to_url();
  let credential_index: u32 = 7;
  let status_A : Status = RevocationList2020Status::RevocationList2020Status::new(service_url, credential_index, "https://example.com/credentials/status/3").into();

  //Status Bob
  let service_url2 = issuer.did().clone().to_url();
  let credential_index2: u32 = 2500;
  let status_B : Status = RevocationList2020Status::RevocationList2020Status::new(service_url2, credential_index2, "https://example.com/credentials/status/3").into();

  //Status Mark
  let service_url3 = issuer.did().clone().to_url();
  let credential_index3: u32 = 100;
  let status_M : Status = RevocationList2020Status::RevocationList2020Status::new(service_url3, credential_index3, "https://example.com/credentials/status/3").into();


  ///////////////////////////////////////Creazione VC revocabili
  
  let mut credential_A: Credential = CredentialBuilder::default()
  .id(Url::parse("https://example.com/credentials/23894672394")?)
  .context(Url::parse("https://w3id.org/vc-revocation-list-2020/v1").unwrap())
  .issuer(Url::parse(issuer.did().clone().as_str())?)
  .subject(sub1)
  .status(status_A)
  .property("IndiceRL", Value::from(index_VC_list))
  .build()?;


  let mut credential_B: Credential = CredentialBuilder::default()
  .id(Url::parse("https://example.com/credentials/23894672394")?)
  .context(Url::parse("https://w3id.org/vc-revocation-list-2020/v1").unwrap())
  .issuer(Url::parse(issuer.did().clone().as_str())?)
  .subject(sub2)
  .status(status_B)
  .property("IndiceRL", Value::from(index_VC_list))
  .build()?;


  let mut credential_M: Credential = CredentialBuilder::default()
  .id(Url::parse("https://example.com/credentials/23894672394")?)
  .context(Url::parse("https://w3id.org/vc-revocation-list-2020/v1").unwrap())
  .issuer(Url::parse(issuer.did().clone().as_str())?)
  .subject(sub3)
  .status(status_M)
  .property("IndiceRL", Value::from(index_VC_list))
  .build()?;


  //Firma delle credenziali
  issuer
  .sign("#key-1", &mut credential_A, ProofOptions::default())
  .await?;

  issuer
  .sign("#key-1", &mut credential_B, ProofOptions::default())
  .await?;

  issuer
  .sign("#key-1", &mut credential_M, ProofOptions::default())
  .await?;




  ///////////////////////////////////////////////////////////////Generazione VC lista

  //Creo lista di dim minima 16kb
  let mut rl = RevocationList2020::RevocationList2020::new("https://example.com/credentials/status/3", 16).unwrap();
  let mut list_coded : String = rl.get_encList();


  //Creo soggetto per la VC lista
  let list_sub: Subject = Subject::from_json_value(json!({
      "id": issuer.document().id(),
      "encodedList": list_coded,
    }))?;

  
  //Creazione della VC lista
  let mut lista_VC: Credential = CredentialBuilder::default()
  .id(Url::parse("https://example.com/credentials/status/3")?)
  .context(Url::parse("https://w3id.org/vc-revocation-list-2020/v1").unwrap())
  .issuer(Url::parse(issuer.did().clone().as_str())?)
  .type_("RevocationList2020Credential")
  .subject(list_sub)
  .build()?;

  //Firma della credenziale lista
  issuer
  .sign("#key-1", &mut lista_VC, ProofOptions::default())
  .await?;
  
  ///////////////////////////////////Pubblicazione della RevocationList sulla Tangle

  //Creazione client
  let iota_cl = ClientDev::builder()
  .with_node("https://api.lb-0.h.chrysalis-devnet.iota.cafe")
  .unwrap()
  .finish()
  .await
  .unwrap();


  //Lista -> payload
  let string_list = String::from(lista_VC.to_string());
  let mut pl_credential : Vec<u8> = string_list.into_bytes();


  //Pubblicazione sulla Tangle
  let sent = iota_cl
    .message()
    .with_index(index_VC_list)
    .with_data(pl_credential)
    .finish()
    .await;


  ///////////////////////////////////////////////////////Revoca delle credenziali
  
  //Vettore credenziali da revocare
  let mut cred_arr : Vec<Credential> = vec![credential_A.clone(), credential_B.clone()];

  //Creazione nuova revocation list
  let mut new_rl = RevocationList2020::RevocationList2020::new("https://example.com/credentials/status/3", 16).unwrap();

  //Revoca delle credenziali
  for c in cred_arr
  {
    let r_index : String = c.clone().credential_status.unwrap().properties.get("revocationListIndex").unwrap().to_string();
    new_rl.revoke(r_index.replace("\"","").parse::<u64>().unwrap());
  }

  //////////////////////////////////////////////////////Creazione nuova VC lista
  
  let mut new_list_coded : String = new_rl.get_encList();

  //Ricreo soggetto
  let new_sub: Subject = Subject::from_json_value(json!({
    "id": issuer.document().id(),
    "encodedList": new_list_coded,
  }))?;


  //Creazione nuova VC lista
  let mut new_lista_VC: Credential = CredentialBuilder::default()
  .id(Url::parse("https://example.com/credentials/status/3")?)
  .context(Url::parse("https://w3id.org/vc-revocation-list-2020/v1").unwrap())
  .issuer(Url::parse(issuer.did().as_str())?)
  .type_("RevocationList2020Credential")
  .subject(new_sub)
  .build()?;

  //Firma
  issuer
  .sign("#key-1", &mut new_lista_VC, ProofOptions::default())
  .await?;


  ///////////////////////////////////Invio della nuova RevocationList sulla Tangle

  //VC -> payload
  let s_list = String::from(new_lista_VC.to_string());
  let mut new_credential : Vec<u8> = s_list.into_bytes();


  //Invio sulla Tangle
  let new_sent = iota_cl
    .message()
    .with_index(index_VC_list)
    .with_data(new_credential)
    .finish()
    .await;
  

  ////////////////// Esempio d'uso RevocationList: presuppongo che le credenziali revocabili siano in possesso dei rispettivi holder
  
  //1) Un client (Alice) condivide la sua VC con un server, il quale verifica se questa è ancora valida o è stata revocata, prima di connettersi

  //Avendo la credenziale, recupero lo IotaDocument dell'issuer (partendo dal suo DID)
  let issuer_did = credential_A.issuer.url().clone().into_string();
  let iota = Client::builder().build().await?;
  let resolved_doc = iota.read_document(&IotaDID::parse(issuer_did.clone())?).await.unwrap();
  let issuer_doc = resolved_doc.document;

  //Verifico la firma dell'issuer sulla credenziale
  CredentialValidator::verify_signature(
    &credential_A,
    std::slice::from_ref(issuer_doc.as_ref()),
    &CredentialValidationOptions::default().verifier_options,
    )
    .unwrap();
  
  //Recupero l'indice della VC, l'id della sua RevocationList e l'indice del messaggio contenente la RevocationList
  let index : String = credential_A.clone().credential_status.unwrap().properties.get("revocationListIndex").unwrap().to_string().replace("\"","");
  let id_list : String = credential_A.clone().credential_status.unwrap().properties.get("revocationListCredential").unwrap().to_string().replace("\"","");
  let indice_lista : String = credential_A.clone().properties.get("IndiceRL").unwrap().to_string().replace("\"","");

  //////////////////////////////////////// Recuperare la lista con la issuance date più recente

  //Ottengo vettore di MessageId con l'index passato
  let elenco_messaggi = iota_cl.get_message().index(index_VC_list).await.unwrap();
  let vettore_messaggi = elenco_messaggi.into_vec();

  let mut newest : Timestamp = Timestamp::parse("1970-01-01T00:00:00Z").unwrap();
  let mut latest_listID : MessageId = MessageId::null();

  //Ciclo allo scopo di trovare il MessageId corrispondente alla versione più recente della lista
  for msg_id in vettore_messaggi
  {
    let messaggio = iota_cl.get_message().data(&msg_id).await.unwrap();
    let payload = messaggio.payload().clone().unwrap().pack_new();
    let payload_stringa = String::from_utf8_lossy(&payload).to_string();
    let mut list_array : Vec<&str> = payload_stringa.split("{").collect();
    list_array.remove(0);
    let mut i = 0;
    let mut result = "{".to_string();
    while i < list_array.len()
    {
      result+= list_array[i];
      result+= "{";
      i+=1;
    }
    //Elimino ultima {
    result.pop();

    //Ottengo la Credential
    let mut credential_list : Credential = serde_json::from_str::<Credential>(&result).unwrap();

    //Recupero la issuance date e verifico se è più recente
    let mut issuance_date : Timestamp = credential_list.issuance_date;
    if issuance_date.gt(&newest)
    {
      newest = issuance_date;
      latest_listID = msg_id.clone();
    }
  }

  //Il messaggio corretto
  let mex = iota_cl.get_message().data(&latest_listID).await.unwrap();

  /////////////////////////// Ora posso recuperare la lista corretta

  //Metodo lossy a causa dei caratteri speciali nella parte del MessageId
  let pl = mex.payload().clone().unwrap().pack_new();
  let pl_stringa = String::from_utf8_lossy(&pl).to_string();

  //Conversione in Credential della credenziale lista
  let mut list_vec : Vec<&str> = pl_stringa.split("{").collect();
  list_vec.remove(0);
  let mut j = 0;
  let mut risultato = "{".to_string();
  while j < list_vec.len()
  {
    risultato+= list_vec[j];
    risultato+= "{";
    j+=1;
  }
    
  risultato.pop();
    
  let mut credential_lista : Credential = serde_json::from_str::<Credential>(&risultato).unwrap();



  ///////////////////////////////////////////////////////////Verifiche su quanto ricostruito

  //Verifica della firma sulla lista credenziale
  let id_client = Client::builder().build().await?;
  let mut issuer_document = id_client.read_document(&IotaDID::parse(issuer_did)?).await.unwrap().document;
  issuer_document.verify_data(&credential_lista, &CredentialValidationOptions::default().verifier_options).unwrap();

  //Recupero id della credenziale lista e lo confronto con quello della mia credenziale
  let lista_id = credential_lista.id.unwrap().into_string();
  if lista_id.ne(&id_list.clone().replace("\"","")) {
        panic!("ERRORE: ID liste differenti");
      }

  ///////////////////////////////////////////////////////////Infine costruisco oggetto RevocationList2020 e check revoca

  //Recupero della encodedList
  let sub = credential_lista.credential_subject.into_vec();
  let eL = sub[0].properties.get("encodedList").unwrap().to_string().replace("\"","");

  //Costruisco la RevocationList con la encodedList recuperata
  let mut rl = RevocationList2020::RevocationList2020::new_withList(&lista_id, &eL).unwrap();

  //Check se credenziale revocata
  if rl.is_revoked(index.parse::<u64>().unwrap()).unwrap() {
    println!("La credenziale è stata revocata, connessione negata!");
  }
  else {
    println!("Credenziale valida, connessione accettata");
  }


  Ok(())
}