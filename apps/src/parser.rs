/*
Verification of the signature
Verification of the validity period
Checking the revocation status
Verification of trust (certificate path)

*/


//use bcder::{decode::Source, OctetString};
#[allow(dead_code)]
use bcder::{Oid, Tag, Mode};
use bcder::decode::{self, Constructed, DecodeError};
use std::fs::File;
use std::io::Read;

use chrono::{NaiveDateTime, TimeZone, Utc};
//use std::time::{SystemTime, UNIX_EPOCH};

//use chrono::{NaiveDateTime, TimeZone, Utc};
//use ring::signature::{self, UnparsedPublicKey};

pub struct Pkcs7 {
    pub content_type: Oid,
    pub content: SignedData,
}

pub struct SignedData {
    pub version: u8,
    pub digest_algorithms: Vec<AlgorithmIdentifier>,
    pub content_info: ContentInfo,
    pub certs: Vec<Certificate>,
    pub crls: Vec<u8>,
    pub signer_infos: Vec<SignerInfo>, // Multiple SignerInfo structures
}

pub struct SignerInfo {
    pub version: u8,
    pub issuer_and_serial_number: IssuerAndSerialNumber,
    pub digest_algorithm: AlgorithmIdentifier,
    pub authenticated_attributes: Option<AuthenticatedAttributes>, // Optional field
    pub digest_encryption_algorithm: AlgorithmIdentifier,
    pub encrypted_digest: Vec<u8>, // The actual signature (Encrypted digest)
    pub unauthenticated_attributes: Option<AuthenticatedAttributes>, // Optional field
}

pub struct IssuerAndSerialNumber {
    pub issuer: Name,  
    pub serial_number: String,
}
#[derive(Debug)]
pub struct Name {
    pub rdn_sequence: Vec<RelativeDistinguishedName>,
}

#[derive(Debug)]
pub struct RelativeDistinguishedName {
    pub attributes: Vec<AttributeTypeAndValue>,
}
#[derive(Debug)]
pub struct AttributeTypeAndValue {
    pub attribute_type: Oid,
    pub attribute_value: String,
}

pub struct AuthenticatedAttributes {
    pub auth_attr: Vec<u8>, 
}

pub struct Attribute {
    pub oid: Oid,           // Object Identifier of the attribute
    pub value: Vec<u8>,     // Byte array representing the attribute value
}

pub struct ContentInfo {
    pub content_type: Oid,
    pub content: Option<Vec<u8>>, // Encapsulated content
}

pub struct Certificate {
    pub tbs_certificate: TbsCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: Vec<u8>,
}

pub struct TbsCertificate {
    pub version: Option<u8>,
    pub serial_number: String,
    pub signature_algorithm: AlgorithmIdentifier,
    pub issuer: Vec<u8>,
    pub validity: Validity,
    pub subject: Vec<u8>,
    pub subject_public_key_info: SubjectPublicKeyInfo,
}

pub struct AlgorithmIdentifier {
    pub algorithm: Oid,
    pub parameters: Option<Vec<u8>>, // Optional parameters
}

pub struct Validity {
    pub not_before: u64,
    pub not_after: u64,
}

pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: Vec<u8>,
}

impl Pkcs7 {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let content_type = Oid::take_from(cons)?;
            let content = cons.take_constructed_if(Tag::CTX_0, |cons| {
                SignedData::take_from(cons)
            })?;
            Ok(Pkcs7 {
                content_type,
                content,
            })
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "Pkcs7 {{\n  content_type: {},\n  content: {}\n}}",
            self.content_type.to_string(),
            self.content.to_string(),
        )
    }
}

impl SignedData {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let version = cons.take_primitive_if(Tag::INTEGER, |content| content.to_u8())?;
            let digest_algorithms = cons.take_set(|cons| {
                let mut algorithms = Vec::new();
                while let Ok(algorithm) = AlgorithmIdentifier::take_from(cons) {
                    algorithms.push(algorithm);
                }
                Ok(algorithms)
            })?;
            let content_info = ContentInfo::take_from(cons)?;
            
            let certs = cons.take_constructed_if(Tag::CTX_0, |cons| {
                let mut certificates = Vec::new();
                while let Ok(cert) = Certificate::take_from(cons) {
                    certificates.push(cert);
                }
                Ok(certificates)
            })?;

            let signer_infos = cons.take_set(|cons| {
                let mut signers = Vec::new();
                while let Ok(signer) = SignerInfo::take_from(cons) {
                    signers.push(signer);
                }
                Ok(signers)
            })?;

            Ok(SignedData {
                version,
                digest_algorithms,
                content_info,
                certs,
                crls: Vec::new(), // Optional, can be parsed later
                signer_infos,
            })
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "SignedData {{\n  version: {},\n  content_info: {},\n  signer_infos: {}\n}}",
            self.version,
            self.content_info.to_string(),
            self.signer_infos.iter().map(|s| s.to_string()).collect::<String>(),
        )
    }
}

impl SignerInfo {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let version = cons.take_primitive_if(Tag::INTEGER, |content| content.to_u8())?;
            let issuer_and_serial_number = IssuerAndSerialNumber::take_from(cons)?;
            let digest_algorithm = AlgorithmIdentifier::take_from(cons)?;
            let authenticated_attributes = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
                AuthenticatedAttributes::take_from(cons)
            })?;
            let digest_encryption_algorithm = AlgorithmIdentifier::take_from(cons)?;

            let encrypted_digest = cons.take_value(|_,content| {
                /*let bytes = content.as_primitive()?.slice_all()?.to_vec();
                println!("[SignerInfo] Parsed encrypted digest (bytes): {:?}", bytes);
                Ok(bytes)*/
                let sign = content.as_primitive().map_err(|e|{
                    DecodeError::content(format!("Expected constructed content: {}", e), decode::Pos::default())
                })?;
                
                let sign_bytes = sign.slice_all()?.to_vec();
                //sign_bytes.drain(0..1);
                //let hex_bytes = hex::encode(&sign_bytes);
                _=sign.skip_all();
                println!("[SignerInfo] Parsed encrypted digest (bytes): {:?}", sign_bytes);
                Ok(sign_bytes)
            })?;

            println!("[SignerInfo] Successfully parsed encrypted digest.");
            let unauthenticated_attributes = cons.take_opt_constructed_if(Tag::CTX_1, |cons| {
                AuthenticatedAttributes::take_from(cons)
            })?;

            cons.skip_all().unwrap_or(());
            //let unauthenticated_attributes = None;
            Ok(SignerInfo {
                version,
                issuer_and_serial_number,
                digest_algorithm,
                authenticated_attributes,
                digest_encryption_algorithm,
                encrypted_digest,
                unauthenticated_attributes,
            })
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "SignerInfo {{\n  version: {},\n  digest_algorithm: {},\n  encrypted_digest: {:?}\n}}",
            self.version,
            self.digest_algorithm.to_string(),
            self.encrypted_digest,
        )
    }
}

impl IssuerAndSerialNumber {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let issuer = Name::take_from(cons)?;
            let serial_number = cons.take_primitive_if(Tag::INTEGER, |content| {
                let bytes = String::from_utf8(content.slice_all()?.to_vec()).expect("Failed to parse serial number");

                Ok(bytes)
            })?;
            
            Ok(IssuerAndSerialNumber {
                issuer,
                serial_number,
            })
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "IssuerAndSerialNumber {{\n  issuer: {:?},\n  serial_number: {:?}\n}}",
            self.issuer,
            self.serial_number,
        )
    }
}

impl Name {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        /*cons.take_sequence(|cons| {
            let mut rdn_sequence = Vec::new();
            println!("[Name] Start parsing Name sequence...");

            // Usa un approccio simile a quello usato per l'encrypted digest
            while let Ok(rdn) = RelativeDistinguishedName::take_from(cons) {
                println!("[Name] Parsed RelativeDistinguishedName: {:?}", rdn);
                rdn_sequence.push(rdn);
            }

            // Saltare i dati rimanenti
            let remaining = cons.capture_all()?;
            println!("[Name] Remaining data skipped: {:?}", remaining);
            Ok(Name { rdn_sequence })
        })*/
        /*cons.take_sequence(|cons| {
            let mut rdn_set = Vec::new();
            while let Ok(rdn) = RelativeDistinguishedName::take_from(cons) {
                println!("[Name] parsed rdn {:?}",rdn);
                rdn_set.push(rdn);
            }
            Ok( Name { rdn_sequence: rdn_set})
        })*/
        
        let _skipped = cons.capture_all()?;
        //println!("skipped in Name: {:?}",skipped);
        Ok( Name { rdn_sequence: Vec::new() } )
    }
}

impl RelativeDistinguishedName {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_set(|cons| {
            let mut attributes = Vec::new();
            println!("[RelativeDistinguishedName] Start parsing set...");

            while let Ok(attr) = AttributeTypeAndValue::take_from(cons) {
                println!("[RelativeDistinguishedName] Parsed AttributeTypeAndValue: {:?}", attr);
                attributes.push(attr);
            }

            // Saltare i dati rimanenti
            let remaining = cons.capture_all()?;
            println!("[RelativeDistinguishedName] Remaining data skipped: {:?}", remaining);
            Ok(RelativeDistinguishedName { attributes: attributes })
        })
    }
}

impl AttributeTypeAndValue {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let attribute_type = Oid::take_from(cons)?;
            println!("[AttributeTypeAndValue] Parsed attribute type: {:?}", attribute_type);

            /*let attribute_value = cons.take_value(|tag, content| {
                match tag {
                    Tag::PRINTABLE_STRING | Tag::UTF8_STRING => {
                        let bytes = content.as_primitive()?.slice_all()?.to_vec();
                        
                        let value_bytes = bytes;
                        println!("[AttributeTypeAndValue] Parsed attribute value (bytes): {:?}", value_bytes);

                        Ok(String::from_utf8(value_bytes).expect("Valid UTF-8 string"))
                    },
                    _ => Err(DecodeError::content("Unsupported attribute value type", decode::Pos::default())),
                }
            })?;*/
            let attribute_value = cons.take_value(|_,content| {
                let bytes = content.as_primitive()?.slice_all()?.to_vec();
                Ok(String::from_utf8(bytes).expect("Failed to parse attribute_value with type"))
            })?;

            // Saltare eventuali dati rimanenti
            let remaining = cons.capture_all()?;
            println!("[AttributeTypeAndValue] Remaining data skipped: {:?}", remaining);

            Ok(AttributeTypeAndValue {
                attribute_type,
                attribute_value,
            })
        })
    }
}


impl AuthenticatedAttributes {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
          
          let auth_attr_bytes = cons.capture_all()?.into_bytes().to_vec();
          Ok(AuthenticatedAttributes {auth_attr: auth_attr_bytes, })
    }

    pub fn to_string(&self) -> String {
        format!(
            "AuthenticatedAttributes {{\n  authenticated attributes: {:?}\n}}",
            self.auth_attr
        )
    }
}
/* 
impl Attribute {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let oid = Oid::take_from(cons)?;
            let value = cons.take_value_if(Tag::OCTET_STRING, |content| {
                let bytes = content.as_primitive()?.slice_all()?; 
                    Ok(bytes.to_vec()) 
                })?;
            Ok(Attribute { oid, value })
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "Attribute {{\n  oid: {},\n  value: {:?}\n}}",
            self.oid.to_string(),
            self.value
        )
    }
}*/

impl ContentInfo {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {

            let content_type = Oid::take_from(cons)?;
            let content = cons.take_opt_constructed_if(Tag::CTX_0, |content| {
                let bytes = content.take_primitive(|_, content| {
                    Ok(content.slice_all()?.to_vec())
                })?;
                Ok(bytes)
            })?;

            Ok(ContentInfo {
                content_type,
                content,
            })
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "ContentInfo {{\n  content_type: {},\n  content: {:?}\n}}",
            self.content_type.to_string(),
            self.content
        )
    }
}

impl Certificate {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {

            let tbs_certificate = TbsCertificate::take_from(cons)?;
            let signature_algorithm = AlgorithmIdentifier::take_from(cons)?;
            let signature_value = cons.take_value(|_,content| {
                let sign = content.as_primitive().map_err(|e|{
                    DecodeError::content(format!("Expected constructed content: {}", e), decode::Pos::default())
                })?;
                
                let mut sign_bytes = sign.slice_all()?.to_vec();
                sign_bytes.drain(0..1);
                //let hex_bytes = hex::encode(&sign_bytes);
                _=sign.skip_all();
                Ok(sign_bytes)
            })?;

            //println!("parsing certificate, sig : {:?}",signature_algorithm.to_string());
            Ok(Certificate {
                tbs_certificate,
                signature_algorithm,
                signature_value,
            })
            
        })
    }
    

    pub fn to_string(&self) -> String {
        format!(
            "Certificate {{\n  tbs_certificate: {},\n  signature_algorithm: {},\n  signature_value: {:?}\n}}",
            self.tbs_certificate.to_string(),
            self.signature_algorithm.to_string(),
            self.signature_value,
        )
    }

}

impl TbsCertificate {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            
            //version = optional field
            let version = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
                cons.take_primitive_if(Tag::INTEGER, |content| {
                    content.to_u8()
                })
                //println!("[tbs] version {:?}",version);
            })?;
            
            let serial_number = cons.take_primitive(|_,content| {
                let bytes = content.slice_all()?.to_vec();     
                let hex_bytes = hex::encode(&bytes); 
                _ = content.skip_all();
                //println!("[tbs] Serial Number Bytes: {:?}", serial_number);
                Ok(hex_bytes)
            })?;
            
            let signature_algorithm = AlgorithmIdentifier::take_from(cons)?;

            // only byte vec, for more detailed issuer, take it as a SEQUENCE and parse...
            let issuer = cons.take_value_if(Tag::SEQUENCE, |content| {
                let constructed_content = content.as_constructed().map_err(|e|{
                    DecodeError::content(format!("Expected constructed content: {}", e), decode::Pos::default())
                })?;
                
                let issuer_bytes = constructed_content.capture_all()?;
                let issuer_vec = issuer_bytes.to_vec();

                Ok(issuer_vec)
            })?;

            //asn1 format YYMMDDHHMMSSZ
            let validity = Validity::take_from(cons)?;

            //same as issuer
            let subject = cons.take_value_if(Tag::SEQUENCE, |content| {
                let constructed_content = content.as_constructed().map_err(|e|{
                    DecodeError::content(format!("Expected constructed content: {}", e), decode::Pos::default())
                })?;
                
                let issuer_bytes = constructed_content.capture_all()?;
                let subject_vec = issuer_bytes.to_vec();
                //println!("sub {:?}",subject_vec);
                Ok(subject_vec)
            })?;

            let subject_public_key_info = SubjectPublicKeyInfo::take_from(cons)?;

            _ = cons.skip_all();
            
            Ok(TbsCertificate {
                version,
                serial_number,
                signature_algorithm,
                issuer,
                validity,
                subject,
                subject_public_key_info,
            })
        })
    }
    pub fn to_string(&self) -> String {
        format!(
            "TbsCertificate {{\n    version: {:?},\n    serial_number: {:?},\n    signature_algorithm: {},\n    issuer: {:?},\n    validity: {},\n    subject: {:?},\n    subject_public_key_info: {}\n  }}",
            self.version,
            self.serial_number,
            self.signature_algorithm.to_string(),
            self.issuer,
            self.validity.to_string(),
            self.subject,
            self.subject_public_key_info.to_string()
        )
    }
  

}

impl AlgorithmIdentifier {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {

            let algorithm = Oid::take_from(cons)?;
            let parameters = None; //not needed
            _= cons.skip_all();
             
            Ok(AlgorithmIdentifier {
                algorithm,
                parameters,
            })
        })
    }
    pub fn to_string(&self) -> String {
        format!(
            "AlgorithmIdentifier {{\n    algorithm: {},\n    parameters: {:?}\n  }}",
            self.algorithm.to_string(),
            self.parameters
        )
    }
}

impl Validity {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {

            let not_before_str = cons.take_primitive(|_, content| {
                let bytes = content.slice_all()?;
                let time_str = String::from_utf8(bytes.to_vec()).map_err(|_| {
                    DecodeError::content("Invalid UTF-8 sequence", decode::Pos::default())
                })?;
                _ = content.skip_all();
                Ok(time_str)
            })?;

            let not_after_str = cons.take_primitive(|_, content| {
                let bytes = content.slice_all()?;
                let time_str = String::from_utf8(bytes.to_vec()).map_err(|_| {
                    DecodeError::content("Invalid UTF-8 sequence", decode::Pos::default())
                })?;
                _ = content.skip_all();
                Ok(time_str)
            })?;

            // converts string into UNIX epoch time
            let not_before = Validity::parse_asn1_to_timestamp(&not_before_str)
                .map_err(|_| DecodeError::content("Failed to parse not_before timestamp", decode::Pos::default()))?;
            let not_after = Validity::parse_asn1_to_timestamp(&not_after_str)
                .map_err(|_| DecodeError::content("Failed to parse not_after timestamp", decode::Pos::default()))?;

            Ok(Validity {
                not_before,
                not_after,
            })
        })
    }

    fn parse_asn1_to_timestamp(date_str: &str) -> Result<u64, DecodeError<std::string::FromUtf8Error>> {
        let naive_time = NaiveDateTime::parse_from_str(date_str, "%y%m%d%H%M%SZ")
            .map_err(|_| DecodeError::content("Invalid date format", decode::Pos::default()))?;
        
        let timestamp = Utc.from_utc_datetime(&naive_time).timestamp() as u64;

        Ok(timestamp)
    }

    pub fn to_string(&self) -> String {
        format!(
            "Validity {{\n    not_before: {},\n    not_after: {}\n  }}",
            self.not_before,
            self.not_after
        )
    }
}

impl SubjectPublicKeyInfo {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            
            let algorithm = AlgorithmIdentifier::take_from(cons)?;

            let subject_public_key = cons.take_primitive(|_, content| {
                let mut key_bytes = content.slice_all()?.to_vec();
                _= content.skip_all();

                //remove first 9 -> Tag, sequence, ecc; last 5 -> exp
                if key_bytes.len() > 14 {
                    key_bytes.drain(0..9);
                    key_bytes.truncate(key_bytes.len()-5); //exp
                }
                else {
                    println!("Failed to load pub Key");
                    }
                
                Ok(key_bytes)
                //let hex_bytes = hex::encode(&key_bytes);
                //Ok(hex_bytes)
            })?;
            _ = cons.skip_all();
            
            //println!("subpubkey {:?}", subject_public_key);

            Ok(SubjectPublicKeyInfo {
                algorithm,
                subject_public_key,
            })
        })
    }  
    pub fn to_string(&self) -> String {
        format!(
            "SubjectPublicKeyInfo {{\n    algorithm: {},\n    subject_public_key: {:?}\n  }}",
            self.algorithm.to_string(),
            self.subject_public_key
        )
    }     
}

/* load single x509 file

fn load_certificate(path: &str) -> Result<Certificate, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let pem = pem::parse(buffer)?;
    let bytes = pem.contents();

    let cert = Constructed::decode(bytes, Mode::Der, |constructed| {
        Certificate::take_from(constructed)
    }).map_err(|err| {
        eprintln!("Error decoding certificate: {:?}", err);
        Box::new(err) as Box<dyn std::error::Error>
    })?;
    
    Ok(cert)/* 
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let cert = X509::from_der(&buffer)?;
    Ok(cert)*/
}
*/

pub fn load_pkcs7(path: &str) -> Result<Pkcs7, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let pem = pem::parse(buffer)?;
    let bytes = pem.contents();

    let pkcs7 = Constructed::decode(bytes, Mode::Der, |constructed| {
        Pkcs7::take_from(constructed)
    }).map_err(|err| {
        eprintln!("Error decoding PKCS#7: {:?}", err);
        Box::new(err) as Box<dyn std::error::Error>
    })?;

    Ok(pkcs7)
}


/*
    problema

*/
/*fn main() {
    match load_pkcs7("../sdoc.p7b") {
        Ok(pkcs7) => {
            println!("PKCS#7 file loaded successfully!");
            println!("{:?}",pkcs7.content.certs[0].signature_value);
            println!("not after{:?}",pkcs7.content.certs[0].tbs_certificate.validity.not_after);
            //let a = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            //println!("now {}", a)

        },
        Err(e) => println!("Failed to load PKCS#7 file: {}", e),
    }
}*/
    


