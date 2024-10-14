/*
Verification of the signature
Verification of the validity period
Checking the revocation status
Verification of trust (certificate path)

*/


use bcder::decode::IntoSource;
use bcder::{Oid, Tag, Mode};
use bcder::decode::{self, Constructed, DecodeError};
use std::fs::File;
use std::io::Read;
use hex;
use chrono::{NaiveDateTime, TimeZone, Utc};

//use chrono::{NaiveDateTime, TimeZone, Utc};
//use ring::signature::{self, UnparsedPublicKey};
const ECDSA_OID_BYTES: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const ECDSA_SIGN_OID_BYTES: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04,0x03, 0x02];

const RSA_OID_BYTES: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

#[derive(Debug)]
pub struct Pkcs7 {
    pub content_type: Oid,
    pub content: SignedData,
    pub content_bytes: Vec<u8>,
}
#[derive(Debug)]
pub struct SignedData {
    pub version: u8,
    pub digest_algorithms: Vec<AlgorithmIdentifier>,
    pub content_info: ContentInfo,
    pub certs: Vec<Certificate>,
    pub crls: Vec<u8>,
    pub signer_infos: Vec<SignerInfo>, // Multiple SignerInfo structures
}
#[derive(Debug)]
pub struct ContentInfo {
    pub content_type: Oid,
    pub e_content: Option<Vec<u8>>, // Encapsulated content, present if doc sigend with -nodetach option
}
#[derive(Debug)]
pub struct SignerInfo {
    pub version: u8,
    pub signer_identifier: SignerIdentifier,
    //pub issuer_and_serial_number: IssuerAndSerialNumber,
    pub digest_algorithm: AlgorithmIdentifier,
    pub auth_attributes: Option<Vec<Attribute>>, // Optional field
    pub auth_bytes: Vec<u8>,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: Vec<u8>, // The actual signature (Encrypted digest)
    //pub unauthenticated_attributes: Option<AuthenticatedAttributes>, // Optional field
}
#[derive(Debug)]
pub struct SignerIdentifier {
    pub issuer: Name,
    pub serial_number: String, //hex
}
/*
#[derive(Debug)]
pub struct IssuerAndSerialNumber {
    pub issuer: Vec<RelativeDistinguishedName>,  
    pub serial_number: Vec<u8>,
}*/

#[derive(Debug)]
pub struct Name {
    pub rdn_sequence: Vec<RelativeDistinguishedName>,
}

#[derive(Debug)]
pub struct RelativeDistinguishedName {
    pub attribute: Attribute,
}
/*
#[derive(Debug)]
pub struct AuthenticatedAttributes {
    //pub auth_attr_bytes: Vec<u8>, 
    pub attributes: Vec<Attribute>,
}*/
#[derive(Debug)]
pub struct Attribute {
    pub oid: Oid,           
    pub value: Vec<u8>, 
}

#[derive(Debug)]

pub struct Certificate {
    pub tbs_certificate: TbsCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: Vec<u8>,
}
#[derive(Debug)]

pub struct TbsCertificate {
    pub tbs_bytes: Vec<u8>,
    pub version: Option<u8>,
    pub serial_number: String,
    pub signature_algorithm: AlgorithmIdentifier,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo,
}
#[derive(Debug)]

pub struct AlgorithmIdentifier {
    pub algorithm: Oid,
    pub parameters: Vec<u8>, // Optional parameters
}
#[derive(Debug)]

pub struct Validity {
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: PublicKey,
    //pub exp: Vec<u8>,
}
#[derive(Debug)]

pub enum PublicKey {
    Rsa {
        modulus: Vec<u8>,
        exponent: Vec<u8>,
    },
    Ecdsa {
        point: Vec<u8>,
    },
}


impl Pkcs7 {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        
        cons.take_sequence(|cons| {

            let content_type = Oid::take_from(cons)?;

            let content_captured = cons.capture_all()?;
            let mut content_bytes = content_captured.as_slice().to_vec();
            content_bytes.drain(0..4); //remove tag and lenght bytes

            let content_source = content_captured.into_source(); 

            let content = Constructed::decode(content_source, Mode::Ber, |cons|{
                let content_parsed = cons.take_constructed_if(Tag::CTX_0, |cons| {
                    SignedData::take_from(cons)
                })?;
                Ok(content_parsed)
            }).expect("failed to parse content");

            
            Ok(Pkcs7 {
                content_type,
                content,
                content_bytes,
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
            let signer_identifier = SignerIdentifier::take_from(cons)?;
            /*let issuer_and_serial_number = IssuerAndSerialNumber::take_from(cons)?;
            println!("signerInfo issSerial: {:?}",issuer_and_serial_number);*/
            
            let digest_algorithm = AlgorithmIdentifier::take_from(cons)?;
            
            /*let auth_captured = cons.capture_one()?;
            let mut auth_bytes = auth_captured.as_slice().to_vec();
            auth_bytes.drain(0..3); //remove implicit tag and lenght (A0,len,len)*/

            let auth_captured = cons.capture_one()?;
            let mut auth_bytes = auth_captured.as_slice().to_vec();
            
            //remove IMPLICIT TAG (A0), insert SET OF TAG (0x31)
            auth_bytes[0] = 0x31;

            let auth_source = auth_captured.into_source();

            let auth_attributes = Constructed::decode(auth_source, Mode::Ber, |cons|{
                let auth_attrs = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
                    let mut attributes = Vec::new();
                    while let Ok(attr) = Attribute::take_from(cons){
                        attributes.push(attr);
                    }
                    Ok(attributes)
                })?;
                Ok(auth_attrs)
            }).expect("failed to parse auth attributes");
            
            //println!("auth attr: {:?}",auth_attributes);

            let signature_algorithm = AlgorithmIdentifier::take_from(cons)?;

            let signature_captured = cons.capture_all()?;
            //let b = signature_captured.as_slice().to_vec();
            //println!("\nb {:?}\n sign algo: {:?}",b,signature_algorithm.algorithm.as_ref().bytes());
            let signature = if signature_algorithm.algorithm.as_ref() == RSA_OID_BYTES{
                let rsa_signature = cons.take_value(|_,content| {
                    let sign = content.as_primitive().map_err(|e|{
                        DecodeError::content(format!("Expected constructed content: {}", e), decode::Pos::default())
                    })?;
                    let sign_bytes = sign.slice_all()?.to_vec();
                    _=sign.skip_all();
                    Ok(sign_bytes)
                })?;
                _=cons.skip_all();
                rsa_signature
    
            } else if signature_algorithm.algorithm.as_ref() == ECDSA_SIGN_OID_BYTES {
                let sign_source = signature_captured.as_slice().into_source();            
                let signature = Constructed::decode(sign_source, Mode::Ber, |cons| {
                    cons.take_value(|_, content| {
                       
                       let signature_bytes = {
                        let primitive_content = content.as_primitive()?;
                        primitive_content.slice_all()?.to_vec()
                       };

                       _ = content.as_primitive()?.skip_all();

                        if signature_bytes.len() < 72 {
                            return Err(DecodeError::content("ECDSA signature too short!", decode::Pos::default()));
                        }
                        let mut r = signature_bytes[5..37].to_vec();

                        let mut s = signature_bytes[40..72].to_vec();

                        if r.len() < 32 {
                            let mut padded_r = vec![0u8; 32 - r.len()];
                            padded_r.extend_from_slice(&r);
                            r = padded_r;
                        } else if r.len() > 32 {
                            return Err(DecodeError::content("Key(r) too long", decode::Pos::default()));
                        }
                    
                        if s.len() < 32 {
                            let mut padded_s = vec![0u8; 32 - s.len()];
                            padded_s.extend_from_slice(&s);
                            s = padded_s;
                        } else if s.len() > 32 {
                            return Err(DecodeError::content("Key(s) too long", decode::Pos::default()));
                        }


                        //println!("\n\n-------------------------\nr {:?}\ns {:?} \n",r,s);
                        
                        //sec1 encoding
                        //let mut signature = vec![0x4];
                        //signature.extend(r);
                        let mut signature = r;
                        signature.extend(s);

                        //println!("\nsource: {:?}\n\nextracted ECDSA signature: [{:?},   len: {:?}\n",sign_source, signature, signature.len());

                        Ok(signature)
                    })
                }).expect("failed to parse ecdsa signature");
                
                _=cons.skip_all();
                signature
            }
            else {
                return Err(DecodeError::content("Unsupported signature algorithm", decode::Pos::default()));
            };
            
            /*let unauthenticated_attributes = cons.take_opt_constructed_if(Tag::CTX_1, |cons| {
                AuthenticatedAttributes::take_from(cons)
            })?;*/

            _=cons.skip_all();
            //let unauthenticated_attributes = None;
            Ok(SignerInfo {
                version,
                signer_identifier,
                digest_algorithm,
                auth_attributes,
                auth_bytes,
                signature_algorithm,
                signature,
                //unauthenticated_attributes,
            })
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "SignerInfo {{\n  version: {},\n  digest_algorithm: {},\n  encrypted_digest: {:?}\n}}",
            self.version,
            self.digest_algorithm.to_string(),
            self.signature,
        )
    }
}

impl SignerIdentifier {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {

        let signer_identifier = cons.take_sequence(|cons| {
            // Capture the issuer bytes as needed
            /*let issuer = cons.take_sequence(|cons|{
                let issuer_bytes = cons.capture_all()?.as_slice().to_vec();
                Ok(issuer_bytes)
            })?;*/

            let issuer = Name::take_from(cons)?;

            let serial_number = cons.take_primitive(|_, content| {
                let sn = content.slice_all()?.to_vec();
                _=content.skip_all();
                let sn_hex = hex::encode(&sn);
                Ok(sn_hex)
            })?;

            Ok(SignerIdentifier {
                issuer,
                serial_number,
            })
        })?;

        Ok(signer_identifier)
    }
}


impl Name {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
    
        //println!("name cons: {:?}\n",cons);
        let mut rdn_sequence = Vec::new();

        let name = cons.take_sequence(|cons|{
            while let Ok(rdn) = RelativeDistinguishedName::take_from(cons) {
                rdn_sequence.push(rdn);
            }
            
            Ok( Name { rdn_sequence })
        }).expect("failed to parse name");
        Ok(name)
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.rdn_sequence == other.rdn_sequence
    }
}

impl RelativeDistinguishedName {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        
        let attribute = cons.take_set(|cons|{
            let attr = cons.take_sequence(|cons|{
                let oid = Oid::take_from(cons)?;
                let value = cons.take_value(|_,content|{
                    let val = content.as_primitive()?.slice_all()?.to_vec();
                    _=content.as_primitive()?.skip_all();
                    Ok(val)
                })?;
                Ok( Attribute{ oid, value })
            })?;
            _=cons.skip_all();
            Ok(attr)
            
        })?;
        Ok( RelativeDistinguishedName{ attribute })

    }
}

impl PartialEq for RelativeDistinguishedName {
    fn eq(&self, other: &Self) -> bool {
        (self.attribute.oid == other.attribute.oid) &&
        (self.attribute.value == other.attribute.value)
    }
}
/*
impl IssuerAndSerialNumber {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        println!("PARSING issuer serial");

        cons.take_sequence(|cons| {
            let issuer = Name::take_from(cons)?;
            let serial_number = cons.take_primitive_if(Tag::INTEGER, |content| {
                let bytes = content.slice_all()?.to_vec();
                println!("issuer serial number: {:?}",bytes);
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
        println!("PARSING name");

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
        
        let skipped = cons.capture_all()?;
        //println!("skipped in Name: {:?}",skipped);
        Ok( Name { rdn_sequence: Vec::new() } )
    }
}

impl RelativeDistinguishedName {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {

        println!("PARSING rdn");

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
        println!("PARSING attrTypeValue");

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
*/
/* AUTH ATTR BONO
impl AuthenticatedAttributes {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        
        println!("PARSING auth attr");

        let auth_bytes = cons.capture_all()?.into_bytes();
        let auth_attr_bytes = auth_bytes.clone().to_vec();
        //println!("signed_attributes bytes: {:?}",auth_attr_bytes);

        let auth_source = auth_attr_bytes.into_source();

        //println!("auth source {:?}",auth_source.slice());
       /* let attributes = Constructed::decode(auth_source, Mode::Der, |cons|{

            println!("cons prima {:?}",cons);

            let auth_attributes_vec = cons.take_constructed(|_,cons|{

                let mut auth_attrs = Vec::new();
                println!("cons passato a Attribute {:?}",cons);
                
                while let Ok(attr) = Attribute::take_from(cons){
                    auth_attrs.push(attr);
                }
                Ok(auth_attrs)
            })?;

            Ok(auth_attributes_vec)
        }).expect("failed to parse auth attr values"); */


        Ok(AuthenticatedAttributes {
            auth_attr_bytes,
            attributes
         })
    }

    pub fn to_string(&self) -> String {
        format!(
            "AuthenticatedAttributes {{\n  authenticated attributes: {:?}\n}}",
            self.auth_attr_bytes
        )
    }
}*/


impl Attribute {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        //println!("cons: {:?}",cons.capture_all()?.as_slice());
        cons.take_sequence(|cons| {
            
            let oid = Oid::take_from(cons)?;
            //println!("parsed attr with OID {:?}",oid.as_ref().to_vec());
            
            //value = vec di bytes (AttributeValue senza i 2 byte di Tag)
            let value = cons.take_set(|cons|{
                let mut bytes_value = cons.capture_all()?.as_slice().to_vec();
                bytes_value.drain(0..2);
                //println!("bytes_value: {:?}\n",bytes_value);
                Ok(bytes_value)
                /*let mut attr_values = Vec::new();
                if let Ok(attr_value) = AttributeValue::take_from(cons){
                    attr_values.push(attr_value);
                }
                Ok(attr_values)*/ 
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
}


/* useless data for now, bytes are sufficient (only need the digest value)
impl AttributeValue {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
          
    }
}*/


impl ContentInfo {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {

            let content_type = Oid::take_from(cons)?;
            let e_content = cons.take_opt_constructed_if(Tag::CTX_0, |content| {
                let bytes = content.take_primitive(|_, content| {
                    let content_bytes = content.slice_all()?.to_vec();
                    _=content.skip_all();
                    Ok(content_bytes)
                })?;
                Ok(bytes)
            })?;
            //_=cons.skip_all();

            Ok(ContentInfo {
                content_type,
                e_content,
            })
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "ContentInfo {{\n  content_type: {},\n  content: {:?}\n}}",
            self.content_type.to_string(),
            self.e_content
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

        let tbs_captured = cons.capture_one()?;
        let tbs_bytes = tbs_captured.as_slice().to_vec();
        let tbs_source = tbs_captured.into_source();

        //let mut tbs_bytes: Vec<u8> = Vec::new();
        //let tbs_certificate = cons.take_sequence(|cons| {
        let tbs_certificate = Constructed::decode(tbs_source, Mode::Der, |cons|{  
            cons.take_sequence(|cons|{
                //version = optional field
                let version = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
                cons.take_primitive_if(Tag::INTEGER, |content| {
                    let v = content.to_u8()?;
                    //tbs_bytes.push(v);
                    Ok(v)                    
                })
                //println!("[tbs] version {:?}",version);
                })?;
            
                let serial_number = cons.take_primitive(|_,content| {
                let bytes = content.slice_all()?.to_vec();     
                let hex_bytes = hex::encode(&bytes); 
                _ = content.skip_all();
                Ok(hex_bytes)
                })?;
            
                let signature_algorithm = AlgorithmIdentifier::take_from(cons)?;
                let issuer = Name::take_from(cons)?;
                //asn1 format YYMMDDHHMMSSZ
                let validity = Validity::take_from(cons)?;
                let subject = Name::take_from(cons)?;
                let subject_public_key_info = SubjectPublicKeyInfo::take_from(cons)?;
                _ = cons.skip_all();
                
                Ok(TbsCertificate {
                    tbs_bytes,
                    version,
                    serial_number,
                    signature_algorithm,
                    issuer,
                    validity,
                    subject,
                    subject_public_key_info,
                })
            })
            
        }).expect("failed to parse tbs certificate");

        Ok(tbs_certificate)
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
            /*let parameters = cons.take_opt_primitive(|_,content|{
                let p = content.slice_all()?.to_vec();
                println!("p {:?}\n",p);
                Ok(p)
            })?;*/
            let parameters = cons.capture_all()?.to_vec();
            _=cons.skip_all();
            Ok(AlgorithmIdentifier {
                algorithm,
                parameters,
            })
        })
    }
    pub fn to_string(&self) -> String {
        format!(
            "AlgorithmIdentifier {{    algorithm: {},\n    parameters: {:?}\n  }}",
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
                    DecodeError::content("Invalid UTF-8 sequence", decode::Pos::default())})?;
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
                
                let key_bytes = content.slice_all()?;

                let pk = if algorithm.algorithm.as_ref() == RSA_OID_BYTES{
                    let key_source = key_bytes[1..].into_source();
                    //let  = key_bytes_trimmed.into_source();
                    let public_key = Constructed::decode(key_source, Mode::Der, |cons| {
                        cons.take_sequence(|cons| {

                            let modulus = cons.take_value(|_,content| {
                                let mod_bytes = content.as_primitive()?;
                                let mut modu = mod_bytes.slice_all()?.to_vec();
                                //remove initial 0 (positive/negative number in complement2 )
                                modu.drain(0..1);
                                _=mod_bytes.skip_all();
                                Ok(modu)
                            })?;
                            
                            let exponent = cons.take_value(|_,content|{
                                let exp_bytes = content.as_primitive()?;
                                let expp = exp_bytes.slice_all()?.to_vec();
                                _=exp_bytes.skip_all();
                                Ok(expp)
                            })?;
                            
                            _=cons.skip_all();
                            //println!("\n[*] parsed RSA key: mod: {:?}\nexp:{:?}",modulus,exponent);
                            Ok(PublicKey::Rsa {
                                modulus,
                                exponent,
                            })
                        })
                    }).expect("failed to parse public key modulus and exponent");
                    
                    _=content.skip_all();
                    public_key //return to pk
                } 
                else if algorithm.algorithm.as_ref() == ECDSA_OID_BYTES {
                    // TODO: invece che [1..] si dovrebbe creare una source e fare take_value(..){}
                    let point_bytes = &key_bytes[1..];
                    //println!("\n[*] parsed ECDSA key. point: {:?}",point_bytes);

                    PublicKey::Ecdsa { point: point_bytes.to_vec() } //return to pk
                }
                else {
                    return Err(DecodeError::content("Unsupported algorithm", decode::Pos::default()));
                };

                _=content.skip_all();
                Ok(pk)
            })?;

            _ = cons.capture_all();

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
    /*let bytes: Vec<u8>;

    // if the file is PEM, parse 
    let bytes_slice: &[u8] = if let Ok(pem) = pem::parse(&buffer) {
        bytes = pem.contents().to_vec(); // Store the contents in a new Vec
        &bytes // Reference the new Vec, which has the correct lifetime
    } else {
        &buffer // Use the entire buffer as a slice if it's DER
    };*/

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


fn main() {
    match load_pkcs7("../sdoc.p7b") {
        Ok(pkcs7) => {
            println!("PKCS#7 file loaded successfully!");
            println!("signed attributes: {:?}",pkcs7.content.signer_infos[0].auth_attributes);
            //println!("tbs_bytes: {:?}",pkcs7.content.certs[0].tbs_certificate.tbs_bytes);
            //println!("auth attr{:?}",pkcs7.content.signer_infos[0].authenticated_attributes);
            //let a = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            //println!("now {}", a)

        },
        Err(e) => println!("Failed to load PKCS#7 file: {}", e),
    }
}*/
    


