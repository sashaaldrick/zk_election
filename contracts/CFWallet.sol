
pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ImageID} from "./ImageID.sol"; // auto-generated contract after running `cargo build`.


contract CFWallet {
    
    bytes32 public constant imageId = ImageID.PKCS7_VERIFY_ID;
    IRiscZeroVerifier public immutable verifier;
    bytes32 public saltedCf;

    address payable to;
    
    bytes public lastSeal;
    bytes public lastJournal;

  
    event VerificationAttempted(address sender, bytes32 imageId, bytes journal);

    constructor(IRiscZeroVerifier _verifier, bytes32 _cf) {
        verifier = _verifier;
        saltedCf = _cf; 
    }

    receive() external payable {}

    function transfer(address payable _to) public {
        //require(verify_proof(proof, saltedCf, _to));
        payable(_to).transfer(address(this).balance);
    }

    // @notice function called by Rust. Verify the proof and call transfer function
    // verify the proof (done by IRiscZeroVerifier)
    // verify the salted_CF
    // verify if the root_public_key is valid
    function verifyAndTransfer(bytes calldata journal, bytes calldata seal) public {
        
        verifier.verify(seal, imageId, sha256(journal));
        to = bytesToAddress(journal[0:20]);
        require(verifyJournalData(bytes32(journal[20:52]),journal[52:]), "Data verification failed");
        //bytes32 extractedCf = bytes32(journal[20:52]);
        //bytes rootPubKey = journal[52:];
        //require(verifyJournalData(extractedCf, rootPubKey));


        transfer(to);
    }


    function verifyJournalData(bytes32 extractedCf, bytes calldata rootPubKey) private view returns (bool is_verified) {

        if (extractedCf != saltedCf){
            return false;
        }  
        //check the root key here

        return true;
    }


    function bytesToAddress(bytes memory bys) private pure returns (address payable addr) {
        require(bys.length == 20, "Invalid length");
        assembly {
            // Carica i 32 byte dei dati effettivi
            let data := mload(add(bys, 32))
            // Sposta a destra di 96 bit (12 byte) per ottenere i primi 20 byte
            addr := div(data, 0x1000000000000000000000000)
        }
        //oppure
        //addr = payable(abi.decode(bys, (address)));

    }

    //  TEST

    function get_owner() public view returns (bytes32){
        return saltedCf;
    }

    function get_extracted_address() public view returns (address){
        return to;
    }

    /*function get_extracted_pubkey() public view returns (bytes){
        return journal[52:];
    }*/
    /* function verifyAndCommitVote(bytes calldata seal, bytes calldata journal) public {
        lastSeal = seal;
        lastJournal = journal;
        
        emit VerificationAttempted(msg.sender, imageId, journal);
        verifier.verify(seal, imageId, sha256(journal));
        
    }

    // debug function
    function getLastVerificationData() public view returns (bytes memory, bytes memory) {
        return (lastSeal, lastJournal);
    }*/
}
