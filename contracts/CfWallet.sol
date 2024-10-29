
pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ImageID} from "./ImageID.sol"; // auto-generated contract after running `cargo build`.


contract CfWallet {
    
    bytes32 public constant imageId = ImageID.PKCS7_VERIFY_ID;
    IRiscZeroVerifier public immutable verifier;
    bytes32 public saltedCf;

    address payable to;
    
    bytes public lastSeal;
    bytes public lastJournal;

    //event LogAddress(address extracted);

    constructor(IRiscZeroVerifier _verifier, bytes32 _cf) {
        verifier = _verifier;
        saltedCf = _cf; 
    }

    receive() external payable {}

    //transfer the found to the address contained in the signed document
    function transfer(address payable _to) public {
        //require(verify_proof(proof, saltedCf, _to));
        emit Log("transfer");

        payable(_to).transfer(address(this).balance);
    }

    // @notice function called by Rust. Verify the proof and call transfer function
    // verify the proof (done by IRiscZeroVerifier)
    // verify the salted_CF
    // verify if the root_public_key is valid
    function verifyAndTransfer(bytes calldata journal, bytes calldata seal) public {
        //require(journal.length == 308, "Invalid journal length");

        verifier.verify(seal, imageId, sha256(journal));
        //emit Log("Verifier verification passed");
        
        to = bytesToAddress(journal[0:20]);

        bytes32 extractedCf = bytes32(journal[20:52]);
        bytes calldata rootPubKey = journal[52:];

        bool is_journal_valid = verifyJournalData(extractedCf, rootPubKey);
        require(is_journal_valid, "Incorrect journal data");
        emit Log("Journal data verified");

        transfer(to);
    }

    event Log(string message);

    function verifyJournalData(bytes32 extractedCf, bytes calldata rootPubKey) private view returns (bool res){
        
        require(extractedCf == saltedCf, "different cf");
        
        //check the root key here

        return true;
    }


    function bytesToAddress(bytes calldata b) internal pure returns (address payable addr) {
        require(b.length == 20, "Invalid address length");
        addr = payable(address(uint160(bytes20(b))));
    }


    //  TEST

    function get_owner() public view returns (bytes32) {
        return saltedCf;
    }

    function get_extracted_address() public view returns (address payable){
        return to;
    }

    /*function get_extracted_cf() public view returns (bytes32){
        return extractedCf;
    }*/

    function get_balance() public view returns (uint256){
        return address(this).balance;
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
