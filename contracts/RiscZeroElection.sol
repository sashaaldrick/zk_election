
pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ImageID} from "./ImageID.sol"; // auto-generated contract after running `cargo build`.


contract RiscZeroElection {
    
    bytes32 public constant imageId = ImageID.SIGNATURE_VERIFIER_ID;
    IRiscZeroVerifier public immutable verifier;
    bytes public lastSeal;
    bytes public lastJournal;
    

    event VerificationAttempted(address sender, bytes32 imageId, bytes journal);

    constructor(IRiscZeroVerifier _verifier) {
        verifier = _verifier; 
    }

    function verifyAndCommitVote(bytes calldata seal, bytes calldata journal) public {
        lastSeal = seal;
        lastJournal = journal;
        
        emit VerificationAttempted(msg.sender, imageId, journal);
        verifier.verify(seal, imageId, sha256(journal));
        
    }

    function getLastVerificationData() public view returns (bytes memory, bytes memory) {
        return (lastSeal, lastJournal);
    }
}
