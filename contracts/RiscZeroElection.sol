
pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ImageID} from "./ImageID.sol"; // auto-generated contract after running `cargo build`.


contract RiscZeroElection {
    
    bytes32 public constant imageId = ImageID.ZK_VERIFIER_ID;
    IRiscZeroVerifier public immutable verifier;

    

    event VerificationAttempted(address sender, bytes32 imageId, bytes journal);

    constructor(IRiscZeroVerifier _verifier) {
        verifier = _verifier; 
    }

    function verifyAndCommitVote(bytes calldata seal, bytes calldata journal) public {

        emit VerificationAttempted(msg.sender, imageId, journal);
        verifier.verify(seal, imageId, sha256(journal));
        
    }

    /*function get() public view returns (){
        return journal_global;
    }*/
}
