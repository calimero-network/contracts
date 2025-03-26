// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/console.sol";
// Interface for the context config contract - simplified

interface IContextConfig {
    function hasMember(bytes32 contextId, bytes32 userId) external view returns (bool);
}

/**
 * @title ContextProxy
 * @dev Multi-signature proposal execution contract for Calimero contexts
 */
contract ContextProxy {
    // Define the types needed for the proxy contract
    enum RequestKind {
        Propose,
        Approve
    }

    struct Request {
        bytes32 signerId; // ECDSA public key
        bytes32 userId; // Ed25519 public key
        RequestKind kind;
        bytes data; // Encoded proposal or approval data
    }

    struct SignedRequest {
        Request payload;
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    // Data structures
    enum ProposalActionKind {
        ExternalFunctionCall,
        Transfer,
        SetNumApprovals,
        SetActiveProposalsLimit,
        SetContextValue,
        DeleteProposal
    }

    struct ProposalAction {
        ProposalActionKind kind;
        bytes data;
    }

    struct Proposal {
        bytes32 id;
        bytes32 authorId;
        ProposalAction[] actions;
    }

    struct ProposalWithApprovals {
        bytes32 proposalId;
        uint32 numApprovals;
    }

    struct ProposalApprovalWithSigner {
        bytes32 proposalId;
        bytes32 userId;
    }

    // State variables
    bytes32 public immutable contextId;
    address public immutable contextConfigId;
    uint32 public numApprovals;
    mapping(bytes32 => Proposal) public proposals;
    mapping(bytes32 => bytes32[]) public approvals;
    mapping(bytes32 => uint32) public numProposalsPk;
    uint32 public activeProposalsLimit;
    mapping(bytes => bytes) public contextStorage;
    bytes[] private contextStorageKeys;
    bytes32[] private allProposalIds;

    // Events
    event ProposalCreated(bytes32 indexed proposalId, bytes32 authorId);
    event ProposalApproved(bytes32 indexed proposalId, bytes32 signerId, uint32 numApprovals);
    event ProposalExecuted(bytes32 indexed proposalId);
    event ProposalDeleted(bytes32 indexed proposalId);
    event NumApprovalsChanged(uint32 oldValue, uint32 newValue);
    event ActiveProposalsLimitChanged(uint32 oldValue, uint32 newValue);
    event ContextValueSet(bytes key, bytes value);
    event ExternalCallExecuted(address target, bytes4 selector, uint256 value);
    event TokenTransferred(address to, uint256 amount);

    // Errors
    error AlreadyInitialized();
    error Unauthorized();
    error InvalidAction();
    error TooManyActiveProposals();
    error ProposalNotFound();
    error ProposalAlreadyApproved();
    error InsufficientBalance();
    error InvalidSignature();

    // Storage slot for implementation address (follows EIP-1967)
    bytes32 private constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
     * @dev Constructor
     * @param _contextId ID of the context this proxy belongs to
     * @param _owner Address of the context configuration contract
     */
    constructor(bytes32 _contextId, address _owner) {
        contextId = _contextId;
        contextConfigId = _owner;
        numApprovals = 3;
        activeProposalsLimit = 10;
    }

    /**
     * @dev Processes a signed mutation request for the proxy contract
     * @param signedRequest The signed request containing the mutation action
     * @return Optional proposal with approvals if not executed
     */
    function mutate(SignedRequest calldata signedRequest) external returns (ProposalWithApprovals memory) {
        // Verify signature and authorization
        bytes32 messageHash = keccak256(abi.encode(signedRequest.payload));

        // Get the Ethereum signed message hash
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        // Verify the signature using ECDSA key with ethSignedMessageHash
        address signer = ecrecover(ethSignedMessageHash, signedRequest.v, signedRequest.r, signedRequest.s);

        // Convert signer address to bytes32 for comparison
        bytes32 signerAsBytes32 = bytes32(uint256(uint160(signer)));

        if (signer == address(0) || signerAsBytes32 != signedRequest.payload.signerId) {
            revert InvalidSignature();
        }

        // Check if user is a member
        if (!isMember(signedRequest.payload.userId)) {
            revert Unauthorized();
        }

        // Process based on request kind
        if (signedRequest.payload.kind == RequestKind.Propose) {
            Proposal memory proposal = abi.decode(signedRequest.payload.data, (Proposal));
            return internalCreateProposal(proposal);
        } else if (signedRequest.payload.kind == RequestKind.Approve) {
            ProposalApprovalWithSigner memory approval =
                abi.decode(signedRequest.payload.data, (ProposalApprovalWithSigner));
            return internalApproveProposal(approval);
        }

        revert InvalidAction();
    }

    /**
     * @dev Creates a new proposal in the contract
     * @param proposal The proposal to be created
     * @return Optional proposal with approvals if not executed
     */
    function internalCreateProposal(Proposal memory proposal) internal returns (ProposalWithApprovals memory) {
        // Validate proposal
        if (proposal.actions.length == 0) {
            revert InvalidAction();
        }

        // Handle delete action if present
        for (uint256 i = 0; i < proposal.actions.length; i++) {
            if (proposal.actions[i].kind == ProposalActionKind.DeleteProposal) {
                bytes32 proposalIdToDelete = abi.decode(proposal.actions[i].data, (bytes32));

                Proposal storage toDelete = proposals[proposalIdToDelete];

                if (toDelete.authorId != proposal.authorId) {
                    revert Unauthorized();
                }

                removeProposal(proposalIdToDelete);

                // Return empty proposal with approvals
                return ProposalWithApprovals({proposalId: bytes32(0), numApprovals: 0});
            }
        }

        // Check proposal limit
        uint32 authorProposalCount = numProposalsPk[proposal.authorId];
        if (authorProposalCount >= activeProposalsLimit) {
            revert TooManyActiveProposals();
        }

        // Validate all actions
        for (uint256 i = 0; i < proposal.actions.length; i++) {
            validateProposalAction(proposal.actions[i]);
        }

        // Store proposal
        bytes32 proposalId = proposal.id;
        Proposal storage newProposal = proposals[proposalId];
        newProposal.id = proposal.id;
        newProposal.authorId = proposal.authorId;

        // Copy actions array element by element
        for (uint256 i = 0; i < proposal.actions.length; i++) {
            newProposal.actions.push(proposal.actions[i]);
        }

        numProposalsPk[proposal.authorId] = authorProposalCount + 1;

        // Add to the list of all proposal IDs
        allProposalIds.push(proposalId);

        emit ProposalCreated(proposalId, proposal.authorId);

        // Auto-approve by author
        return internalApproveProposal(ProposalApprovalWithSigner({proposalId: proposalId, userId: proposal.authorId}));
    }

    /**
     * @dev Approves an existing proposal
     * @param approval The approval details including proposal ID and signer
     * @return Optional proposal with approvals if not executed
     */
    function internalApproveProposal(ProposalApprovalWithSigner memory approval)
        internal
        returns (ProposalWithApprovals memory)
    {
        bytes32 proposalId = approval.proposalId;
        Proposal storage proposal = proposals[proposalId];

        // Check if proposal exists
        if (proposal.id != proposalId) {
            revert ProposalNotFound();
        }

        // Check if already approved
        bytes32[] storage proposalApprovals = approvals[proposalId];
        for (uint256 i = 0; i < proposalApprovals.length; i++) {
            if (proposalApprovals[i] == approval.userId) {
                revert ProposalAlreadyApproved();
            }
        }

        // Add approval
        proposalApprovals.push(approval.userId);

        emit ProposalApproved(proposalId, approval.userId, uint32(proposalApprovals.length));

        // Check if should execute
        if (proposalApprovals.length >= numApprovals) {
            executeProposal(proposalId);
            return ProposalWithApprovals({proposalId: bytes32(0), numApprovals: 0});
        }

        return ProposalWithApprovals({proposalId: proposalId, numApprovals: uint32(proposalApprovals.length)});
    }

    /**
     * @dev Verifies if an address is a member of the context
     * @param userId The user ID to check
     * @return Whether the user is a member
     */
    function isMember(bytes32 userId) internal view returns (bool) {
        return IContextConfig(contextConfigId).hasMember(contextId, userId);
    }

    /**
     * @dev Validates a single proposal action
     * @param action The action to validate
     */
    function validateProposalAction(ProposalAction memory action) internal pure {
        if (action.kind == ProposalActionKind.ExternalFunctionCall) {
            // Get the data bytes
            bytes memory data = action.data;

            // Log the raw data bytes without using slices
            if (data.length >= 32) {
                bytes32 chunk1;
                assembly {
                    // Load 32 bytes from memory - need to add 32 to skip the length field
                    chunk1 := mload(add(data, 32))
                }
            }

            // Check if the first 32 bytes are a pointer (0x20)
            bytes32 firstWord;
            assembly {
                firstWord := mload(add(data, 32))
            }

            bytes memory actualData;
            address target;
            bytes memory callData;
            uint256 value;

            if (firstWord == 0x0000000000000000000000000000000000000000000000000000000000000020) {
                // Skip the first 32 bytes (the pointer) and use the rest
                actualData = new bytes(data.length - 32);
                for (uint256 i = 0; i < data.length - 32; i++) {
                    actualData[i] = data[i + 32];
                }

                // Attempt the decode on the adjusted data
                (target, callData, value) = abi.decode(actualData, (address, bytes, uint256));
            } else {
                // Use the original data
                (target, callData, value) = abi.decode(data, (address, bytes, uint256));
            }

            // (address target, bytes memory callData,) = abi.decode(
            //     action.data,
            //     (address, bytes, uint256)
            // );

            if (target == address(0)) {
                revert InvalidAction();
            }
        } else if (action.kind == ProposalActionKind.Transfer) {
            (address recipient, uint256 amount) = abi.decode(action.data, (address, uint256));
            if (recipient == address(0) || amount == 0) {
                revert InvalidAction();
            }
        } else if (action.kind == ProposalActionKind.SetNumApprovals) {
            uint32 newApprovals = abi.decode(action.data, (uint32));
            if (newApprovals == 0) {
                revert InvalidAction();
            }
        } else if (action.kind == ProposalActionKind.SetActiveProposalsLimit) {
            uint32 newLimit = abi.decode(action.data, (uint32));
            if (newLimit == 0) {
                revert InvalidAction();
            }
        }
    }

    /**
     * @dev Removes a proposal and updates related state
     * @param proposalId The ID of the proposal to remove
     */
    function removeProposal(bytes32 proposalId) internal {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.id == proposalId) {
            bytes32 authorId = proposal.authorId;

            // Delete approvals
            delete approvals[proposalId];

            // Delete proposal
            delete proposals[proposalId];

            // Update author count
            if (numProposalsPk[authorId] > 0) {
                numProposalsPk[authorId]--;
            }

            // Remove from allProposalIds array
            for (uint256 i = 0; i < allProposalIds.length; i++) {
                if (allProposalIds[i] == proposalId) {
                    // Replace with the last element and pop
                    allProposalIds[i] = allProposalIds[allProposalIds.length - 1];
                    allProposalIds.pop();
                    break;
                }
            }

            emit ProposalDeleted(proposalId);
        }
    }

    /**
     * @dev Executes a proposal that has received sufficient approvals
     * @param proposalId The ID of the proposal to execute
     */
    function executeProposal(bytes32 proposalId) internal {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.id != proposalId) {
            revert ProposalNotFound();
        }

        // Cache the actions array length
        uint256 actionsLength = proposal.actions.length;

        // Execute each action
        for (uint256 i = 0; i < actionsLength; i++) {
            ProposalAction memory action = proposal.actions[i];

            if (action.kind == ProposalActionKind.ExternalFunctionCall) {
                // Get the data bytes
                bytes memory data = action.data;

                // Log the raw data bytes without using slices
                if (data.length >= 32) {
                    bytes32 chunk1;
                    assembly {
                        // Load 32 bytes from memory - need to add 32 to skip the length field
                        chunk1 := mload(add(data, 32))
                    }
                }

                // Check if the first 32 bytes are a pointer (0x20)
                bytes32 firstWord;
                assembly {
                    firstWord := mload(add(data, 32))
                }

                bytes memory actualData;
                address target;
                bytes memory callData;
                uint256 value;

                if (firstWord == 0x0000000000000000000000000000000000000000000000000000000000000020) {
                    // Skip the first 32 bytes (the pointer) and use the rest
                    actualData = new bytes(data.length - 32);
                    for (uint256 j = 0; j < data.length - 32; j++) {
                        actualData[j] = data[j + 32];
                    }

                    // Attempt the decode on the adjusted data
                    (target, callData, value) = abi.decode(actualData, (address, bytes, uint256));
                } else {
                    // Use the original data
                    (target, callData, value) = abi.decode(data, (address, bytes, uint256));
                }
                // Execute external call
                (bool success,) = target.call{value: value}(callData);
                if (!success) {
                    revert InvalidAction();
                }

                emit ExternalCallExecuted(target, bytes4(callData), value);
            } else if (action.kind == ProposalActionKind.Transfer) {
                (address recipient, uint256 amount) = abi.decode(action.data, (address, uint256));

                // Transfer tokens using unchecked for gas optimization
                bool success;
                unchecked {
                    (success,) = recipient.call{value: amount}("");
                }
                if (!success) {
                    revert InsufficientBalance();
                }

                emit TokenTransferred(recipient, amount);
            } else if (action.kind == ProposalActionKind.SetNumApprovals) {
                uint32 newApprovals = abi.decode(action.data, (uint32));
                uint32 oldApprovals = numApprovals;
                numApprovals = newApprovals;

                emit NumApprovalsChanged(oldApprovals, newApprovals);
            } else if (action.kind == ProposalActionKind.SetActiveProposalsLimit) {
                uint32 newLimit = abi.decode(action.data, (uint32));
                uint32 oldLimit = activeProposalsLimit;
                activeProposalsLimit = newLimit;

                emit ActiveProposalsLimitChanged(oldLimit, newLimit);
            } else if (action.kind == ProposalActionKind.SetContextValue) {
                (bytes memory key, bytes memory value) = abi.decode(action.data, (bytes, bytes));
                bool keyExists = contextStorage[key].length > 0;

                if (!keyExists) {
                    contextStorageKeys.push(key);
                }
                contextStorage[key] = value;

                emit ContextValueSet(key, value);
            } else if (action.kind == ProposalActionKind.DeleteProposal) {
                bytes32 proposalIdToDelete = abi.decode(action.data, (bytes32));
                removeProposal(proposalIdToDelete);
            }
        }

        // Clean up after successful execution
        emit ProposalExecuted(proposalId);
        removeProposal(proposalId);
    }

    /**
     * @dev Returns the number of approvals required for proposal execution
     */
    function getNumApprovals() external view returns (uint32) {
        return numApprovals;
    }

    /**
     * @dev Returns the maximum number of active proposals allowed per author
     */
    function getActiveProposalsLimit() external view returns (uint32) {
        return activeProposalsLimit;
    }

    /**
     * @dev Retrieves a specific proposal by ID
     * @param proposalId The ID of the proposal to retrieve
     */
    function getProposal(bytes32 proposalId) external view returns (Proposal memory) {
        return proposals[proposalId];
    }

    /**
     * @dev Returns a paginated list of active proposals
     */
    function getProposals(uint32 fromIndex, uint32 limit) external view returns (Proposal[] memory) {
        // Calculate result size based on available proposals and pagination
        uint32 resultSize = 0;
        if (fromIndex < allProposalIds.length) {
            resultSize = (uint32(allProposalIds.length) - fromIndex) < limit
                ? (uint32(allProposalIds.length) - fromIndex)
                : limit;
        }

        Proposal[] memory result = new Proposal[](resultSize);

        // Fill array with paginated results
        for (uint32 i = 0; i < resultSize; i++) {
            bytes32 proposalId = allProposalIds[fromIndex + i];
            result[i] = proposals[proposalId];
        }

        return result;
    }

    /**
     * @dev Returns the total number of active proposals
     */
    function getProposalCount() external view returns (uint256) {
        return allProposalIds.length;
    }

    /**
     * @dev Gets the number of confirmations for a specific proposal
     * @param proposalId The ID of the proposal to check
     */
    function getConfirmationsCount(bytes32 proposalId) external view returns (ProposalWithApprovals memory) {
        if (proposals[proposalId].id != proposalId) {
            return ProposalWithApprovals({proposalId: bytes32(0), numApprovals: 0});
        }

        return ProposalWithApprovals({proposalId: proposalId, numApprovals: uint32(approvals[proposalId].length)});
    }

    /**
     * @dev Returns the list of addresses that have approved a specific proposal
     * @param proposalId The ID of the proposal to check
     */
    function proposalApprovers(bytes32 proposalId) external view returns (bytes32[] memory) {
        return approvals[proposalId];
    }

    /**
     * @dev Returns detailed approval information for a proposal
     * @param proposalId The ID of the proposal to check
     */
    function proposalApprovalsWithSigner(bytes32 proposalId)
        external
        view
        returns (ProposalApprovalWithSigner[] memory)
    {
        bytes32[] storage proposalApprovals = approvals[proposalId];
        ProposalApprovalWithSigner[] memory result = new ProposalApprovalWithSigner[](proposalApprovals.length);

        for (uint256 i = 0; i < proposalApprovals.length; i++) {
            result[i] = ProposalApprovalWithSigner({proposalId: proposalId, userId: proposalApprovals[i]});
        }

        return result;
    }

    /**
     * @dev Retrieves a value from the context storage
     * @param key The key to look up in the context storage
     */
    function getContextValue(bytes calldata key) external view returns (bytes memory) {
        return contextStorage[key];
    }

    /**
     * @dev Returns a paginated list of key-value pairs from the context storage
     * @param fromIndex Starting index for pagination
     * @param limit Maximum number of entries to return
     */
    function contextStorageEntries(uint32 fromIndex, uint32 limit)
        external
        view
        returns (bytes[] memory, bytes[] memory)
    {
        uint256 resultSize = 0;

        // Calculate result size based on available keys and pagination
        if (fromIndex < contextStorageKeys.length) {
            resultSize =
                (contextStorageKeys.length - fromIndex) < limit ? (contextStorageKeys.length - fromIndex) : limit;
        }

        bytes[] memory keys = new bytes[](resultSize);
        bytes[] memory values = new bytes[](resultSize);

        // Fill arrays with paginated results
        for (uint32 i = 0; i < resultSize; i++) {
            bytes memory key = contextStorageKeys[fromIndex + i];
            keys[i] = key;
            values[i] = contextStorage[key];
        }

        return (keys, values);
    }

    /**
     * @dev Returns the current implementation address
     */
    function _getImplementation() internal view returns (address) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        address implementation;
        assembly {
            implementation := sload(slot)
        }
        return implementation;
    }

    /**
     * @dev Sets the implementation address
     */
    function _setImplementation(address implementation) internal {
        require(implementation.code.length > 0, "Implementation must be a contract");
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, implementation)
        }
    }

    /**
     * @dev Upgrades the proxy contract
     * @param implementation The new implementation address
     * @param contextAddress The context configuration contract address
     */
    function upgrade(address implementation, address contextAddress) external {
        // Require authorization from context contract
        if (msg.sender != contextAddress || contextAddress != contextConfigId) {
            revert Unauthorized();
        }

        // Ensure the new implementation is a contract
        if (implementation.code.length == 0) {
            revert("Implementation must be a contract");
        }

        // Update the implementation
        _setImplementation(implementation);
    }

    /**
     * @dev Receive function to accept ETH
     */
    receive() external payable {}
}
