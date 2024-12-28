## EntryPoint Foundry

Working on rewriting/testing the EntryPoint implementation by eth-infinitism with Foundry.

## Covered Functions

- [ ] senderCreator  
- [ ] supportsInterface  
- [x] _compensate  
- [ ] _executeUserOp  
- [x] emitUserOperationEvent  
- [x] emitPrefundTooLow  
- [ ] handleOps  
- [ ] handleAggregatedOps  
- [ ] innerHandleOp  
- [x] getUserOpHash  
- [x] _copyUserOpToMemory  
- [x] _getRequiredPrefund  
- [ ] _createSenderIfNeeded  
- [ ] getSenderAddress  
- [x] _validateAccountPrepayment  
- [x] _validatePaymasterPrepayment 
- [x] _validateAccountAndPaymasterValidationData  
- [x] _getValidationData  
- [ ] _validatePrepayment  
- [ ] _postExecution - work on understanding this.
- [x] getUserOpGasPrice  
- [ ] getOffsetOfMemoryBytes  
- [ ] getMemoryBytesFromOffset  
- [ ] delegateAndRevert  