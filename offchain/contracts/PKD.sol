pragma solidity ^0.5.8;
/**
This contract acts as a Public Key Directory for looking up ZKP public keys if you know
the Ethereum address.  It also works as a simple Name Service
@author Westlad
*/
// 如果您知道以太坊地址，则该合约充当用于查找ZKP公共密钥的公共密钥目录。 它也可以用作简单的[名称服务].
//
// TODO 存储公钥合约,
// 公钥包括两部分:
//      1. whisper 本身的公钥
//      2. 隐私交易的公钥（地址）
// 简单的说，offchain 模块维护了线下的公钥，并提供了相互查询的功能.

contract PKD{

  mapping ( bytes32 => address) private byName;
  mapping ( address => bytes32) private byAddress;

  // whisper 的公钥集 (用于 p2p)
  mapping ( address => string) private WhisperPublicKeyByAddress;

  // 零知识证明 的公钥集 (用于隐私交易)
  mapping ( address => bytes32) private ZkpPublicKeyByAddress;
  mapping ( bytes32 => address) private AddressByZkpPublicKey;
  bytes32[] private names;

  function getWhisperPublicKeyFromName(bytes32 name) public view returns(string memory){
    return WhisperPublicKeyByAddress[byName[name]];
  }

  function getWhisperPublicKeyFromAddress(address addr) public view returns(string memory){
    return WhisperPublicKeyByAddress[addr];
  }

  function getZkpPublicKeyFromAddress(address addr) public view returns(bytes32){
    return ZkpPublicKeyByAddress[addr];
  }

  function getZkpPublicKeyFromName(bytes32 name) public view returns(bytes32){
    return ZkpPublicKeyByAddress[byName[name]];
  }

  function getPublicKeysFromName(bytes32 name) public view returns(
    string  memory whisperPublicKey,
    bytes32 zkpPublicKey
    ){
      whisperPublicKey = WhisperPublicKeyByAddress[byName[name]];
      zkpPublicKey = ZkpPublicKeyByAddress[byName[name]];
    }

  function getPublicKeysFromAddress(address addr) public view returns(
    string  memory whisperPublicKey,
    bytes32 zkpPublicKey
    ){
      whisperPublicKey = WhisperPublicKeyByAddress[addr];
      zkpPublicKey = ZkpPublicKeyByAddress[addr];
    }

  function setPublicKeys(
    string  memory whisperPublicKey,
    bytes32 zkpPublicKey
    ) public{
    WhisperPublicKeyByAddress[msg.sender] = whisperPublicKey;
    ZkpPublicKeyByAddress[msg.sender] = zkpPublicKey;
  }

  function setWhisperPublicKey(string  memory pk) public{
    WhisperPublicKeyByAddress[msg.sender] = pk;
  }

  function setZkpPublicKey(bytes32 pk) public{
    ZkpPublicKeyByAddress[msg.sender] = pk;
    AddressByZkpPublicKey[pk] = msg.sender;
  }

  function setName(bytes32 name) public {
    require(byName[name] == address(0), "Name already in use"); //you can only use a name once
    byName[name] = msg.sender;
    byAddress[msg.sender] = name;
    names.push(name);
  }

  function getNameFromAddress(address addr) public view returns(bytes32){
    return byAddress[addr];
  }

  function getNameFromZkpPublicKey(bytes32 pk) public view returns(bytes32){
    address addr = AddressByZkpPublicKey[pk];
    return byAddress[addr];
  }

  function getAddressFromName(bytes32 name) public view returns(address){
    return byName[name];
  }

  function getNames() public view returns(bytes32[] memory){
    return names;
  }

  function isNameInUse(bytes32 name) public view returns(bool){
    if (byName[name] == address(0)) return false;
    return true;
  }

}
