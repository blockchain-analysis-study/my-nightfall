/**
This acts as a layer of logic between the index.js, which lands the
rest api calls, and the heavy-lifitng coin-zkp.js and zokrates.js.  It exists so
that the amount of logic in restapi.js is absolutely minimised. It is used for paying
arbitrary amounts of currency in zero knowlege.
@module f-token-controller.js
@author westlad, Chaitanya-Konda, iAmMichaelConnor
*/

// TODO 这个才是真正的  ERC20 隐私交易的真正入口
import contract from 'truffle-contract';
import jsonfile from 'jsonfile';
import zkp from './f-token-zkp';
import Web3 from './web3';
import { getContractAddress } from './contractUtils';


const FTokenShield = contract(jsonfile.readFileSync('./build/contracts/FTokenShield.json'));
FTokenShield.setProvider(Web3.connect());

const Verifier = contract(jsonfile.readFileSync('./build/contracts/Verifier.json'));
Verifier.setProvider(Web3.connect());

const FToken = contract(jsonfile.readFileSync('./build/contracts/FToken.json'));
FToken.setProvider(Web3.connect());

const shield = {}; // this field holds the current Shield contract instance.

async function unlockAccount(address, password) {
  const web3 = Web3.connection();
  await web3.eth.personal.unlockAccount(address, password, 0);
}

/**
This function allocates a specific FTokenShield contract to a particular user
(or, more accurately, a particular Ethereum address)
@param {string} shieldAddress - the address of the shield contract you want to point to
@param {string} address - the Ethereum address of the user to whom this shieldAddress will apply
*/
async function setShield(shieldAddress, address) {
  if (shieldAddress === undefined) shield[address] = await getContractAddress('FTokenShield');
  else shield[address] = await FTokenShield.at(shieldAddress);
}

function unSetShield(address) {
  delete shield[address];
}

/**
return the address of the shield contract
*/
async function getShieldAddress(account) {
  const fTokenShieldInstance = shield[account]
    ? shield[account]
    : await getContractAddress('FTokenShield');
  return fTokenShieldInstance.address;
}

/**
return the balance of an account
@param {string} address - the address of the Ethereum account
*/
async function getBalance(address) {
  const fToken = await FToken.at(await getContractAddress('FToken'));
  return fToken.balanceOf.call(address);
}

/**
return the address of the ERC-20 token
*/
async function getFTAddress() {
  return getContractAddress('FToken');
}

/**
create ERC-20 in an account.  This allows one to mint more coins into the ERC-20
contract that the shield contract is using.  Obviously the ERC-20 needs to support
this functionality and most won't (as it would make the token value zero) but it's
useful to be able to create coins for demonstration purposes.
@param {string} amount - the amount of cryptocurrency to mint
@param {string} address - the address of the Ethereum account
*/
async function buyFToken(amount, address) {
  console.log('Buying ERC-20', amount, address);
  const fToken = await FToken.at(await getContractAddress('FToken'));
  return fToken.mint(address, amount, {
    from: address,
    gas: 4000000,
  });
}

/**
transfer ERC-20 to an account.  This allows one to transfer a token from fromAddress
to toAddress.  The tranaction fee will be taken from fromAddress
@param {string} amount - the amount of cryptocurrency to transfer
@param {string} toAddress - the address of the Ethereum account to transfer to
@param {string} fromAddress - the address of the Ethereum account to transfer from
*/
async function transferFToken(amount, fromAddress, toAddress) {
  console.log('Transferring ERC-20', amount, toAddress);
  const fToken = await FToken.at(await getContractAddress('FToken'));
  return fToken.transfer(toAddress, amount, {
    from: fromAddress,
    gas: 4000000,
  });
}

/**
Burn a ERC-20 token in an account.  This allows one to delete coins from the ERC-20
contract that the shield contract is using.  Obviously the ERC-20 needs to support
this functionality and most won't (as it would simply destroy value) but it's
useful to be able to delete coins for demonstration purposes.
Note: this is different functionality from 'burning' a commitment (private token).
Burning a commitment recovers the original ERC-20 value.
@param {string} amount - the amount of cryptocurrency to burn
@param {string} address - the address of the Ethereum account
*/
async function burnFToken(amount, address) {
  console.log('Buying ERC-20', amount, address);

  const fToken = await FToken.at(await getContractAddress('FToken'));
  return fToken.burn(address, amount, {
    from: address,
    gas: 4000000,
  });
}

/**
Return the meta data for the ERC-20 token that the user with the given address
is utilising.
@param address - the address of the user (different users may us different ERC-20 contracts)
@returns - an object containing the token symbol and name.
*/
async function getTokenInfo() {
  console.log('Getting ERC-20 info');
  const fToken = await FToken.at(await getContractAddress('FToken'));
  const symbol = await fToken.symbol.call();
  const name = await fToken.name.call();
  return { symbol, name };
}

async function checkCorrectness(
  erc20Address,
  amount,
  publicKey,
  salt,
  commitment,
  commitmentIndex,
  blockNumber,
  account,
) {
  const fTokenShieldInstance = shield[account] ? shield[account] : await FTokenShield.deployed();

  const results = await zkp.checkCorrectness(
    erc20Address,
    amount,
    publicKey,
    salt,
    commitment,
    commitmentIndex,
    blockNumber,
    fTokenShieldInstance,
  );
  console.log('\nf-token-controller', '\ncheckCorrectness', '\nresults', results);

  return results;
}

/**
Return transaction receipt for a particular transaction hash.
@param txHash - Mined transaction's hash.
@returns - an object transaction receipt.
*/
async function getTxRecipt(txHash) {
  const web3 = Web3.connection();
  return web3.eth.getTransactionReceipt(txHash);
}

/**
Return decoded transaction receipt object.
@param inputs - event input defination.
@param data - encoded data
*/
async function getTxLogDecoded(inputs, data) {
  const web3 = Web3.connection();
  return web3.eth.abi.decodeLog(inputs, data);
}

export default {
  getBalance,
  getFTAddress,
  buyFToken,
  transferFToken,
  burnFToken,
  getTokenInfo,
  unlockAccount,
  setShield,
  unSetShield,
  checkCorrectness,
  getShieldAddress,
  getTxRecipt,
  getTxLogDecoded,
};
