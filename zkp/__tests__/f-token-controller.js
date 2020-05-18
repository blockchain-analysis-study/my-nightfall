/* eslint-disable import/no-unresolved */

import { erc20 } from '@eyblockchain/nightlite';
import bc from '../src/web3';

import utils from '../src/zkpUtils';
import controller from '../src/f-token-controller';
import { getTruffleContractInstance, getContractAddress } from '../src/contractUtils';

jest.setTimeout(7200000);

const amountC = '0x00000000000000000000000000000020'; // 128 bits = 16 bytes = 32 chars
const amountD = '0x00000000000000000000000000000030';
const amountE = '0x00000000000000000000000000000040';
const amountF = '0x00000000000000000000000000000010'; // don't forget to make C+D=E+F
const amountG = '0x00000000000000000000000000000030';
const amountH = '0x00000000000000000000000000000020'; // these constants used to enable a second transfer
const amountI = '0x00000000000000000000000000000050';
const secretKeyA = '0x1111111111111111111111111111111111111111111111111111111111111111';
const secretKeyB = '0x2222222222222222222222222222222222222222222222222222222222222222';
let saltAliceC;
let saltAliceD;
let saltAliceToBobE;
let saltAliceToAliceF;
let publicKeyA;
let publicKeyB;
const publicKeyE = '0x1111111111111111111111111111111111111111111111111111111111111112';
let commitmentAliceC;
let commitmentAliceD;
let saltBobG;
let saltBobToEveH;
let saltBobToBobI;
let commitmentBobG;
let commitmentBobE;
let commitmentAliceF;
// storage for z indexes
let zInd1;
let zInd2;
let zInd3;

let accounts;
let fTokenShieldJson;
let fTokenShieldAddress;
let erc20Address;
if (process.env.COMPLIANCE !== 'true') {
  beforeAll(async () => {
    if (!(await bc.isConnected())) await bc.connect();
    accounts = await (await bc.connection()).eth.getAccounts();

    const { contractJson, contractInstance } = await getTruffleContractInstance('FTokenShield');
    fTokenShieldAddress = contractInstance.address;
    fTokenShieldJson = contractJson;

    erc20Address = await getContractAddress('FToken');
    const erc20AddressPadded = `0x${utils.strip0x(erc20Address).padStart(64, '0')}`;

    saltAliceC = await utils.rndHex(32);
    saltAliceD = await utils.rndHex(32);
    saltAliceToBobE = await utils.rndHex(32);
    saltAliceToAliceF = await utils.rndHex(32);
    publicKeyA = utils.hash(secretKeyA);
    publicKeyB = utils.hash(secretKeyB);
    commitmentAliceC = utils.concatenateThenHash(

      // ERC20 token 合约地址
      erc20AddressPadded,

      // 本次 mint 的token 金额
      amountC,

      // mint发起者 Alice 自己的公钥
      publicKeyA,

      // Alice 的 salt C
      saltAliceC,
    );
    commitmentAliceD = utils.concatenateThenHash(
      erc20AddressPadded,
      amountD,
      publicKeyA,
      saltAliceD,
    );
    saltBobG = await utils.rndHex(32);
    saltBobToEveH = await utils.rndHex(32);
    saltBobToBobI = await utils.rndHex(32);
    commitmentBobG = utils.concatenateThenHash(erc20AddressPadded, amountG, publicKeyB, saltBobG);
    commitmentBobE = utils.concatenateThenHash(
      erc20AddressPadded,
      amountE,
      publicKeyB,
      saltAliceToBobE,
    );
    commitmentAliceF = utils.concatenateThenHash(
      erc20AddressPadded,
      amountF,
      publicKeyA,
      saltAliceToAliceF,
    );
  });

  // eslint-disable-next-line no-undef
  describe('f-token-controller.js tests', () => {
    // Alice has C + D to start total = 50 ETH
    // Alice sends Bob E and gets F back (Bob has 40 ETH, Alice has 10 ETH)
    // Bob then has E+G at total of 70 ETH
    // Bob sends H to Alice and keeps I (Bob has 50 ETH and Alice has 10+20=30 ETH)
    test('Should create 10000 tokens in accounts[0] and accounts[1]', async () => {
      // fund some accounts with FToken
      const AMOUNT = 10000;
      const bal1 = await controller.getBalance(accounts[0]);
      await controller.buyFToken(AMOUNT, accounts[0]);
      await controller.buyFToken(AMOUNT, accounts[1]);
      const bal2 = await controller.getBalance(accounts[0]);
      expect(AMOUNT).toEqual(bal2 - bal1);
    });

    test('Should move 1 ERC-20 token from accounts[0] to accounts[1]', async () => {
      const AMOUNT = 1;
      const bal1 = await controller.getBalance(accounts[0]);
      const bal3 = await controller.getBalance(accounts[1]);
      await controller.transferFToken(AMOUNT, accounts[0], accounts[1]);
      const bal2 = await controller.getBalance(accounts[0]);
      const bal4 = await controller.getBalance(accounts[1]);
      expect(AMOUNT).toEqual(bal1 - bal2);
      expect(AMOUNT).toEqual(bal4 - bal3);
    });

    test('Should burn 1 ERC-20 from accounts[1]', async () => {
      const AMOUNT = 1;
      const bal1 = await controller.getBalance(accounts[1]);
      await controller.burnFToken(AMOUNT, accounts[1]);
      const bal2 = await controller.getBalance(accounts[1]);
      expect(AMOUNT).toEqual(bal1 - bal2);
    });

    test('Should get the ERC-20 metadata', async () => {
      const { symbol, name } = await controller.getTokenInfo(accounts[0]);
      expect('OPS').toEqual(symbol);
      expect('EY OpsCoin').toEqual(name);
    });


    // todo 测试 ftoken mint
    test('Should mint an ERC-20 commitment Z_A_C for Alice for asset C', async () => {
      console.log('Alices account ', (await controller.getBalance(accounts[0])).toNumber());


      // Alice 发起 mint,

      const { commitment: zTest, commitmentIndex: zIndex } = await erc20.mint(

        // 本次 mint 的token金额
        amountC,
        // Alice 的公钥
        publicKeyA,

        // Alice 的 salt
        saltAliceC,
        {

          // ERC20 token 合约地址
          erc20Address,
          //
          account: accounts[0],
          fTokenShieldJson,
          fTokenShieldAddress,
        },
        {
          codePath: `${process.cwd()}/code/gm17/ft-mint/out`,
          outputDirectory: `${process.cwd()}/code/gm17/ft-mint`,
          pkPath: `${process.cwd()}/code/gm17/ft-mint/proving.key`,
        },
      );
      zInd1 = parseInt(zIndex, 10);
      expect(commitmentAliceC).toEqual(zTest);
      console.log(`Alice's account `, (await controller.getBalance(accounts[0])).toNumber());
    });

    test('Should mint another ERC-20 commitment Z_A_D for Alice for asset D', async () => {
      const { commitment: zTest, commitmentIndex: zIndex } = await erc20.mint(
        amountD,

        // Alice 的公钥 (加密世界用)
        publicKeyA,
        saltAliceD,
        {
          erc20Address,
          account: accounts[0],
          fTokenShieldJson,
          fTokenShieldAddress,
        },
        {
          codePath: `${process.cwd()}/code/gm17/ft-mint/out`,
          outputDirectory: `${process.cwd()}/code/gm17/ft-mint`,
          pkPath: `${process.cwd()}/code/gm17/ft-mint/proving.key`,
        },
      );
      zInd2 = parseInt(zIndex, 10);
      expect(commitmentAliceD).toEqual(zTest);
      console.log(`Alice's account `, (await controller.getBalance(accounts[0])).toNumber());
    });

    test('Should transfer a ERC-20 commitment to Bob (two coins get nullified, two created; one coin goes to Bob, the other goes back to Alice as change)', async () => {
      // E becomes Bob's, F is change returned to Alice

      // Alice 转 一部分 加密币 给 Bob

      // 产生 两个 commitment (E、F), 使用 之前Alice 两次 mint 的 commitment C和D 生成两个 nullifier C和D
      // 然后, 目标是生成两个 新的 commitment E和F
      const inputCommitments = [
        { value: amountC, salt: saltAliceC, commitment: commitmentAliceC, commitmentIndex: zInd1 },
        { value: amountD, salt: saltAliceD, commitment: commitmentAliceD, commitmentIndex: zInd2 },
      ];
      const outputCommitments = [
        { value: amountE, salt: saltAliceToBobE },
        { value: amountF, salt: saltAliceToAliceF },
      ];
      await erc20.transfer(
        inputCommitments,
        outputCommitments,
        publicKeyB,
        secretKeyA,
        {
          erc20Address,
          account: accounts[0],
          fTokenShieldJson,
          fTokenShieldAddress,
        },
        {
          codePath: `${process.cwd()}/code/gm17/ft-transfer/out`,
          outputDirectory: `${process.cwd()}/code/gm17/ft-transfer`,
          pkPath: `${process.cwd()}/code/gm17/ft-transfer/proving.key`,
        },
      );
      // now Bob should have 40 (E) ETH
    });

    test('Should mint another ERC-20 commitment Z_B_G for Bob for asset G', async () => {
      const { commitment: zTest, commitmentIndex: zIndex } = await erc20.mint(
        amountG,
        publicKeyB,
        saltBobG,
        {
          erc20Address,
          account: accounts[1],
          fTokenShieldJson,
          fTokenShieldAddress,
        },
        {
          codePath: `${process.cwd()}/code/gm17/ft-mint/out`,
          outputDirectory: `${process.cwd()}/code/gm17/ft-mint`,
          pkPath: `${process.cwd()}/code/gm17/ft-mint/proving.key`,
        },
      );
      zInd3 = parseInt(zIndex, 10);
      expect(commitmentBobG).toEqual(zTest);
    });

    test('Should transfer an ERC-20 commitment to Eve', async () => {
      // H becomes Eve's, I is change returned to Bob
      const inputCommitments = [
        {
          value: amountE,
          salt: saltAliceToBobE,
          commitment: commitmentBobE,
          commitmentIndex: zInd1 + 2,
        },
        { value: amountG, salt: saltBobG, commitment: commitmentBobG, commitmentIndex: zInd3 },
      ];
      const outputCommitments = [
        { value: amountH, salt: saltBobToEveH },
        { value: amountI, salt: saltBobToBobI },
      ];

      await erc20.transfer(
        inputCommitments,
        outputCommitments,
        publicKeyE,
        secretKeyB,
        {
          erc20Address,
          account: accounts[1],
          fTokenShieldJson,
          fTokenShieldAddress,
        },
        {
          codePath: `${process.cwd()}/code/gm17/ft-transfer/out`,
          outputDirectory: `${process.cwd()}/code/gm17/ft-transfer`,
          pkPath: `${process.cwd()}/code/gm17/ft-transfer/proving.key`,
        },
      );
    });

    test(`Should burn Alice's remaining ERC-20 commitment`, async () => {
      const bal1 = await controller.getBalance(accounts[3]);
      const bal = await controller.getBalance(accounts[0]);
      console.log('accounts[3]', bal1.toNumber());
      console.log('accounts[0]', bal.toNumber());
      await erc20.burn(
        amountF,
        secretKeyA,
        saltAliceToAliceF,
        commitmentAliceF,
        zInd2 + 2,
        {
          erc20Address,
          account: accounts[0],
          tokenReceiver: accounts[3],
          fTokenShieldJson,
          fTokenShieldAddress,
        },
        {
          codePath: `${process.cwd()}/code/gm17/ft-burn/out`,
          outputDirectory: `${process.cwd()}/code/gm17/ft-burn`,
          pkPath: `${process.cwd()}/code/gm17/ft-burn/proving.key`,
        },
      );
      const bal2 = await controller.getBalance(accounts[3]);
      console.log('accounts[3]', bal2.toNumber());
      expect(parseInt(amountF, 16)).toEqual(bal2 - bal1);
    });
  });
} else {
  describe('Conventional fungible tests disabled', () => {
    test('COMPLIANCE env variable is set to `true`', () => {
      expect(process.env.COMPLIANCE).toEqual('true');
    });
  });
}
