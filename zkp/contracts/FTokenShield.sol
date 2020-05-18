/**
Contract to enable the management of private fungible token (ERC-20) transactions using zk-SNARKs.
@Author Westlad, Chaitanya-Konda, iAmMichaelConnor
*/

pragma solidity ^0.5.8;

import "./Ownable.sol";
import "./MerkleTree.sol";
import "./Verifier_Interface.sol";
import "./ERC20Interface.sol";
import "./PublicKeyTree.sol";

// TODO Fungible Tokens (FToken)
//
// TODO ERC20 对应的隐私交易合约，管理所有隐私交易信息
//
// Nightfall中的六个主要子协议为以下：
//
//      Mint ERC-20 Token Commitment ERC20铸币承兑协议
//      Transfer ERC-20 Token Commitment ERC20转移承兑协议
//      Burn ERC-20 Token Commitment ERC20销毁承兑协议
//      Mint ERC-721 Token Commitment ERC721铸币承兑协议
//      Transfer ERC-721 Token Commitment ERC721转移承兑协议
//      Burn ERC-721 Token Commitment ERC721销毁承兑协议
//
// TODO 6中操作： ft-mint , ft-transfer , ft-burn , nft-mint , nft-transfer , nft-burn

contract FTokenShield is Ownable, MerkleTree, PublicKeyTree {
    // ENUMS:
    enum TransactionTypes {
        Mint,                       // 铸币
        Transfer,                   // 转账
        Burn,                       // 提币
        SimpleBatchTransfer,        // 批转账
        ConsolidationTransfer,      // 保密转账
        MintRC,                     // todo 没用?
        TransferRC,                 // todo 没用?
        BurnRC                      // todo 没用?
    }

    // EVENTS:
    // Observers may wish to listen for nullification of commitments:
    event Transfer(bytes32 nullifier1, bytes32 nullifier2);
    event TransferRC(bytes32[] publicInputs);
    event SimpleBatchTransfer(bytes32 nullifier);
    event ConsolidationTransfer(bytes32[] nullifiers);
    event Burn(bytes32 nullifier);
    event BurnRC(bytes32[] publicInputs);

    // Observers may wish to listen for zkSNARK-related changes:
    event VerifierChanged(address newVerifierContract);
    event VkChanged(TransactionTypes txType);

    // For testing only. This SHOULD be deleted before mainnet deployment:
    // 仅用于测试。 在主网部署之前，应删除此文件：
    event GasUsed(uint256 byShieldContract, uint256 byVerifierContract);

    // CONTRACT INSTANCES:
    // 零知识证明的 校验合约
    Verifier_Interface private verifier; // the verification smart contract

    // PRIVATE TRANSACTIONS' PUBLIC STATES:
    // 私人交易的公开状态：

    // 存储已用承诺的取消符 (nullifier)
    mapping(bytes32 => bytes32) public nullifiers; // store nullifiers of spent commitments
    // 保留我们计算出的每个根，以便我们可以提取与证明者相关的根
    //
    // todo (root => root) 沃日,为什么要这么放
    mapping(bytes32 => bytes32) public roots; // holds each root we've calculated so that we can pull the one relevant to the prover

    // TODO 存储 verification Key (用于生成 proof)
    //
    // 映射到枚举 (uint => TransactionTypes)
    mapping(uint => uint256[]) public vks; // mapped to by an enum uint(TransactionTypes):
    // 持有最新 root 目录的索引，以便证明方可以在以后提供它，并且此合同可以查找相关的 root目录
    bytes32 public latestRoot; // holds the index for the latest root so that the prover can provide it later and this contract can look up the relevant root

    // FUNCTIONS:
    constructor(address _verifier) public {
        // 在初始化时, 需要指定 零知识证明合约
        _owner = msg.sender;
        verifier = Verifier_Interface(_verifier);
    }

    /**
    self destruct
    */
    function close() external onlyOwner {
        selfdestruct(address(uint160(_owner)));
    }

    /**
    function to change the address of the underlying Verifier contract
    */
    // 更换 零知识证明验证合约
    function changeVerifier(address _verifier) external onlyOwner {
        verifier = Verifier_Interface(_verifier);
        emit VerifierChanged(_verifier);
    }

    /**
    returns the verifier-interface contract address that this shield contract is calling
    */
    // 获取零知识验证合约地址
    function getVerifier() public view returns (address) {
        return address(verifier);
    }

    /**
    Stores verification keys (for the 'mint', 'transfer' and 'burn' computations).
    */
    // 存储验证密钥 (用于 'mint', 'transfer' 和 'burn' 计算)
    // TODO verification Key 用来生成 proof ??
    function registerVerificationKey(uint256[] calldata _vk, TransactionTypes _txType) external onlyOwner {
        // CAUTION: we do not prevent overwrites of vk's. Users must listen for the emitted event to detect updates to a vk.
        // 注意：我们不防止覆盖vk。 用户必须侦听发出的事件以检测对vk的更新。
        vks[uint(_txType)] = _vk;

        // 记录 变动 vk 事件, 让外部用户自己去监听 回执, 再去做业务操作
        emit VkChanged(_txType);
    }

    /**
    The mint function accepts fungible tokens from the specified fToken ERC-20 contract and creates the same amount as a commitment.
    */
    // TODO ERC20铸币承兑协议
    // mint函数从指定的 fToken ERC-20合同接受可替代的令牌，并创建与承诺 (commitment) 相同的金额。
    function mint(
        bytes32 tokenContractAddress, // ERC20 token 合约地址, 使用 bytes32接收.  Take in as bytes32 for consistent hashing
        uint256[] calldata _proof,    // proof
        uint256[] calldata _inputs,   // 输入
        uint128 _value,               // 铸币的token数目 ?
        bytes32 _commitment           // 承诺
    ) external {
        // gas measurement:
        // gas 测量
        uint256 gasCheckpoint = gasleft(); // todo gasleft(), solidity的内置函数, 获取当前tx到目前为止剩余的gas

        // Check that the publicInputHash equals the hash of the 'public inputs':
        //
        // 检查 publicInputHash 是否等于 'public inputs' 的哈希:
        //
        bytes31 publicInputHash = bytes31(bytes32(_inputs[0]) << 8);
        bytes31 publicInputHashCheck = bytes31(sha256(abi.encodePacked(tokenContractAddress, uint128(_value), _commitment)) << 8);
        // Note that we force the _value to be left-padded with zeros to fill 128-bits, so as to match the padding in the hash calculation performed within the zokrates proof.
        // 请注意，我们强制_value左填充零以填充128位，以便匹配在zokrates证明内执行的哈希计算中的填充。
        require(publicInputHashCheck == publicInputHash, "publicInputHash cannot be reconciled");

        // gas measurement:
        // gas 测量
        uint256 gasUsedByShieldContract = gasCheckpoint - gasleft();
        gasCheckpoint = gasleft();

        // verify the proof
        //
        // 校验 零知识证明
        bool result = verifier.verify(_proof, _inputs, vks[uint(TransactionTypes.Mint)]);
        require(result, "The proof has not been verified by the contract");

        // gas measurement:
        uint256 gasUsedByVerifierContract = gasCheckpoint - gasleft();
        gasCheckpoint = gasleft();

        // update contract states
        //
        // 将当前 commitment 插入 merkle tree 中
        //
        // 将 最新的root 记录在当前合约的 latestRoot 字段
        latestRoot = insertLeaf(_commitment);

        // recalculate the root of the merkleTree as it's now different
        //
        // 将新的 root 存入 roots集
        roots[latestRoot] = latestRoot;
        // and save the new root to the list of roots

        // Finally, transfer the fTokens from the sender to this contract
        // 最后, 将 fToken 转移到当前 合约中

        // Need to cast from bytes32 to address.
        //
        // 将存储在 32位tokenContractAddress变量的 addr内容转换成 address
        ERC20Interface tokenContract = ERC20Interface(address(uint160(uint256(tokenContractAddress))));

        // 当前合约 代替 ERC20 token 合约将token 转入当前合约中
        bool transferCheck = tokenContract.transferFrom(msg.sender, address(this), _value);
        require(transferCheck, "Commitment cannot be minted");

        // gas measurement:
        gasUsedByShieldContract = gasUsedByShieldContract + gasCheckpoint - gasleft();
        emit GasUsed(gasUsedByShieldContract, gasUsedByVerifierContract);
    }

    /**
    The transfer function transfers a commitment to a new owner
    */
    // TODO ERC20转移承兑协议
    // transfer: 转移功能将 commitment 转移给新所有者
    //
    // TODO 看得出来, 资产转移 是需要两个 输入的 (nullifierC, commitmentE) 和 (nulliferD, commitmentF)
    function transfer(
        uint256[] calldata _proof,  // proof
        uint256[] calldata _inputs, // inputs
        bytes32 _root,              // merkle tree 的 root
        bytes32 _nullifierC,        // 第一个输入
        bytes32 _nullifierD,        // 第二个输入
        bytes32 _commitmentE,       // 第一输入的commitment
        bytes32 _commitmentF        // 第二输入的commitment
    ) external {

        // gas measurement: 做测试用的代码
        uint256[3] memory gasUsed;
        // array needed to stay below local stack limit
        gasUsed[0] = gasleft();

        // Check that the publicInputHash equals the hash of the 'public inputs':
        //
        // 检查 publicInputHash 是否等于 'public inputs' 的哈希:
        //
        bytes31 publicInputHash = bytes31(bytes32(_inputs[0]) << 8);
        bytes31 publicInputHashCheck = bytes31(sha256(abi.encodePacked(_root, _nullifierC, _nullifierD, _commitmentE, _commitmentF)) << 8);
        require(publicInputHashCheck == publicInputHash, "publicInputHash cannot be reconciled");

        // gas measurement:
        gasUsed[1] = gasUsed[0] - gasleft();
        gasUsed[0] = gasleft();

        // verify the proof
        //
        // 对proof 进行校验
        bool result = verifier.verify(_proof, _inputs, vks[uint(TransactionTypes.Transfer)]);
        require(result, "The proof has not been verified by the contract");

        // gas measurement:
        gasUsed[2] = gasUsed[0] - gasleft();
        gasUsed[0] = gasleft();

        // check inputs vs on-chain states
        require(roots[_root] == _root, "The input root has never been the root of the Merkle Tree");

        // 校验 两个输入必须不相等
        require(_nullifierC != _nullifierD, "The two input nullifiers must be different!");
        require(_commitmentE != _commitmentF, "The new commitments (commitmentE and commitmentF) must be different!");
        require(nullifiers[_nullifierC] == 0, "The commitment being spent (commitmentE) has already been nullified!");
        require(nullifiers[_nullifierD] == 0, "The commitment being spent (commitmentF) has already been nullified!");

        // 记录已经花费的 nullifierC 和 _nullifierD

        // update contract states
        nullifiers[_nullifierC] = _nullifierC;
        //remember we spent it
        nullifiers[_nullifierD] = _nullifierD;
        //remember we spent it

        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = _commitmentE;
        leaves[1] = _commitmentF;

        // 同时向 merkle tree 插入两个 叶子
        //
        // 记录最后最新的 root
        latestRoot = insertLeaves(leaves);

        // recalculate the root of the merkleTree as it's now different

        // 就最新的 root
        roots[latestRoot] = latestRoot;
        // and save the new root to the list of roots

        emit Transfer(_nullifierC, _nullifierD);

        // gas measurement:
        gasUsed[1] = gasUsed[1] + gasUsed[0] - gasleft();
        emit GasUsed(gasUsed[1], gasUsed[2]);
    }

    /**
    The transfer function transfers 20 commitments to new owners
    */
    // (消费单个 未花费输出) 批量给多个账户转移 token
    //
    // 最多只能发起 20 个  commitment
    //
    function simpleBatchTransfer(
        uint256[] calldata _proof,          // 证明
        uint256[] calldata _inputs,         // 输入
        bytes32 _root,                      // merkle tree root
        bytes32 _nullifier,                 // 某个未花费输出对应的 nullifier
        bytes32[] calldata _commitments     // 多个 commitment
    ) external {

        // gas measurement:
        uint256 gasCheckpoint = gasleft();

        // Check that the publicInputHash equals the hash of the 'public inputs':
        bytes31 publicInputHash = bytes31(bytes32(_inputs[0]) << 8);
        bytes31 publicInputHashCheck = bytes31(sha256(abi.encodePacked(_root, _nullifier, _commitments)) << 8);
        require(publicInputHashCheck == publicInputHash, "publicInputHash cannot be reconciled");

        // gas measurement:
        uint256 gasUsedByShieldContract = gasCheckpoint - gasleft();
        gasCheckpoint = gasleft();

        // verify the proof
        //
        // 校验证明
        bool result = verifier.verify(_proof, _inputs, vks[uint(TransactionTypes.SimpleBatchTransfer)]);
        require(result, "The proof has not been verified by the contract");

        // gas measurement:
        uint256 gasUsedByVerifierContract = gasCheckpoint - gasleft();
        gasCheckpoint = gasleft();

        // 校验 root、 校验 nullifier
        //
        // check inputs vs on-chain states
        require(roots[_root] == _root, "The input root has never been the root of the Merkle Tree");
        require(nullifiers[_nullifier] == 0, "The commitment being spent has already been nullified!");

        // 花费掉 nullifier
        //
        // update contract states
        nullifiers[_nullifier] = _nullifier;
        //remember we spent it


        // 将多个 commitment 插入 merkle tree
        //
        // 记录 最新的 root
        latestRoot = insertLeaves(_commitments);
        roots[latestRoot] = latestRoot;
        //and save the new root to the list of roots

        emit SimpleBatchTransfer(_nullifier);

        // gas measurement:
        gasUsedByShieldContract = gasUsedByShieldContract + gasCheckpoint - gasleft();
        emit GasUsed(gasUsedByShieldContract, gasUsedByVerifierContract);
    }

    /**
    This transfer function transfers 20 commitments to a new owner
    */
    // 保密转移 commitment, 最多可以转移 20个
    //
    // todo 和 simpleBatchTransfer() 配对看, 就明白了
    function consolidationTransfer(
        uint256[] calldata _proof,
        uint256[] calldata _inputs,
        bytes32 _root,
        bytes32[] calldata _nullifiers,
        bytes32 _commitment
    ) external {

        // gas measurement:
        uint256 gasCheckpoint = gasleft();

        // Check that the publicInputHash equals the hash of the 'public inputs':
        // bytes31 publicInputHash = bytes31(bytes32(_inputs[0]) << 8);
        bytes31 publicInputHashCheck = bytes31(sha256(abi.encodePacked(_root, _nullifiers, _commitment)) << 8);
        require(publicInputHashCheck == bytes31(bytes32(_inputs[0]) << 8), "publicInputHash cannot be reconciled");

        // gas measurement:
        uint256 gasUsedByShieldContract = gasCheckpoint - gasleft();
        gasCheckpoint = gasleft();

        // 校验 proof
        //
        // verify the proof
        bool result = verifier.verify(_proof, _inputs, vks[uint(TransactionTypes.ConsolidationTransfer)]);
        require(result, "The proof has not been verified by the contract");

        // gas measurement:
        uint256 gasUsedByVerifierContract = gasCheckpoint - gasleft();
        gasCheckpoint = gasleft();

        // 校验 root
        //
        // check inputs vs on-chain states
        require(roots[_root] == _root, "The input root has never been the root of the Merkle Tree");

        // 逐个 花费 old commitments (逐个记录commitment对应的 nullifiers)
        for (uint i = 0; i < _nullifiers.length; i++) {
            require(nullifiers[_nullifiers[i]] == 0, "The commitment being spent has already been nullified!");
            nullifiers[_nullifiers[i]] = _nullifiers[i];
            //remember we spent it
        }


        // 将当前本次 tx的 commitment 插入 merkle tree
        // 记录最新的 root
        latestRoot = insertLeaf(_commitment);
        roots[latestRoot] = latestRoot;
        //and save the new root to the list of roots

        emit ConsolidationTransfer(_nullifiers);

        // gas measurement:
        gasUsedByShieldContract = gasUsedByShieldContract + gasCheckpoint - gasleft();
        emit GasUsed(gasUsedByShieldContract, gasUsedByVerifierContract);
    }

    // TODO ERC20销毁承兑协议
    //
    // tokenContractAddress: ERC20 token 合约地址
    // _proof: proof数据
    // _inputs: input数据
    // _root: root
    // _nullifier: 对应的 nullifier
    // _value: 本次提款的 金额
    // _payTo: 提款提给谁
    //
    function burn(
        bytes32 tokenContractAddress,
        uint256[] calldata _proof,
        uint256[] calldata _inputs,
        bytes32 _root,
        bytes32 _nullifier,
        uint128 _value,
        uint256 _payTo
    ) external {

        // gas measurement:
        uint256 gasCheckpoint = gasleft();

        // Check that the publicInputHash equals the hash of the 'public inputs':
        bytes31 publicInputHash = bytes31(bytes32(_inputs[0]) << 8);
        bytes31 publicInputHashCheck = bytes31(sha256(abi.encodePacked(tokenContractAddress, _root, _nullifier, uint128(_value), _payTo)) << 8);
        // Note that although _payTo represents an address, we have declared it as a uint256. This is because we want it to be abi-encoded as a bytes32 (left-padded with zeros) so as to match the padding in the hash calculation performed within the zokrates proof. Similarly, we force the _value to be left-padded with zeros to fill 128-bits.
        require(publicInputHashCheck == publicInputHash, "publicInputHash cannot be reconciled");

        // gas measurement:
        uint256 gasUsedByShieldContract = gasCheckpoint - gasleft();
        gasCheckpoint = gasleft();


        // 校验 proof
        // verify the proof
        bool result = verifier.verify(_proof, _inputs, vks[uint(TransactionTypes.Burn)]);
        require(result, "The proof has not been verified by the contract");

        // gas measurement:
        uint256 gasUsedByVerifierContract = gasCheckpoint - gasleft();
        gasCheckpoint = gasleft();

        // check inputs vs on-chain states
        require(roots[_root] == _root, "The input root has never been the root of the Merkle Tree");
        require(nullifiers[_nullifier] == 0, "The commitment being spent has already been nullified!");


        // 花费掉 nullifer
        nullifiers[_nullifier] = _nullifier;
        // add the nullifier to the list of nullifiers


        // 从当前合约中将 ERC20 token 转移到对应地址 payTo 中, 提取的金额为 value
        // Need to cast from bytes32 to address.
        ERC20Interface tokenContract = ERC20Interface(address(uint160(uint256(tokenContractAddress))));
        bool transferCheck = tokenContract.transfer(address(_payTo), _value);
        require(transferCheck, "Commitment cannot be burned");

        emit Burn(_nullifier);

        // gas measurement:
        gasUsedByShieldContract = gasUsedByShieldContract + gasCheckpoint - gasleft();
        emit GasUsed(gasUsedByShieldContract, gasUsedByVerifierContract);
    }

    /**
    The mint function accepts fungible tokens from the specified fToken ERC-20 contract and creates the same amount as a commitment.
    */
    //
    // TODO 和 mint 只相差一个 函数修饰器 onlyCheckedUser()
    function mintRC(
        bytes32 tokenContractAddress, // Take in as bytes32 for consistent hashing  接受为bytes32以实现一致的哈希
        uint256[] calldata _proof,    // proof数据
        uint256[] calldata _inputs,   // input数据
        uint128 _value,               // 铸币的 token数目
        bytes32 _commitment,          // 承诺
        bytes32 zkpPublicKey
    )
    external onlyCheckedUser(zkpPublicKey) /* onlyCheckedUser()中做了 publicKey的去重和索引merkle tree 的更新 */ {

        // gas measurement:
        uint256 gasCheckpoint = gasleft();

        // Check that the publicInputHash equals the hash of the 'public inputs':
        bytes31 publicInputHash = bytes31(bytes32(_inputs[0]) << 8);
        bytes31 publicInputHashCheck = bytes31(sha256(abi.encodePacked(tokenContractAddress, uint128(_value), _commitment, zkpPublicKey)) << 8);
        // Note that we force the _value to be left-padded with zeros to fill 128-bits, so as to match the padding in the hash calculation performed within the zokrates proof.
        require(publicInputHashCheck == publicInputHash, "publicInputHash cannot be reconciled");

        // gas measurement:
        uint256 gasUsedByShieldContract = gasCheckpoint - gasleft();
        gasCheckpoint = gasleft();

        // verify the proof
        //
        // 校验 _proof
        bool result = verifier.verify(_proof, _inputs, vks[uint(TransactionTypes.Mint)]);
        require(result, "The proof has not been verified by the contract");

        // gas measurement:
        uint256 gasUsedByVerifierContract = gasCheckpoint - gasleft();
        gasCheckpoint = gasleft();

        // update contract states
        //
        // 将当前 commitment 插入 merkle tree 中
        //
        // 将 最新的root 记录在当前合约的 latestRoot 字段
        latestRoot = insertLeaf(_commitment);

        // recalculate the root of the merkleTree as it's now different
        //
        // 将最新的 root 进行存储
        roots[latestRoot] = latestRoot;
        // and save the new root to the list of roots

        // Finally, transfer the fTokens from the sender to this contract
        // Need to cast from bytes32 to address.
        ERC20Interface tokenContract = ERC20Interface(address(uint160(uint256(tokenContractAddress))));
        bool transferCheck = tokenContract.transferFrom(msg.sender, address(this), _value);
        require(transferCheck, "Commitment cannot be minted");

        // gas measurement:
        gasUsedByShieldContract = gasUsedByShieldContract + gasCheckpoint - gasleft();
        emit GasUsed(gasUsedByShieldContract, gasUsedByVerifierContract);
    }

    /**
    The transfer function transfers a commitment to a new owner
    */
    // TODO 和 transfer 的区别是, 将多余的信息都聚合到 publicInputs 中了 (里头有 Elgamal相关的东西)
    function transferRC(
        uint256[] calldata _proof,  // proof信息
        uint256[] calldata _inputs, // 输入信息
        bytes32[] calldata publicInputs // 一串很复杂的复合信息, 函数里面有说
    ) external {

        // gas measurement:
        uint256[3] memory gasUsed;
        // array needed to stay below local stack limit
        gasUsed[0] = gasleft();

        // Check that the publicInputHash equals the hash of the 'public inputs':
        bytes31 publicInputHash = bytes31(bytes32(_inputs[0]) << 8);
        bytes31 publicInputHashCheck = bytes31(sha256(abi.encodePacked(publicInputs)) << 8);
        require(publicInputHashCheck == publicInputHash, "publicInputHash cannot be reconciled");

        // gas measurement:
        gasUsed[1] = gasUsed[0] - gasleft();
        gasUsed[0] = gasleft();

        // verify the proof
        //
        // 校验 _proof
        bool result = verifier.verify(_proof, _inputs, vks[uint(TransactionTypes.Transfer)]);
        require(result, "The proof has not been verified by the contract");

        // gas measurement:
        gasUsed[2] = gasUsed[0] - gasleft();
        gasUsed[0] = gasleft();

        // TODO - need to enforce correct public keys!!
        // Unfortunately stack depth constraints mandate an array, so we can't use more friendly names.
        // However, here's a handy guide:
        // publicInputs[0] - root (of the commitment Merkle tree)
        // publicInputs[1] - nullifierC
        // publicInputs[2] - nullifierD
        // publicInputs[3] - commitmentE
        // publicInputs[4] - commitmentF
        // publicInputs[5] - root (of public key Merkle tree)
        // publicInputs[6..] - elGamal

        /*
         * TODO 需要执行正确的公共密钥！
         * 不幸的是，堆栈深度约束要求使用数组，因此我们不能使用更友好的名称 ?? 啥啊? 想说的啥啊?
         * 但是，这是一个方便的指南:
         *
         * publicInputs[0] - root (of the commitment Merkle tree), commitment merkle tree 的 root
         * publicInputs[1] - nullifierC
         * publicInputs[2] - nullifierD
         * publicInputs[3] - commitmentE
         * publicInputs[4] - commitmentF
         * publicInputs[5] - root (of public key Merkle tree), publicKey merkle tree 的 root
         * publicInputs[6..] - elGamal, 其实 6-9 都是Elgamal 加密算法相关信息, 而 10 -12 则是 三个 管理员账户的公钥信息
         */

        // 各种校验数据
        //
        // check inputs vs on-chain states
        require(roots[publicInputs[0]] == publicInputs[0], "The input root has never been the root of the Merkle Tree");
        require(publicInputs[1] != publicInputs[2], "The two input nullifiers must be different!");
        require(publicInputs[3] != publicInputs[4], "The new commitments (commitmentE and commitmentF) must be different!");
        require(nullifiers[publicInputs[1]] == 0, "The commitment being spent (commitmentE) has already been nullified!");
        require(nullifiers[publicInputs[2]] == 0, "The commitment being spent (commitmentF) has already been nullified!");
        require(publicKeyRoots[publicInputs[5]] != 0, "The input public key root has never been a root of the Merkle Tree");
        require(publicInputs[10] == compressedAdminPublicKeys[0], 'Admin public key 0 does not match');
        require(publicInputs[11] == compressedAdminPublicKeys[1], 'Admin public key 1 does not match');
        require(publicInputs[12] == compressedAdminPublicKeys[2], 'Admin public key 2 does not match');

        // 记录已花费的nullifier

        // update contract states
        nullifiers[publicInputs[1]] = publicInputs[1];
        //remember we spent it
        nullifiers[publicInputs[2]] = publicInputs[2];
        //remember we spent it


        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = publicInputs[3];
        leaves[1] = publicInputs[4];

        // 同时往 commitment merkle tree 上插入 commitmentE 和 commitmentF
        // 并计算最新的 root
        latestRoot = insertLeaves(leaves);

        // recalculate the root of the merkleTree as it's now different
        //
        // 记录最新的 root
        roots[latestRoot] = latestRoot;
        // and save the new root to the list of roots

        emit TransferRC(publicInputs);

        // gas measurement:
        gasUsed[1] = gasUsed[1] + gasUsed[0] - gasleft();
        emit GasUsed(gasUsed[1], gasUsed[2]);
    }

    // TODO 和 burn 只是差别了 将 杂七杂八的加入 publicInputs中 (里头有 Elgamal相关的东西)
    //
    function burnRC(
        uint256[] calldata _proof,
        uint256[] calldata _inputs,
        bytes32[] calldata publicInputs
    ) external {

        // gas measurement:
        uint256 gasCheckpoint = gasleft();

        // Check that the publicInputHash equals the hash of the 'public inputs':
        bytes31 publicInputHash = bytes31(bytes32(_inputs[0]) << 8);
        // This line can be made neater when we can use pragma 0.6.0 and array slices
        bytes31 publicInputHashCheck = bytes31(sha256(abi.encodePacked(publicInputs)) << 8);
        // Note that although _payTo represents an address, we have declared it as a uint256. This is because we want it to be abi-encoded as a bytes32 (left-padded with zeros) so as to match the padding in the hash calculation performed within the zokrates proof. Similarly, we force the _value to be left-padded with zeros to fill 128-bits.
        require(publicInputHashCheck == publicInputHash, "publicInputHash cannot be reconciled");

        // gas measurement:
        uint256 gasUsedByShieldContract = gasCheckpoint - gasleft();
        gasCheckpoint = gasleft();

        // verify the proof
        //
        // 校验 proof
        bool result = verifier.verify(_proof, _inputs, vks[uint(TransactionTypes.Burn)]);
        require(result, "The proof has not been verified by the contract");

        // gas measurement:
        uint256 gasUsedByVerifierContract = gasCheckpoint - gasleft();
        gasCheckpoint = gasleft();

        // Unfortunately stack depth constraints mandate an array, so we can't use more friendly names.
        // publicInputs[0] - tokenContractAddress (left-padded with 0s)
        // publicInputs[1] - root (of the commitment Merkle tree)
        // publicInputs[2] - nullifier
        // publicInputs[3] - value
        // publicInputs[4] - payTo address
        // publicInputs[5] - root (of public key Merkle tree)
        // publicInputs[6:12] - elGamal (6 elements)

        /*
         * publicInputs[0] - tokenContractAddress (left-padded with 0s) 左填充0的bytes32  合约地址
         * publicInputs[1] - root (of the commitment Merkle tree)  commitment merkle tree 的 root
         * publicInputs[2] - nullifier  提款的 nullifier
         * publicInputs[3] - value      需要提取的 value数额
         * publicInputs[4] - payTo address  收款地址
         * publicInputs[5] - root (of public key Merkle tree)  publicKey merkle tree 的 root
         * publicInputs[6:12] - elGamal (6 elements) Elgamal 相关?? 6个元素 ?
         */

        // 校验各种数据

        // check inputs vs on-chain states
        require(roots[publicInputs[1]] == publicInputs[1], "The input root has never been the root of the Merkle Tree");
        require(nullifiers[publicInputs[2]] == 0, "The commitment being spent has already been nullified!");
        require(publicKeyRoots[publicInputs[5]] != 0, "The input public key root has never been a root of the Merkle Tree");
        require(publicInputs[8] == compressedAdminPublicKeys[0], 'Admin public key 0 does not match');

        // 花费掉对应的 nullifier
        nullifiers[publicInputs[2]] = publicInputs[2];
        // add the nullifier to the list of nullifiers

        // Need to cast from bytes32 to address.
        ERC20Interface tokenContract = ERC20Interface(address(uint160(uint256(publicInputs[0]))));
        bool transferCheck = tokenContract.transfer(address(uint256(publicInputs[4])), uint256(publicInputs[3]));
        require(transferCheck, "Commitment cannot be burned");

        emit BurnRC(publicInputs);

        // gas measurement:
        gasUsedByShieldContract = gasUsedByShieldContract + gasCheckpoint - gasleft();
        emit GasUsed(gasUsedByShieldContract, gasUsedByVerifierContract);
    }
}
