
pragma solidity ^0.5.8;

import "./MiMC.sol";
import "./Ownable.sol";


// 公钥 tree 合约 ??
contract PublicKeyTree is MiMC, Ownable {

  // 在这里，我们定义高度，以便仅由根组成的树的高度为0
  uint256 internal constant TREE_HEIGHT = 32; // here we define height so that a tree consisting of just a root would have a height of 0

  // 这是节点索引（从根数= 0开始）和叶子索引（从左数的第一个叶子开始编号= 0）之间的差
  //
  // 2^32 -1
  uint256 internal constant FIRST_LEAF_INDEX = 2**(TREE_HEIGHT) - 1; //this is the difference between a node index (numbered from the root=0) and a leaf index (numbered from the first leaf on the left=0)


  // 这个只是为了计算 publicKey的简化值的一个 系数
  uint256 private constant q = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

  // TODO M 和 L 的内容是反着来的
  // TODO M 为: (index => publicKey)
  // TODO L 为: (publicKey => index)

  // TODO 其实是将 merkle tree 节点对应的元数据 存在 M 中
  // TODO 但是 merkle tree 是节点的索引形成的

  // 存储 merkle tree 节点
  mapping (uint256 => bytes32) public M; //storage for the Merkle Tree nodes

  // 查找叶子索引
  mapping (bytes32 => uint256) public L; // lookup for a leaf index

  // 如果您知道ETH地址，则存储zkp公钥的查找
  // (address => zkpPublicKey)
  // todo 这里的数据是不会删除的
  mapping (address => bytes32) internal keyLookup; // stores a lookup of the zkp public key if you know the ETH address

  // 保留下一个我们可以在其中存储密钥的空插槽
  uint256 internal nextAvailableIndex = FIRST_LEAF_INDEX; //holds the next empty slot that we can store a key in

  // 黑名单
  //
  mapping (address => uint256) internal blacklist;

  // 所有有效 索引 merkle tree root 的链接列表，每个值都指向上一个根，以使它们全部都可以删除
  mapping (bytes32 => bytes32) public publicKeyRoots; //linked list of all valid roots each value points to the previous root to enable them all to be deleted

  // 初始的 publicKey 的 merkle tree root
  bytes32 private constant ONE = 0x0000000000000000000000000000000000000000000000000000000000000001;
  bytes32 public currentPublicKeyRoot = ONE;

  // 被记住的历史 root 源数量 (初始值是, 50)
  uint256 public rootPruningInterval = 50; // the number of historic roots that are remembered

  // 历史root 计数器
  uint256 public publicKeyRootComputations; // the total number of roots currently

  // 压缩的管理员公钥, todo 即 有三个公钥, Shield 合约会使用
  bytes32[3] public compressedAdminPublicKeys;

  /**
  This function adds a key to the Merkle tree at the next available leaf
  updating state variables as needed.
  */
  // 该函数根据需要在下一个可用的叶子更新状态变量处向Merkle树添加密钥
  //
  function addPublicKeyToTree(bytes32 key) internal {
    // firstly we need to mod the key to Fq(zok) because that's what Zokrates and MiMC will do
    //
    // 首先，我们需要将密钥修改为 Fq(zok), 因为这就是 Zokrates (一种 零知识证明 算法) 和 MiMC 要做的
    key = bytes32(uint256(key) % q);
    require(M[nextAvailableIndex] == 0, "Trying to add key to a non-empty leaf");
    require(L[key] == 0, "The key being added is already in the Public Key tree");

    // 往 对应的索引, 添加 publicKey
    M[nextAvailableIndex] = key;

    // 记录 publicKey 对应的索引
    L[key] = nextAvailableIndex; // reverse lookup for a leaf

    // 将当前索引插入 索引 merkle  tree
    // 并计算新的 root
    bytes32 root = updatePathToRoot(nextAvailableIndex++);

    // 更新 root 的引用链表值, 默认只保留最近的50个root
    updatePublicKeyRootsLinkedList(root);
  }

  /**
  This modifier registers a new user (adds them to the Public Key Tree provided they
  are not previously registed and are not on a blacklist). If they are an existing
  user, it just does the blacklist check
  */
  // 此 modifier 注册一个新用户（将其添加到公钥树中，前提是他们先前未注册且不在黑名单中）。 如果他们是现有用户，则只执行黑名单检查
  //
  function checkUser(bytes32 zkpPublicKey) public {

    // 每个 addr 只能放 一个 publicKey
    if (keyLookup[msg.sender] == 0) {

      // 将未知用户添加到密钥查找
      keyLookup[msg.sender] = zkpPublicKey; // add unknown user to key lookup

      // 用新叶子更新Merkle树
      addPublicKeyToTree(zkpPublicKey); // update the Merkle tree with the new leaf
    }
    require (keyLookup[msg.sender] == zkpPublicKey, "The ZKP public key has not been registered to this address");
    require (blacklist[msg.sender] == 0, "This address is blacklisted - transaction stopped");
  }

  modifier onlyCheckedUser(bytes32 zkpPublicKey) {
    checkUser(zkpPublicKey);
    _;
  }


  // todo 将某个 addr 加入 黑名单
  function blacklistAddress(address addr) external onlyOwner {


    //add the malfeasant to the blacklist
    //
    // 将不良分子 addr 添加到黑名单中
    //
    // 这里有不同的 "黑名单代码" 范围
    blacklist[addr] = 1; // there is scope here for different 'blacklisting codes'


    // remove them from the Merkle tree
    //
    // 先取出该 addr 对应的 publicKey, 并求出简化值
    //
    // 在 keyLookup 取出转换为Fq之前的 key
    bytes32 blacklistedKey = bytes32(uint256(keyLookup[addr]) % q); // keyLookup stores the key before conversition to Fq
    require(uint256(blacklistedKey) != 0, 'The key being blacklisted does not exist');

    // 先用key从 L 中查到 M中的索引
    uint256 blacklistedIndex = L[blacklistedKey];

    // 校验下 索引是否为 叶子节点的索引, tree 上的叶子结点的索引总比 拓展节点和root节点索引大
    require(blacklistedIndex >= FIRST_LEAF_INDEX, 'The blacklisted index is not that of a leaf');

    // 删掉 M 中的 publicKey
    delete M[blacklistedIndex];


    // and recalculate the root
    //
    // 重新计算 merkle tree
    bytes32 root = updatePathToRoot(blacklistedIndex);


    // next, traverse the linked list, deleting each element (could be expensive if we have many transactions)
    // 接下来，遍历链接列表，删除每个元素（如果我们有很多交易，可能会很昂贵） todo 清空 publicKeyRoots 中所有 历史 root
    deleteHistoricRoots(currentPublicKeyRoot);

    // 当 publicKeyRoots 中的所有的root被清空了, 这时候
    // 我们正在开始一个新的历史 root 列表，必须将其标记为0以外的值
    publicKeyRoots[root] = ONE; //we're starting a new list of historic roots have to label it with something other than 0

    // 重新记录最新的root
    currentPublicKeyRoot = root;

    // 重新计数 历史 root数目
    publicKeyRootComputations = 1; //have to reset this so we prune correctly
  }

  /**
  function to recursively delete historic roots. Normally called automatically by `blacklistAddress`
  However, if we ever had so many roots that we exceeded the block gas limit, we could call this
  function directly to iteratively remove roots. This is public onlyOwner, rather than private so
  it can be called directly in case of emergency (e.g. some bug prevents it working as part of blacklisting).
  */
  // TODO 递归删除所有历史 root
  // 通常由“ blacklistAddress”自动调用
  // 但是，如果我们有太多 root，超过了 block的 gasLimit，我们可以直接调用此函数来迭代删root。
  // todo 可以在紧急情况下直接调用（例如，某些错误阻止了它作为黑名单的一部分工作）。
  //
  function deleteHistoricRoots(bytes32 publicKeyRoot) public onlyOwner {
    bytes32 nextPublicKeyRoot = publicKeyRoots[publicKeyRoot];
    delete publicKeyRoots[publicKeyRoot];
    if (nextPublicKeyRoot != 0) deleteHistoricRoots(nextPublicKeyRoot);
    return;  // we've deleted the whole linked list  我们已经删除了整个链表
  }

  /**
  To avoid having so many roots stored that deleting them (in the event of a blacklisting)
  would be very expensive, we only keep publicKeyRootComputations of them.  Once we have that
  many, we need to remove the oldest one each time we add a new one.
  */
  // TODO 修剪, 旧的 root
  // 为了避免存储太多 root，以至于将它们删除（如果列入黑名单）将非常昂贵，我们只保留它们的 publicKeyRootComputations。
  // 一旦有那么多，每次添加一个新的时，我们都需要删除最旧的一个
  function pruneOldestRoot(bytes32 publicKeyRoot) private {

    //note, we must have at least two historic roots for this to work
    // 请注意，我们必须至少有两个历史根源才能起作用
    bytes32 nextPublicKeyRoot = publicKeyRoot;
    bytes32 nextNextPublicKeyRoot = ONE;

    // 下降到列表末尾，记住上一个 item
    while(nextNextPublicKeyRoot != 0) { // decend to the end of the list, remembering the previous item

      // 一直不断的替换最新的值
      publicKeyRoot = nextPublicKeyRoot;
      nextPublicKeyRoot = publicKeyRoots[publicKeyRoot];
      nextNextPublicKeyRoot = publicKeyRoots[nextPublicKeyRoot];
      // 只有遍历到头的时候, 才会 nextNextPublicKeyRoot = 0
    }

    // 因为 while 之后, 导致这里的 publicKey 是最后一个有引用之前的root的root
    delete publicKeyRoots[publicKeyRoot]; //remove the oldest (non-zero) root
    return;
  }


  // todo 将某个 addr 移出 黑名单
  function unBlacklistAddress(address addr) external onlyOwner {

    //remove the reformed charater from the blacklist
    // 将 addr 从 黑名单中移出
    delete blacklist[addr];


    // add them back to the Merkle tree
    // 并将该 该addr对应的 publicKey的简化值取出来
    bytes32 blacklistedKey = bytes32(uint256(keyLookup[addr]) % q); //keyLookup stores the key before conversition to Fq

    //
    require(uint256(blacklistedKey) != 0, 'The key being unblacklisted does not exist');

    // 存放 L 中的反向索引
    uint256 blacklistedIndex = L[blacklistedKey];

    // 校验节点索引是否非法
    require(blacklistedIndex >= FIRST_LEAF_INDEX, 'The blacklisted index is not that of a leaf');

    // 存放 M 中的正向索引
    M[blacklistedIndex] = blacklistedKey;


    // and recalculate the root
    //
    // 重新计算 root
    bytes32 root = updatePathToRoot(blacklistedIndex);

    // 更新 root 的引用链表值, 默认只保留最近的50个root
    updatePublicKeyRootsLinkedList(root);
  }

  /**
  A function to update the linked list of roots and associated state variables
  */
  // 更新 merkle tree 和 相关状态变量的链接列表
  //
  function updatePublicKeyRootsLinkedList(bytes32 root) private {

    // 将索引 merkle tree root 放置入集合中,并指向上一个 merkle root 的跟
    publicKeyRoots[root] = currentPublicKeyRoot;

    // 全局的 中转变量记录最新的root
    currentPublicKeyRoot = root;

    // 累加 root 的数量
    publicKeyRootComputations++;

    // 当累加的 历史 root数量大于 50 个时
    // 根据当前最新的root逐个遍历到倒数第51个root
    // 并将倒数第51root 删除掉
    if (publicKeyRootComputations > rootPruningInterval) pruneOldestRoot(currentPublicKeyRoot);
  }

  // 修改 历史 root的数目容量
  function setRootPruningInterval(uint256 interval) external onlyOwner {
    rootPruningInterval = interval;
  }


  // 设置三个 管理员公钥
  function setCompressedAdminPublicKeys(bytes32[3] calldata keys) external onlyOwner {
    compressedAdminPublicKeys = keys;
  }

  /**
  To implement blacklisting, we need a merkle tree of whitelisted public keys. Unfortunately
  this can't use Timber because we need to change leaves after creating them.  Therefore we
  need to store the tree in this contract and use a full update algorithm:
  Updates each node of the Merkle Tree on the path from leaf to root.
  p - is the Index of the new token within M.
  */
  //
  // 要实施黑名单, 我们需要一个列入[白名单公钥的梅克尔树]. 不幸的是, 这不能使用 Timber (数目), 因为我们需要在创建叶子后更改叶子.
  // 因此, 我们需要将树存储在此合同中, 并使用完整的更新算法:
  // 在从叶到根的路径上更新Merkle树的每个节点。
  //
  // p-是M中新 token 的索引。
  // TODO 所以, 这是一颗 索引 merkle tree
  function updatePathToRoot(uint256 p) internal returns (bytes32) {

  /*
  If Z were the token, then the p's mark the 'path', and the s's mark the 'sibling path'
  如果Z是 token，则p标记为 'path', 而s标记为 '兄弟 path'
                   p
          p                  s
     s         p        EF        GH
  A    B    Z    s    E    F    G    H
  */

    // s 是 p 的姐妹路径
    uint256 s; //s is the 'sister' path of p.

    // 下一个p的 缓存索引（即，上一行的路径节点）
    uint256 t; //temp index for the next p (i.e. the path node of the row above)


    for (uint256 r = TREE_HEIGHT; r > 0; r--) {
      if (p%2 == 0) { //p even index in M
        s = p-1;
        t = (p-1)/2;
        M[t] = mimcHash2([M[s],M[p]]);
      } else { //p odd index in M
        s = p+1;
        t = p/2;
        M[t] = mimcHash2([M[p],M[s]]);
      }
      p = t; //move to the path node on the next highest row of the tree
    }
    return M[0]; //the root of M
  }
}
