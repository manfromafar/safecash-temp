// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <uint256.h>
#include <arith_uint256.h>
#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

// For equihash_parameters_acceptable.
#include <crypto/equihash/equihash.h>
#include <net.h>
#include <validation.h>
#define equihash_parameters_acceptable(N, K) \
    ((CBlockHeader::HEADER_SIZE + equihash_solution_size(N, K))*MAX_HEADERS_RESULTS < \
     MAX_PROTOCOL_MESSAGE_LENGTH-1000)

#include <base58.h>
#include <assert.h>
#include <memory>
#include <boost/assign/list_of.hpp>
#include <limits>

#include <chainparamsseeds.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.nHeight  = 0;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */

// "SafeCash was bootstrapped on Wed May 16 09:57:21 UTC 2018 BTC#524001 0000000000000000001196f00272283935fabb908aa162f9207dd96ac012c67c"
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "SafeCash4cc9ed056331f61a4b359fe12dab5edf7ba80fbcc742025f904cc91208be728f";
    const CScript genesisOutputScript = CScript() << ParseHex("0405cd1787ffcf6d5b59b0f70fff5cb0946b06eea488b812cb5062b8940cb729cfbaad51729064b14465e8c4ccddae18131f4440acefdefc82a708d22208182f4f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 0; 
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("00028cfb5aa39c474b7d7d27f053dc7351cf5839da15ee1fdc837cc09ec2f6df");
        consensus.BIP65Height = 0; 
        consensus.BIP66Height = 0; 
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; 
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; 
        consensus.nMinerConfirmationWindow = 2016; 
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000100010001");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00"); 

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x6b; // Main 0
        pchMessageStart[1] = 0x17; // Main 1
        pchMessageStart[2] = 0xa4; // Main 2
        pchMessageStart[3] = 0xbf; // Main 3
        nDefaultPort = 7233;
        nPruneAfterHeight = 100000;

	    // Equihash
        const size_t N = 192, K = 7;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        // SafeCash PoW
        consensus.nSuperBlockInterval = 1440; // Once a day

        genesis = CreateGenesisBlock(
            // nTime
            1526476661, 
            // nNonce
            uint256S("0x0000000000000000000000000000000000000000000000000000000000001d08"), 
            // Solution
            ParseHex("006ccd3474d539dd177eb62a61dce79a8cefdb88641b3ab265d0d02ef8afa803b76fca5df67737dfeccb07e0e5d1e695a896b6e7e7f3b45662dabb8a7a9f42085917fc314813eed692c54809daaf12adaaddef210da097ac4ea08b9b3d7e8510bfc5eeef247fde849369b4e5d6599b66198e1436b924ecec263c413847281baa2b55c42186f72be73268b9d4970dcebc31f7b22673dcf12b2cbfa7fef5b5daad5fd31de631b8657b0c5c1c82db89d927bdf8a1e6d6a2480116809aeb3e31f5ada9e99f8c01141575e10660ec12e6525801811117b8ff166e383d8b098652c1ead116389b9d95eb3675ff94ca62de4baf43b9811befba06a5c9f8ad5e1a025cf65e1b35e7bb1434ab187bc9bd61e9b2655558d8fb170f97b8cd7121a70070e1ef320841733f142702d41f044e23e1122f7444c828fbb756e83c037d41953c03b71e8df13e3dda5884dc82c6c08cbc024600b5cc7e9012fdd6a77ef7b2f8793d3609f01e8c16037bcc060d17062789b4b93a377a5b866f5ff5a91608821db2c74be159ec7ef474116642dd8ad939de1e0d39b3098864b4016c814591263582efa4295e06ae0fdcca1ff6f1bc0dde10411a4a68a43d0622da42a016bb0ede98565d2d8241ba97f0f1ab06f5fc3e0d552c45dfc2170c57e9d8535798a3be3b3614de778f392fb7dd608f5c3507f69bc888a04e838e65d6b597bc037716b2c982897ae9ac3253e8c7af25ba37d444e6312573b24c174a81763834e426d347e2b21efd35f70c3518cbf59e846bd65913f851f0dc1f027e9aed7b193d34a43ddbdb551d44f1d158baddd592b7dd5125066b32a6b59be7b3d7fae070de6f1b742a6904443133c8c3d204ee12d5ec81ea2f02f14852bb077ade2e0baf8b5a520b834baaf7668ce2b9dc6a9f8099ec2821b28211048aaad9f65884a667d024c946ce33eb4f03824bec0f2692a5ab4e326d71c15864a13e712a8a06464dffe804cba5c8c344ecb05f03c1cff67210dd07494ffeb889e54126d43534f0cd9212fc83fe79ab12ffa22909dacac57e2cb3d4a04611357641f2375c0c96df23991deb4bc9ce428cc81bfb118e06deaae710196636f2dec3a76a3eb7aa3fe6f676b9aafe795d13f06e2ec15cc6abf61ba473ae3a1a8a606f3a2457645bbe285d2ebd7d8409286d296121e69f6716f0710461b3d8666eff219c54646c5167a8f61c70d4a9cf408d5e9949167bdf91941a0435f0c12f4ca1dc3ef605cdea8f7114569ecc58923694d6ef92dc8017979e104e173ec74748148615a1f61fde811dfc7dfb3e49062ba92263244737e20864a7b738bba1f769d1b8c91f0e09e19cd82f2bc56b02e944c97762b2ad9932b7098b8209c2dd15b7993b92e18f7ed5271067bdb56c0c2363383490e8d0a55cf2230e7ca6b88d40bf30fe0418eec407875598ed27c097d27274462bd35baea306294b1ec09f520fa2a0809b9c777141ff99fcb0250c305df5458e95b8f55911dae8ecd8a586bf9670b70c3bc98a574db7bd969eb673a36f038afad3b7e44d0771d0a4a9897a0e5f5e462a347884de006bf9cf64223d4f4338a02b674f0f73e438f120297f3b939ba80fa59c8b8fe70d679fbef37792a1601209987327e42b0b8d20ae50853dfeed3840e9dcc36f44151d30b70605413471e43bc5562cd08bca9e3450b12c53f617452d3e0ea320e7e1da4668b0e1f8ff1e78c6f74bc709a038ecc605301ecfa122696471be2f6dac7ee3db557e0fc3dcdddf3fe007f642554862532fb8ba35510a11eeaf3e4a466be54cd901eedd21a2ed0f9aecaf152bcd2612ec6059aee38170afb86eaf44367c76450a4b243eeab98c4fe971277bc8f7ccb7bb073ed4043d11af5056a5c309c88ab7b516716b16a4995d0b3d"),
            // nBits
            0x1f07ffff, 
            // Version
            4, 
            // Reward
            0); 

        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.timeGenesisBlock = genesis.nTime;

        assert(consensus.hashGenesisBlock == uint256S("00028cfb5aa39c474b7d7d27f053dc7351cf5839da15ee1fdc837cc09ec2f6df"));
        assert(genesis.hashMerkleRoot == uint256S("0x5417bdbcd952fc057e254498df7c83bbb8a5986e73d0055c37ad74b8ad349de6"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they dont support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 28);// 
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 63);// 
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 48);// 
        base58Prefixes[EXT_PUBLIC_KEY] = { 0x53, 0x41, 0x46, 0x45 };// 
        base58Prefixes[EXT_SECRET_KEY] = { 0x53, 0x61, 0x66, 0x65 };// 

        bech32_hrp = "sc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));
        vSeeds.emplace_back("mainnet1.safecash.io", true);
        vSeeds.emplace_back("mainnet2.safecash.io", true);

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {
                    0, consensus.hashGenesisBlock
                },
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        // Founders Addresses: A vector of 2-of-3 multisig addresses
        vFounderAddress = 
        {
            "", // Name
        };
        
        // Infrastructure Addresses: A vector of 2-of-3 multisig addresses
        vInfrastructureAddress = 
        {
            "", // Name
        };
        
        // Giveaway Addresses: A vector of 2-of-3 multisig addresses
        vGiveawayAddress = 
        {
            "", // Name
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 0; 
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("05465adce5ff77fe67e3fd5fb35e01b022580582795782dc29db4f9a6cda324c");
        consensus.BIP65Height = 0; 
        consensus.BIP66Height = 0; 
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; 
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; 
        consensus.nMinerConfirmationWindow = 2016; 
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000000000001f");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00"); 

        pchMessageStart[0] = 0xc6; // Test 0
        pchMessageStart[1] = 0x54; // Test 1
        pchMessageStart[2] = 0xaa; // Test 2
        pchMessageStart[3] = 0xc3; // Test 3
        nDefaultPort = 17233;
        nPruneAfterHeight = 1000;

	    // Equihash
        const size_t N = 192, K = 7;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        // SafeCash PoW
        consensus.nSuperBlockInterval = 10; 

        genesis = CreateGenesisBlock(
            // nTime
            1526476661, 
            // nNonce
            uint256S("0000000000000000000000000000000000000000000000000000000000000009"), 
            // Solution
            ParseHex("00626baad7462104da1ec05094a3a0e848d153d4090691e48a3d54b02138650a5c9ef8130b23075db51e152ea5c39e47ed2345ead63e5b494dd1faffb94632257f2efdaa9a8d2da190a31bd6a82fd76e833bc94802819ded2f8ae6f5a578f3b49af4e99564fb34439f26e8c1d4ffe3d0f752eb2296f3f0d540c9e5d112a007121f2fc9de1b8d4a7864f206bbcaa61e2f9b04542fbe2de4f85c8ac31822b49c98ec36ba72703e4d4504fc2cfc43621769ac9c31af016f233100a46b5e3309003b6b78d3ad43fc95e3d3a37df4f16a63d223e515877fce751f847b84fd9635fd4bcc4790f43f06b35a1aa603c51fd545f8c295e143af620d8155938bf50a2bc668d08f3ed4fda8427914c08a19a5dcff102e1eb923317c9f112da0ac947409c16ea95556cf4cd617d439b47b18544d175e7391de25b8e0efafa89afa40a6def4bf2643abcb83342bb944824dcc4d5b2efe03557cd235414da375dd603bfc9c9748b0c69d07ff14899c28e86036bd08a368dcde5ea8329c5c383a652ac90f7ede1eb93114aa24f944ebf60a4af4d579022bd58436121be58afc9b331a49f091f6cbe3f9918505c6b02f988a399f1fabb18a683254c0767fca850744bd7778df1cc5dcea5845b724b549c59605bbd06f06eedd0c0bc7f931aac6948460365a952cb6fcba100ffcee6a6e918e7ee044da1411dbd1ab78df5f7aac0b378afc1fd56ca1911625ada7c5da0a47b2bf51c015a54ca965ec3cc5bc5fd9a2fbe85bfaf0777f3f2a2a75dd07443e918ff8cf847451301116525b74542834762c43fd53eceaa1a988d48f775a5b35c19eb3720c3a59c693d7ef2f2cac975acec7c902e2983762001e735f4838a536412ed194d6ee451b4299c09e1cb61d1b152f0e56a33ec77153d4aab42903cd237ebb5c26cf2606b1dd20bff062c2a371649b50f2c11d636601e344693e41e6eacdc973b828b5fc657353f7b1761b344e41611c9cab0fcc26788f790d49be31b5c8570c70d90520696aabbc5c2189357950bd5fbbcdc4b723b9e4b90d0b91e33401b677347dbe79e74415123c070d5648ebf6f445ec03f2d0c83f7838e4615505b3178c214b366ee7d39c64832014c5680176669d633a0a124be2d9175241f6d8628d9dce0659d0701a9ec652f6a5d37b6d87d3f7f8a552314257fa6cf8bd81bf0583f944ea0639b4cfae330d38c72fd4d7eb2aa6e640005f4a06dd8d6791e385b680ae9e11b2c9320037077a86a0380c0f57518fe4a501eef1b579d0cd068f0851591f53ce8d57f189940a423576493df056fd02149089a724166cc1077ce1e2fa16aeff1d8c5dd2fc192c7e1b5769ad7dedef81f40c9a30509741c57e433c0bae24d9623949472345dfd1d9d47de01d11402249b8fc748575215dfb861ba1a2e762d76d843bde8502cd1f6be22d95d9b43ec1aad98efd922db39230920933bd62414eb6aece72a36a5bfc01577e139e949c0789cd9ea60cee4296bd7101a959564486508898070a98a265c1679a196cc0e34adc7c86a9738db201d307d740894dc41a0a42cc92b000da06e4fce0d7205319ca3d13c08c89b799488a54dee38e2705e93dad8e0f73fb01a81620fadf8923886f7c7a1285769cde402b64b42eb0f2ef0ff85733918e4568a61f6a1aae1806f27aaf5aa263d32c3613fe9ba023292221d0219b20a8a195c28fc2cbfc78b281d3fc6c0748adfb628d19abcc55e04899cfe62342ca33e220f5787eaf47252157b3c493147514df0442b9dfed5ca0dbc78ab10a071dd752dd1bdcbf982f816fe858fb70d590392441182bddc743987b24f9426683c93aee11c6e450e5c714cc75c721557805cab998ecbad627a27c603778c32239bafda95345ef6a7a58c7a9d0b14aa04df51b10"),
            // nBits
            0x2007ffff, 
            // Version
            4, 
            // Reward
            0); 

        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.timeGenesisBlock = genesis.nTime;
        assert(consensus.hashGenesisBlock == uint256S("05465adce5ff77fe67e3fd5fb35e01b022580582795782dc29db4f9a6cda324c"));
        assert(genesis.hashMerkleRoot == uint256S("5417bdbcd952fc057e254498df7c83bbb8a5986e73d0055c37ad74b8ad349de6"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet1.safecash.io", true);
        vSeeds.emplace_back("testnet2.safecash.io", true);


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 125);// 
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 87);// 
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 15);// 
        base58Prefixes[EXT_PUBLIC_KEY] = { 0x53, 0x4e, 0x55, 0x4c };// 
        base58Prefixes[EXT_SECRET_KEY] = { 0x53, 0x6f, 0x75, 0x6c };// 

        bech32_hrp = "sct";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        // Founders Addresses: 
        vFounderAddress = 
        {
            "c7K6smvBBNN4CFxAWnQFptmyWk1DtEtGNT", // Chris
            "cAuzzQVDS9dx2jE7djxf43empta65XTwHv", // Jimmy
            "c8SQXUgr7sFfSaRLFuo852iwGqjENRwvyY", // Scott
            "c1Y5aJ78mqgQpCFEo8cwjL4275EkEt4zWp", // Shelby
            "cMPZiLacQTfRqwSrG137NaGmVyZkSJQJf8", // Loki
        };
        
        // Infrastructure Addresses:
        vInfrastructureAddress = 
        {
            "cMVFs7e43DAMR6Bds6NPPcvMr5wJB2BEwm", // Infrastructure
        };
        
        // Giveaway Addresses:
        vGiveawayAddress = 
        {
            "cDuFBwJ82XocLG3ZHoJqd5XsswSqEZhJou", // Giveaways
        };

    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 0; 
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0ace1aceae2ae42aa51795a8a0313ed717e29e4890a4296a41d236b79e71f135");
        consensus.BIP65Height = 0; 
        consensus.BIP66Height = 0; 
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; 
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; 
        consensus.nMinerConfirmationWindow = 2016; 
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xae; // RegTest 0
        pchMessageStart[1] = 0x74; // RegTest 1
        pchMessageStart[2] = 0x8c; // RegTest 2
        pchMessageStart[3] = 0xc3; // Regtest 3
        nDefaultPort = 27233;
        nPruneAfterHeight = 1000;

    	// Equihash
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        // SafeCash PoW
        consensus.nSuperBlockInterval = 10; 

        genesis = CreateGenesisBlock(
            // nTime
            1526476661, 
            // nNonce
            uint256S("0000000000000000000000000000000000000000000000000000000000000014"), 
            // Solution
            ParseHex("0c082b7ee1a810c89234701591b593de2e05117c4c5a446471c5b450dc9e1785833ea765"),
            // nBits
            0x200f0f0f, 
            // Version
            4, 
            // Reward
            0); 
        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.timeGenesisBlock = genesis.nTime;
        assert(consensus.hashGenesisBlock == uint256S("0ace1aceae2ae42aa51795a8a0313ed717e29e4890a4296a41d236b79e71f135"));
        assert(genesis.hashMerkleRoot == uint256S("5417bdbcd952fc057e254498df7c83bbb8a5986e73d0055c37ad74b8ad349de6"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {
                    0, consensus.hashGenesisBlock
                },
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 125);// 
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 87);// 
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 15);// 
        base58Prefixes[EXT_PUBLIC_KEY] = { 0x53, 0x4e, 0x55, 0x4c };// 
        base58Prefixes[EXT_SECRET_KEY] = { 0x53, 0x6f, 0x75, 0x6c };// 
        
        bech32_hrp = "scrt";

        // Founders Addresses: A vector of 2-of-3 multisig addresses
        vFounderAddress = 
        {
            "", // Name
        };
        
        // Infrastructure Addresses: A vector of 2-of-3 multisig addresses
        vInfrastructureAddress = 
        {
            "", // Name
        };
        
        // Giveaway Addresses: A vector of 2-of-3 multisig addresses
        vGiveawayAddress = 
        {
            "", // Name
        };
        
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}

// Convenience Functions
CScript CChainParams::AddressToScript(std::string inAddress) const
{
    CTxDestination address = DecodeDestination(inAddress.c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

// Sustainability
// Separated logic, in case individual rules change

// Block height must be >0 and <=last founders reward block height 
// or block time must be within 1 year of the genesis block time
// Index variable i ranges from 0 - (vFounderAddress.size()-1)
std::string CChainParams::GetFounderAddressAtHeight(int nHeight) const 
{
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFounderAddress.size()) / vFounderAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFounderAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// or block time must be within 1 year of the genesis block time
// The address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFounderScriptAtHeight(int nHeight) const 
{
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());
    return AddressToScript(GetFounderAddressAtHeight(nHeight).c_str());
}

std::string CChainParams::GetFounderAddressAtIndex(int i) const 
{
    assert(i >= 0 && i < vFounderAddress.size());
    return vFounderAddress[i];
}

std::vector<CScript> CChainParams::GetAllFounderScripts() const
{
    std::vector<CScript> output;
    for (auto &address : vFounderAddress)
    {
        output.push_back(AddressToScript(address));
    }
    return output;
}

// Block height must be >0 and <=last founders reward block height 
// or block time must be within 1 year of the genesis block time
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetInfrastructureAddressAtHeight(int nHeight) const 
{
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vInfrastructureAddress.size()) / vInfrastructureAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vInfrastructureAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// or block time must be within 1 year of the genesis block time
// The address is expected to be a multisig (P2SH) address
CScript CChainParams::GetInfrastructureScriptAtHeight(int nHeight) const 
{
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());
    return AddressToScript(GetInfrastructureAddressAtHeight(nHeight).c_str());
}

std::string CChainParams::GetInfrastructureAddressAtIndex(int i) const 
{
    assert(i >= 0 && i < vInfrastructureAddress.size());
    return vInfrastructureAddress[i];
}

// Block height must be >0 and <=last founders reward block height 
// or block time must be within 1 year of the genesis block time
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetGiveawayAddressAtHeight(int nHeight) const 
{
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vGiveawayAddress.size()) / vGiveawayAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vGiveawayAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// or block time must be within 1 year of the genesis block time
// The address is expected to be a multisig (P2SH) address
CScript CChainParams::GetGiveawayScriptAtHeight(int nHeight) const 
{
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());
    return AddressToScript(GetGiveawayAddressAtHeight(nHeight).c_str());
}

std::string CChainParams::GetGiveawayAddressAtIndex(int i) const 
{
    assert(i >= 0 && i < vGiveawayAddress.size());
    return vGiveawayAddress[i];
}
