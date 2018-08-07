SafeCash initial release based on Bitcoin-Core version 0.16.0:

Download Wallet [here](https://safecash.io/#download)

Please report bugs using the issue tracker at GitHub or on our [forums](https://safecash.io/forum/).

To receive security and update notifications, please register at our [forums](https://safecash.io/forum/).

How to Upgrade
==============


Bitcoin Core is extensively tested on multiple operating systems using
the Linux kernel, macOS 10.8+, and Windows Vista and later. Windows XP is not supported.

Bitcoin Core should also work on most other Unix-like systems but is not
frequently tested on them.

0.16.2 change log
------------------

### Wallet
- #13622 `c04a4a5` Remove mapRequest tracking that just effects Qt display. (TheBlueMatt)
- #12905 `cfc6f74` [rpcwallet] Clamp walletpassphrase value at 100M seconds (sdaftuar)
- #13437 `ed82e71` wallet: Erase wtxOrderd wtx pointer on removeprunedfunds (MarcoFalke)

### RPC and other APIs
- #13451 `cbd2f70` rpc: expose CBlockIndex::nTx in getblock(header) (instagibbs)
- #13507 `f7401c8` RPC: Fix parameter count check for importpubkey (kristapsk)
- #13452 `6b9dc8c` rpc: have verifytxoutproof check the number of txns in proof structure (instagibbs)
- #12837 `bf1f150` rpc: fix type mistmatch in `listreceivedbyaddress` (joemphilips)
- #12743 `657dfc5` Fix csBestBlock/cvBlockChange waiting in rpc/mining (sipa)

### GUI
- #12432 `f78e7f6` [qt] send: Clear All also resets coin control options (Sjors)
- #12617 `21dd512` gui: Show messages as text not html (laanwj)
- #12793 `cf6feb7` qt: Avoid reseting on resetguisettigs=0 (MarcoFalke)

### Build system
- #13544 `9fd3e00` depends: Update Qt download url (fanquake)
- #12573 `88d1a64` Fix compilation when compiler do not support `__builtin_clz*` (532479301)

### Tests and QA
- #13061 `170b309` Make tests pass after 2020 (bmwiedemann)
- #13192 `79c4fff` [tests] Fixed intermittent failure in `p2p_sendheaders.py` (lmanners)
- #13300 `d9c5630` qa: Initialize lockstack to prevent null pointer deref (MarcoFalke)
- #13545 `e15e3a9` tests: Fix test case `streams_serializedata_xor` Remove Boost dependency. (practicalswift)
- #13304 `cbdabef` qa: Fix `wallet_listreceivedby` race (MarcoFalke)

### Miscellaneous
- #12887 `2291774` Add newlines to end of log messages (jnewbery)
- #12859 `18b0c69` Bugfix: Include <memory> for `std::unique_ptr` (luke-jr)
- #13131 `ce8aa54` Add Windows shutdown handler (ken2812221)
- #13652 `20461fc` rpc: Fix that CWallet::AbandonTransaction would leave the grandchildren, etc. active (Empact)
=======
Initial Release


Change Log
===============

Initial Release

Credits
=======

- Thanks to the Bitcoin Core Development team
- Thanks to [Bulwark](https://github.com/bulwark-crypto/Bulwark) for the great README templates
