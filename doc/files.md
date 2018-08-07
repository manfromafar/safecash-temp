
* banlist.dat: stores the IPs/Subnets of banned nodes
* safecash.conf: contains configuration settings for safecashd or safecash-qt
* safecashd.pid: stores the process id of safecashd while running
* blocks/blk000??.dat: block data (custom, 128 MiB per file);
* blocks/rev000??.dat; block undo data (custom);
* blocks/index/*; block index (LevelDB);
* chainstate/*; block chain state database (LevelDB);
* database/*: BDB database environment;
* db.log: wallet database log file;
* debug.log: contains debug information and general logging generated by safecashd or safecash-qt
* fee_estimates.dat: stores statistics used to estimate minimum transaction fees and priorities required for confirmation;
* mempool.dat: dump of the mempool's transactions;
* peers.dat: peer IP address database (custom format);
* wallet.dat: personal wallet (BDB) with keys and transactions;
* wallets/database/*: BDB database environment;
* wallets/db.log: wallet database log file;
* wallets/wallet.dat: personal wallet (BDB) with keys and transactions;
* .cookie: session RPC authentication cookie (written at start when cookie authentication is used, deleted on shutdown):
* onion_private_key: cached Tor hidden service private key for `-listenonion`:
* guisettings.ini.bak: backup of former GUI settings after `-resetguisettings` is used