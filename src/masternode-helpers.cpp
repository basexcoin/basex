// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2017-2018 The Basex developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "masternode-helpers.h"
#include "init.h"
#include "main.h"
#include "masternodeman.h"
#include "activemasternode.h"
#include "masternode-payments.h"
#include "amount.h"
#include "swifttx.h"

// A helper object for signing messages from Masternodes
CMasternodeSigner masternodeSigner;

void ThreadMasternodePool()
{
    if (fLiteMode) return; //disable all Masternode related functionality

    // Make this thread recognisable
    RenameThread("basex-mnpool");

    unsigned int c = 0;

    while (true) {
        MilliSleep(1000);

        // try to sync from all available nodes, one step at a time
        masternodeSync.Process();

        if (masternodeSync.IsBlockchainSynced()) {
            c++;

            // check if we should activate or ping every few minutes,
            // start right after sync is considered to be done
            if (c % MASTERNODE_PING_SECONDS == 0) activeMasternode.ManageStatus();

            if (c % 60 == 0) {
                mnodeman.CheckAndRemove();
                mnodeman.ProcessMasternodeConnections();
                masternodePayments.CleanPaymentList();
                CleanTransactionLocksList();
            }
        }
    }
}

bool CMasternodeSigner::IsVinAssociatedWithPubkey(CTxIn& vin, CPubKey& pubkey)
{
    CScript payee2;
    payee2 = GetScriptForDestination(pubkey.GetID());

    CAmount collateral = 3500 * COIN;

    CTransaction txVin;
    uint256 hash;
    if (GetTransaction(vin.prevout.hash, txVin, hash, true)) {
        BlockMap::iterator iter = mapBlockIndex.find(hash);
        if (iter != mapBlockIndex.end()) {
            int txnheight = iter->second->nHeight;
            
            if (txnheight <= GetSporkValue(SPORK_19_COLLATERAL_3500)) {
                collateral = 3500 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_20_COLLATERAL_4300)) {
                collateral = 4300 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_21_COLLATERAL_4600)) {
                collateral = 4600 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_22_COLLATERAL_4850)) {
                collateral = 4850 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_23_COLLATERAL_5050)) {
                collateral = 5050 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_24_COLLATERAL_5300)) {
                collateral = 5300 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_25_COLLATERAL_5600)) {
                collateral = 5600 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_26_COLLATERAL_5950)) {
                collateral = 5950 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_27_COLLATERAL_6300)) {
                collateral = 6300 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_28_COLLATERAL_6650)) {
                collateral = 6650 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_29_COLLATERAL_7000)) {
                collateral = 7000 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_30_COLLATERAL_7350)) {
                collateral = 7350 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_31_COLLATERAL_7700)) {
                collateral = 7700 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_32_COLLATERAL_8050)) {
                collateral = 8050 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_33_COLLATERAL_8400)) {
                collateral = 8400 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_34_COLLATERAL_8750)) {
                collateral = 8750 * COIN;
            } else if (txnheight <= GetSporkValue(SPORK_35_COLLATERAL_9500)) {
                collateral = 9500 * COIN;
            }
        }

        BOOST_FOREACH (CTxOut out, txVin.vout) {
            if (out.nValue == collateral) {
                if (out.scriptPubKey == payee2) return true;
            }
        }
    }

    return false;
}

bool CMasternodeSigner::SetKey(std::string strSecret, std::string& errorMessage, CKey& key, CPubKey& pubkey)
{
    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) {
        errorMessage = _("Invalid private key.");
        return false;
    }

    key = vchSecret.GetKey();
    pubkey = key.GetPubKey();

    return true;
}

bool CMasternodeSigner::GetKeysFromSecret(std::string strSecret, CKey& keyRet, CPubKey& pubkeyRet)
{
    CBitcoinSecret vchSecret;

    if (!vchSecret.SetString(strSecret)) return false;

    keyRet = vchSecret.GetKey();
    pubkeyRet = keyRet.GetPubKey();

    return true;
}

bool CMasternodeSigner::SignMessage(std::string strMessage, std::string& errorMessage, vector<unsigned char>& vchSig, CKey key)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    if (!key.SignCompact(ss.GetHash(), vchSig)) {
        errorMessage = _("Signing failed.");
        return false;
    }

    return true;
}

bool CMasternodeSigner::VerifyMessage(CPubKey pubkey, vector<unsigned char>& vchSig, std::string strMessage, std::string& errorMessage)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey2;
    if (!pubkey2.RecoverCompact(ss.GetHash(), vchSig)) {
        errorMessage = _("Error recovering public key.");
        return false;
    }

    if (fDebug && pubkey2.GetID() != pubkey.GetID())
        LogPrintf("CMasternodeSigner::VerifyMessage -- keys don't match: %s %s\n", pubkey2.GetID().ToString(), pubkey.GetID().ToString());

    return (pubkey2.GetID() == pubkey.GetID());
}

bool CMasternodeSigner::SetCollateralAddress(std::string strAddress)
{
    CBitcoinAddress address;
    if (!address.SetString(strAddress)) {
        LogPrintf("CMasternodeSigner::SetCollateralAddress - Invalid collateral address\n");
        return false;
    }
    collateralPubKey = GetScriptForDestination(address.Get());
    return true;
}

bool CMasternodeSigner::IsCollateralAmount(const CAmount& amount)
{
    return
            amount == 3500  * COIN ||
            amount == 4300  * COIN ||
            amount == 4600  * COIN ||
            amount == 4850  * COIN ||
            amount == 5050  * COIN ||
            amount == 5300  * COIN ||
            amount == 5600  * COIN ||
            amount == 5950  * COIN ||
            amount == 6300  * COIN ||
            amount == 7000  * COIN ||
            amount == 7350  * COIN ||
            amount == 7700  * COIN ||
            amount == 8050  * COIN ||
            amount == 8400  * COIN ||
            amount == 8750  * COIN ||
            amount == 9500  * COIN;
}
