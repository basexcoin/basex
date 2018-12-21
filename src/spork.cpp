// Copyright (c) 2014-2016 The Dash developers
// Copyright (c) 2016-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "spork.h"
#include "base58.h"
#include "key.h"
#include "main.h"
#include "masternode-budget.h"
#include "masternode-helpers.h"
#include "net.h"
#include "protocol.h"
#include "sync.h"
#include "sporkdb.h"
#include "util.h"
#include <boost/lexical_cast.hpp>

using namespace std;
using namespace boost;

class CSporkMessage;
class CSporkManager;

CSporkManager sporkManager;

std::map<uint256, CSporkMessage> mapSporks;
std::map<int, CSporkMessage> mapSporksActive;

// BSA: on startup load spork values from previous session if they exist in the sporkDB
void LoadSporksFromDB()
{
    for (int i = SPORK_START; i <= SPORK_END; ++i) {
        // Since not all spork IDs are in use, we have to exclude undefined IDs
        std::string strSpork = sporkManager.GetSporkNameByID(i);
        if (strSpork == "Unknown") continue;

        // attempt to read spork from sporkDB
        CSporkMessage spork;
        if (!pSporkDB->ReadSpork(i, spork)) {
            LogPrintf("%s : no previous value for %s found in database\n", __func__, strSpork);
            continue;
        }

        // add spork to memory
        mapSporks[spork.GetHash()] = spork;
        mapSporksActive[spork.nSporkID] = spork;
        std::time_t result = spork.nValue;
        // If SPORK Value is greater than 1,000,000 assume it's actually a Date and then convert to a more readable format
        if (spork.nValue > 1000000) {
            LogPrintf("%s : loaded spork %s with value %d : %s", __func__,
                      sporkManager.GetSporkNameByID(spork.nSporkID), spork.nValue,
                      std::ctime(&result));
        } else {
            LogPrintf("%s : loaded spork %s with value %d\n", __func__,
                      sporkManager.GetSporkNameByID(spork.nSporkID), spork.nValue);
        }
    }
}

void ProcessSpork(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if (fLiteMode) return; //disable all masternode related functionality

    if (strCommand == "spork") {
        //LogPrintf("ProcessSpork::spork\n");
        CDataStream vMsg(vRecv);
        CSporkMessage spork;
        vRecv >> spork;

        if (chainActive.Tip() == NULL) return;

        // Ignore spork messages about unknown/deleted sporks
        std::string strSpork = sporkManager.GetSporkNameByID(spork.nSporkID);
        if (strSpork == "Unknown") return;

        uint256 hash = spork.GetHash();
        if (mapSporksActive.count(spork.nSporkID)) {
            if (mapSporksActive[spork.nSporkID].nTimeSigned >= spork.nTimeSigned) {
                if (fDebug) LogPrintf("spork - seen %s block %d \n", hash.ToString(), chainActive.Tip()->nHeight);
                return;
            } else {
                if (fDebug) LogPrintf("spork - got updated spork %s block %d \n", hash.ToString(), chainActive.Tip()->nHeight);
            }
        }

        LogPrintf("spork - new %s ID %d Time %d bestHeight %d\n", hash.ToString(), spork.nSporkID, spork.nValue, chainActive.Tip()->nHeight);

        if (!sporkManager.CheckSignature(spork)) {
            LogPrintf("spork - invalid signature\n");
            Misbehaving(pfrom->GetId(), 100);
            return;
        }

        mapSporks[hash] = spork;
        mapSporksActive[spork.nSporkID] = spork;
        sporkManager.Relay(spork);

        // BSA: add to spork database.
        pSporkDB->WriteSpork(spork.nSporkID, spork);
    }
    if (strCommand == "getsporks") {
        std::map<int, CSporkMessage>::iterator it = mapSporksActive.begin();

        while (it != mapSporksActive.end()) {
            pfrom->PushMessage("spork", it->second);
            it++;
        }
    }
}


// grab the value of the spork on the network, or the default
int64_t GetSporkValue(int nSporkID)
{
    int64_t r = -1;

    if (mapSporksActive.count(nSporkID)) {
        r = mapSporksActive[nSporkID].nValue;
    } else {
        if (nSporkID == SPORK_2_SWIFTTX) r = SPORK_2_SWIFTTX_DEFAULT;
        if (nSporkID == SPORK_3_SWIFTTX_BLOCK_FILTERING) r = SPORK_3_SWIFTTX_BLOCK_FILTERING_DEFAULT;
        if (nSporkID == SPORK_5_MAX_VALUE) r = SPORK_5_MAX_VALUE_DEFAULT;
        if (nSporkID == SPORK_7_MASTERNODE_SCANNING) r = SPORK_7_MASTERNODE_SCANNING_DEFAULT;
        if (nSporkID == SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT) r = SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT_DEFAULT;
        if (nSporkID == SPORK_9_MASTERNODE_BUDGET_ENFORCEMENT) r = SPORK_9_MASTERNODE_BUDGET_ENFORCEMENT_DEFAULT;
        if (nSporkID == SPORK_10_MASTERNODE_PAY_UPDATED_NODES) r = SPORK_10_MASTERNODE_PAY_UPDATED_NODES_DEFAULT;
        if (nSporkID == SPORK_11_RESET_BUDGET) r = SPORK_11_RESET_BUDGET_DEFAULT;
        if (nSporkID == SPORK_12_RECONSIDER_BLOCKS) r = SPORK_12_RECONSIDER_BLOCKS_DEFAULT;
        if (nSporkID == SPORK_13_ENABLE_SUPERBLOCKS) r = SPORK_13_ENABLE_SUPERBLOCKS_DEFAULT;
        if (nSporkID == SPORK_14_NEW_PROTOCOL_ENFORCEMENT) r = SPORK_14_NEW_PROTOCOL_ENFORCEMENT_DEFAULT;
        if (nSporkID == SPORK_15_NEW_PROTOCOL_ENFORCEMENT_2) r = SPORK_15_NEW_PROTOCOL_ENFORCEMENT_2_DEFAULT;
        if (nSporkID == SPORK_16_MN_WINNER_MINIMUM_AGE) r = SPORK_16_MN_WINNER_MINIMUM_AGE_DEFAULT;
        if (nSporkID == SPORK_17_REWARDS_SWITCH) r = SPORK_17_REWARDS_SWITCH_DEFAULT;
        if (nSporkID == SPORK_18_CURRENT_MN_COLLATERAL) r = SPORK_18_CURRENT_MN_COLLATERAL_DEFAULT;
        if (nSporkID == SPORK_19_COLLATERAL_3500) r = SPORK_19_COLLATERAL_3500_DEFAULT;
        if (nSporkID == SPORK_20_COLLATERAL_4300) r = SPORK_20_COLLATERAL_4300_DEFAULT;
        if (nSporkID == SPORK_21_COLLATERAL_4600) r = SPORK_21_COLLATERAL_4600_DEFAULT;
        if (nSporkID == SPORK_22_COLLATERAL_4850) r = SPORK_22_COLLATERAL_4850_DEFAULT;
        if (nSporkID == SPORK_23_COLLATERAL_5050) r = SPORK_23_COLLATERAL_5050_DEFAULT;
        if (nSporkID == SPORK_24_COLLATERAL_5300) r = SPORK_24_COLLATERAL_5300_DEFAULT;
        if (nSporkID == SPORK_25_COLLATERAL_5600) r = SPORK_25_COLLATERAL_5600_DEFAULT;
        if (nSporkID == SPORK_26_COLLATERAL_5950) r = SPORK_26_COLLATERAL_5950_DEFAULT;
        if (nSporkID == SPORK_27_COLLATERAL_6300) r = SPORK_27_COLLATERAL_6300_DEFAULT;
        if (nSporkID == SPORK_28_COLLATERAL_6650) r = SPORK_28_COLLATERAL_6650_DEFAULT;
        if (nSporkID == SPORK_29_COLLATERAL_7000) r = SPORK_29_COLLATERAL_7000_DEFAULT;
        if (nSporkID == SPORK_30_COLLATERAL_7350) r = SPORK_30_COLLATERAL_7350_DEFAULT;
        if (nSporkID == SPORK_31_COLLATERAL_7700) r = SPORK_31_COLLATERAL_7700_DEFAULT;
        if (nSporkID == SPORK_32_COLLATERAL_8050) r = SPORK_32_COLLATERAL_8050_DEFAULT;
        if (nSporkID == SPORK_33_COLLATERAL_8400) r = SPORK_33_COLLATERAL_8400_DEFAULT;
        if (nSporkID == SPORK_34_COLLATERAL_8750) r = SPORK_34_COLLATERAL_8750_DEFAULT;
        if (nSporkID == SPORK_35_COLLATERAL_9500) r = SPORK_35_COLLATERAL_9500_DEFAULT;

        if (r == -1) LogPrintf("GetSpork::Unknown Spork %d\n", nSporkID);
    }

    return r;
}

// grab the spork value, and see if it's off
bool IsSporkActive(int nSporkID)
{
    int64_t r = GetSporkValue(nSporkID);
    if (r == -1) return false;
    return r < GetTime();
}

void ReprocessBlocks(int nBlocks)
{
    std::map<uint256, int64_t>::iterator it = mapRejectedBlocks.begin();
    while (it != mapRejectedBlocks.end()) {
        //use a window twice as large as is usual for the nBlocks we want to reset
        if ((*it).second > GetTime() - (nBlocks * 60 * 5)) {
            BlockMap::iterator mi = mapBlockIndex.find((*it).first);
            if (mi != mapBlockIndex.end() && (*mi).second) {
                LOCK(cs_main);

                CBlockIndex* pindex = (*mi).second;
                LogPrintf("ReprocessBlocks - %s\n", (*it).first.ToString());

                CValidationState state;
                ReconsiderBlock(state, pindex);
            }
        }
        ++it;
    }

    CValidationState state;
    {
        LOCK(cs_main);
        DisconnectBlocksAndReprocess(nBlocks);
    }

    if (state.IsValid()) {
        ActivateBestChain(state);
    }
}

bool CSporkManager::CheckSignature(CSporkMessage& spork)
{
    //note: need to investigate why this is failing
    std::string strMessage = boost::lexical_cast<std::string>(spork.nSporkID) + boost::lexical_cast<std::string>(spork.nValue) + boost::lexical_cast<std::string>(spork.nTimeSigned);
    CPubKey pubkeynew(ParseHex(Params().SporkKey()));
    std::string errorMessage = "";
    if (masternodeSigner.VerifyMessage(pubkeynew, spork.vchSig, strMessage, errorMessage)) {
        return true;
    }

    return false;
}

bool CSporkManager::Sign(CSporkMessage& spork)
{
    std::string strMessage = boost::lexical_cast<std::string>(spork.nSporkID) + boost::lexical_cast<std::string>(spork.nValue) + boost::lexical_cast<std::string>(spork.nTimeSigned);

    CKey key2;
    CPubKey pubkey2;
    std::string errorMessage = "";

    if (!masternodeSigner.SetKey(strMasterPrivKey, errorMessage, key2, pubkey2)) {
        LogPrintf("CMasternodePayments::Sign - ERROR: Invalid masternodeprivkey: '%s'\n", errorMessage);
        return false;
    }

    if (!masternodeSigner.SignMessage(strMessage, errorMessage, spork.vchSig, key2)) {
        LogPrintf("CMasternodePayments::Sign - Sign message failed");
        return false;
    }

    if (!masternodeSigner.VerifyMessage(pubkey2, spork.vchSig, strMessage, errorMessage)) {
        LogPrintf("CMasternodePayments::Sign - Verify message failed");
        return false;
    }

    return true;
}

bool CSporkManager::UpdateSpork(int nSporkID, int64_t nValue)
{
    CSporkMessage msg;
    msg.nSporkID = nSporkID;
    msg.nValue = nValue;
    msg.nTimeSigned = GetTime();

    if (Sign(msg)) {
        Relay(msg);
        mapSporks[msg.GetHash()] = msg;
        mapSporksActive[nSporkID] = msg;
        return true;
    }

    return false;
}

void CSporkManager::Relay(CSporkMessage& msg)
{
    CInv inv(MSG_SPORK, msg.GetHash());
    RelayInv(inv);
}

bool CSporkManager::SetPrivKey(std::string strPrivKey)
{
    CSporkMessage msg;

    // Test signing successful, proceed
    strMasterPrivKey = strPrivKey;

    Sign(msg);

    if (CheckSignature(msg)) {
        LogPrintf("CSporkManager::SetPrivKey - Successfully initialized as spork signer\n");
        return true;
    } else {
        return false;
    }
}

int CSporkManager::GetSporkIDByName(std::string strName)
{
    if (strName == "SPORK_2_SWIFTTX") return SPORK_2_SWIFTTX;
    if (strName == "SPORK_3_SWIFTTX_BLOCK_FILTERING") return SPORK_3_SWIFTTX_BLOCK_FILTERING;
    if (strName == "SPORK_5_MAX_VALUE") return SPORK_5_MAX_VALUE;
    if (strName == "SPORK_7_MASTERNODE_SCANNING") return SPORK_7_MASTERNODE_SCANNING;
    if (strName == "SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT") return SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT;
    if (strName == "SPORK_9_MASTERNODE_BUDGET_ENFORCEMENT") return SPORK_9_MASTERNODE_BUDGET_ENFORCEMENT;
    if (strName == "SPORK_10_MASTERNODE_PAY_UPDATED_NODES") return SPORK_10_MASTERNODE_PAY_UPDATED_NODES;
    if (strName == "SPORK_11_RESET_BUDGET") return SPORK_11_RESET_BUDGET;
    if (strName == "SPORK_12_RECONSIDER_BLOCKS") return SPORK_12_RECONSIDER_BLOCKS;
    if (strName == "SPORK_13_ENABLE_SUPERBLOCKS") return SPORK_13_ENABLE_SUPERBLOCKS;
    if (strName == "SPORK_14_NEW_PROTOCOL_ENFORCEMENT") return SPORK_14_NEW_PROTOCOL_ENFORCEMENT;
    if (strName == "SPORK_15_NEW_PROTOCOL_ENFORCEMENT_2") return SPORK_15_NEW_PROTOCOL_ENFORCEMENT_2;
    if (strName == "SPORK_16_MN_WINNER_MINIMUM_AGE") return SPORK_16_MN_WINNER_MINIMUM_AGE;
    if (strName == "SPORK_17_REWARDS_SWITCH") return SPORK_17_REWARDS_SWITCH;
    if (strName == "SPORK_18_CURRENT_MN_COLLATERAL") return SPORK_18_CURRENT_MN_COLLATERAL;
    if (strName == "SPORK_19_COLLATERAL_3500") return SPORK_19_COLLATERAL_3500;
    if (strName == "SPORK_20_COLLATERAL_4300") return SPORK_20_COLLATERAL_4300;
    if (strName == "SPORK_21_COLLATERAL_4600") return SPORK_21_COLLATERAL_4600;
    if (strName == "SPORK_22_COLLATERAL_4850") return SPORK_22_COLLATERAL_4850;
    if (strName == "SPORK_23_COLLATERAL_5050") return SPORK_23_COLLATERAL_5050;
    if (strName == "SPORK_24_COLLATERAL_5300") return SPORK_24_COLLATERAL_5300;
    if (strName == "SPORK_25_COLLATERAL_5600") return SPORK_25_COLLATERAL_5600;
    if (strName == "SPORK_26_COLLATERAL_5950") return SPORK_26_COLLATERAL_5950;
    if (strName == "SPORK_27_COLLATERAL_6300") return SPORK_27_COLLATERAL_6300;
    if (strName == "SPORK_28_COLLATERAL_6650") return SPORK_28_COLLATERAL_6650;
    if (strName == "SPORK_29_COLLATERAL_7000") return SPORK_29_COLLATERAL_7000;
    if (strName == "SPORK_30_COLLATERAL_7350") return SPORK_30_COLLATERAL_7350;
    if (strName == "SPORK_31_COLLATERAL_7700") return SPORK_31_COLLATERAL_7700;
    if (strName == "SPORK_32_COLLATERAL_8050") return SPORK_32_COLLATERAL_8050;
    if (strName == "SPORK_33_COLLATERAL_8400") return SPORK_33_COLLATERAL_8400;
    if (strName == "SPORK_34_COLLATERAL_8750") return SPORK_34_COLLATERAL_8750;
    if (strName == "SPORK_35_COLLATERAL_9500") return SPORK_35_COLLATERAL_9500;

    return -1;
}

std::string CSporkManager::GetSporkNameByID(int id)
{
    if (id == SPORK_2_SWIFTTX) return "SPORK_2_SWIFTTX";
    if (id == SPORK_3_SWIFTTX_BLOCK_FILTERING) return "SPORK_3_SWIFTTX_BLOCK_FILTERING";
    if (id == SPORK_5_MAX_VALUE) return "SPORK_5_MAX_VALUE";
    if (id == SPORK_7_MASTERNODE_SCANNING) return "SPORK_7_MASTERNODE_SCANNING";
    if (id == SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT) return "SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT";
    if (id == SPORK_9_MASTERNODE_BUDGET_ENFORCEMENT) return "SPORK_9_MASTERNODE_BUDGET_ENFORCEMENT";
    if (id == SPORK_10_MASTERNODE_PAY_UPDATED_NODES) return "SPORK_10_MASTERNODE_PAY_UPDATED_NODES";
    if (id == SPORK_11_RESET_BUDGET) return "SPORK_11_RESET_BUDGET";
    if (id == SPORK_12_RECONSIDER_BLOCKS) return "SPORK_12_RECONSIDER_BLOCKS";
    if (id == SPORK_13_ENABLE_SUPERBLOCKS) return "SPORK_13_ENABLE_SUPERBLOCKS";
    if (id == SPORK_14_NEW_PROTOCOL_ENFORCEMENT) return "SPORK_14_NEW_PROTOCOL_ENFORCEMENT";
    if (id == SPORK_15_NEW_PROTOCOL_ENFORCEMENT_2) return "SPORK_15_NEW_PROTOCOL_ENFORCEMENT_2";
    if (id == SPORK_16_MN_WINNER_MINIMUM_AGE) return "SPORK_16_MN_WINNER_MINIMUM_AGE";
    if (id == SPORK_17_REWARDS_SWITCH) return "SPORK_17_REWARDS_SWITCH";
    if (id == SPORK_18_CURRENT_MN_COLLATERAL) return "SPORK_18_CURRENT_MN_COLLATERAL";
    if (id == SPORK_19_COLLATERAL_3500) return "SPORK_19_COLLATERAL_3500";
    if (id == SPORK_20_COLLATERAL_4300) return "SPORK_20_COLLATERAL_4300";
    if (id == SPORK_21_COLLATERAL_4600) return "SPORK_21_COLLATERAL_4600";
    if (id == SPORK_22_COLLATERAL_4850) return "SPORK_22_COLLATERAL_4850";
    if (id == SPORK_23_COLLATERAL_5050) return "SPORK_23_COLLATERAL_5050";
    if (id == SPORK_24_COLLATERAL_5300) return "SPORK_24_COLLATERAL_5300";
    if (id == SPORK_25_COLLATERAL_5600) return "SPORK_25_COLLATERAL_5600";
    if (id == SPORK_26_COLLATERAL_5950) return "SPORK_26_COLLATERAL_5950";
    if (id == SPORK_27_COLLATERAL_6300) return "SPORK_27_COLLATERAL_6300";
    if (id == SPORK_28_COLLATERAL_6650) return "SPORK_28_COLLATERAL_6650";
    if (id == SPORK_29_COLLATERAL_7000) return "SPORK_29_COLLATERAL_7000";
    if (id == SPORK_30_COLLATERAL_7350) return "SPORK_30_COLLATERAL_7350";
    if (id == SPORK_31_COLLATERAL_7700) return "SPORK_31_COLLATERAL_7700";
    if (id == SPORK_32_COLLATERAL_8050) return "SPORK_32_COLLATERAL_8050";
    if (id == SPORK_33_COLLATERAL_8400) return "SPORK_33_COLLATERAL_8400";
    if (id == SPORK_34_COLLATERAL_8750) return "SPORK_34_COLLATERAL_8750";
    if (id == SPORK_35_COLLATERAL_9500) return "SPORK_35_COLLATERAL_9500";
    
    return "Unknown";
}
