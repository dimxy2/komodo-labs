// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include "wallet_ismine.h"

#include "key.h"
#include "keystore.h"
#include "script/script.h"
#include "script/standard.h"
#include "cc/eval.h"

#include <boost/foreach.hpp>

#include "utilstrencodings.h"

using namespace std;

typedef vector<unsigned char> valtype;

unsigned int HaveKeys(const vector<valtype>& pubkeys, const CKeyStore& keystore)
{
    unsigned int nResult = 0;
    BOOST_FOREACH(const valtype& pubkey, pubkeys)
    {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (keystore.HaveKey(keyID))
            ++nResult;
    }
    return nResult;
}

isminetype IsMine(const CKeyStore &keystore, const CTxDestination& dest)
{
    CScript script = GetScriptForDestination(dest);
    return IsMine(keystore, script);
}

std::vector<uint8_t> Mypubkey();
CPubKey pubkey2pk(std::vector<uint8_t> pubkey);

isminetype IsMine(const CKeyStore &keystore, const CScript& _scriptPubKey)
{
    vector<valtype> vSolutions;
    txnouttype whichType;
    CScript scriptPubKey = _scriptPubKey;

    std::cerr << "::IsMine() for scriptPubKey=" << _scriptPubKey.ToString() << std::endl;
    if (scriptPubKey.IsCheckLockTimeVerify())
    {
        uint8_t pushOp = scriptPubKey[0];
        uint32_t scriptStart = pushOp + 3;

        // continue with post CLTV script
        scriptPubKey = CScript(scriptPubKey.size() > scriptStart ? scriptPubKey.begin() + scriptStart : scriptPubKey.end(), scriptPubKey.end());
    }

    if (!Solver(scriptPubKey, whichType, vSolutions)) {
        if (keystore.HaveWatchOnly(scriptPubKey))
            return ISMINE_WATCH_ONLY;
        return ISMINE_NO;
    }

    for(auto v : vSolutions)
        std::cerr << "::IsMine( ) vSolutions=" << HexStr(v) << std::endl;

    CPubKey myPubkey = pubkey2pk(Mypubkey());
    std::cerr << "CWallet::IsMine( ) KeyId for Mypubkey=" << myPubkey.GetID().ToString() << std::endl;

    CKeyID keyID;
    switch (whichType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        break;
    case TX_CRYPTOCONDITION:
        // for now, default is that the first value returned will be the script, subsequent values will be
        // pubkeys. if we have the first pub key in our wallet, we consider this spendable
        if (vSolutions.size() > 1)
        {
            std::cerr << "::IsMine( ) vSolutions.size() > 1" << std::endl;

            keyID = CPubKey(vSolutions[1]).GetID();
            std::cerr << "::IsMine( ) keyID=" << keyID.ToString() << std::endl;

            if (keystore.HaveKey(keyID)) {
                std::cerr << "::IsMine( ) HaveKey(keyID)=true returning ISMINE_SPENDABLE"  << std::endl;
                return ISMINE_SPENDABLE;
            }
        }
        break;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if (keystore.HaveKey(keyID)) {
            std::cerr << "::IsMine( ) TX_PUBKEY returning ISMINE_SPENDABLE" << std::endl;
            return ISMINE_SPENDABLE;
        }
        break;
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (keystore.HaveKey(keyID)) {
            std::cerr << "::IsMine( ) TX_PUBKEYHASH returning ISMINE_SPENDABLE" << std::endl;
            return ISMINE_SPENDABLE;
        }
        break;
    case TX_SCRIPTHASH:
    {
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            isminetype ret = IsMine(keystore, subscript);
            if (ret == ISMINE_SPENDABLE) {
                std::cerr << "::IsMine( ) TX_SCRIPTHASH returning ISMINE_SPENDABLE" << std::endl;
                return ret;
            }
        }
        break;
    }
    case TX_MULTISIG:
    {
        // Only consider transactions "mine" if we own ALL the
        // keys involved. Multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        vector<valtype> keys(vSolutions.begin()+1, vSolutions.begin()+vSolutions.size()-1);
        if (HaveKeys(keys, keystore) == keys.size())
            return ISMINE_SPENDABLE;
        break;
    }
    }

    if (keystore.HaveWatchOnly(scriptPubKey)) {
        std::cerr << "::IsMine( ) returning ISMINE_WATCH_ONLY" << std::endl;
        return ISMINE_WATCH_ONLY;
    }

    std::cerr << "::IsMine( ) returning ISMINE_NO" << std::endl;
    return ISMINE_NO;
}
