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

#include "crosschain.h"
#include "importcoin.h"
#include "cc/utils.h"
#include "coins.h"
#include "hash.h"
#include "script/cc.h"
#include "primitives/transaction.h"
#include "core_io.h"
#include "script/sign.h"
#include "wallet/wallet.h"

#include "cc/CCinclude.h"

int32_t komodo_nextheight();

// makes import tx for either coins or tokens
CTransaction MakeImportCoinTransaction(const ImportProof &proof, const CTransaction &burnTx, const std::vector<CTxOut> &payouts, uint32_t nExpiryHeightOverride)
{
    //std::vector<uint8_t> payload = E_MARSHAL(ss << EVAL_IMPORTCOIN);
    CScript scriptSig;

    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), komodo_nextheight());
    if (mtx.fOverwintered) 
        mtx.nExpiryHeight = 0;
    mtx.vout = payouts;
    if (mtx.vout.size() == 0)
        return CTransaction(mtx);

    // add special import tx vin:
    scriptSig << E_MARSHAL(ss << EVAL_IMPORTCOIN);      // simple payload for coins
    mtx.vin.push_back(CTxIn(COutPoint(burnTx.GetHash(), 10e8), scriptSig));

    if (nExpiryHeightOverride != 0)
        mtx.nExpiryHeight = nExpiryHeightOverride;  //this is for validation code, to make a tx used for validating the import tx

    auto importData = E_MARSHAL(ss << EVAL_IMPORTCOIN; ss << proof; ss << burnTx);  // added evalcode to differentiate importdata from token opret
    // if it is tokens:
    vscript_t vopret;
    GetOpReturnData(mtx.vout.back().scriptPubKey, vopret);

    if (!vopret.empty()) {
        std::vector<uint8_t> vorigpubkey;
        uint8_t funcId;
        std::vector <std::pair<uint8_t, vscript_t>> oprets;
        std::string name, desc;

        if (DecodeTokenCreateOpRet(mtx.vout.back().scriptPubKey, vorigpubkey, name, desc, oprets) == 'c') {    // parse token 'c' opret
            mtx.vout.pop_back(); //remove old token opret
            oprets.push_back(std::make_pair(OPRETID_IMPORTDATA, importData));
            mtx.vout.push_back(CTxOut(0, EncodeTokenCreateOpRet('c', vorigpubkey, name, desc, oprets)));   // make new token 'c' opret with importData                                                                                    
        }
        else {
            LOGSTREAM("importcoin", CCLOG_INFO, stream << "MakeImportCoinTransaction() incorrect token import opret" << std::endl);
        }
    }
    else { //no opret in coin payouts
        mtx.vout.push_back(CTxOut(0, CScript() << OP_RETURN << importData));     // import tx's opret now is in the vout's tail
    }

    return CTransaction(mtx);
}

// prev import tx (for compatibility), only coins
CTransaction MakeImportCoinTransactionVout0(const ImportProof &proof, const CTransaction &burnTx, const std::vector<CTxOut> &payouts, uint32_t nExpiryHeightOverride)
{
    std::vector<uint8_t> payload = E_MARSHAL(ss << EVAL_IMPORTCOIN);
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), komodo_nextheight());
    if (mtx.fOverwintered)
        mtx.nExpiryHeight = 0;
    mtx.vin.push_back(CTxIn(COutPoint(burnTx.GetHash(), 10e8), CScript() << payload));
    mtx.vout = payouts;
    auto importData = E_MARSHAL(ss << proof; ss << burnTx);
    mtx.vout.insert(mtx.vout.begin(), CTxOut(0, CScript() << OP_RETURN << importData));

    if (nExpiryHeightOverride != 0)
        mtx.nExpiryHeight = nExpiryHeightOverride;  //this is for construction of the tx used for validating importtx
    return CTransaction(mtx);
}


CTxOut MakeBurnOutput(CAmount value, uint32_t targetCCid, const std::string &targetSymbol, const std::vector<CTxOut> &payouts, const std::vector<uint8_t> &rawproof)
{
    std::vector<uint8_t> opret;
    opret = E_MARSHAL(ss << (uint8_t)EVAL_IMPORTCOIN;  // should mark burn opret to differentiate it from token opret
                      ss << VARINT(targetCCid);
                      ss << targetSymbol;
                      ss << SerializeHash(payouts);
                      ss << rawproof);
    return CTxOut(value, CScript() << OP_RETURN << opret);
}


bool UnmarshalImportTx(const CTransaction &importTx, ImportProof &proof, CTransaction &burnTx, std::vector<CTxOut> &payouts)
{
    if (importTx.vout.size() < 1) 
        return false;
    
    if (importTx.vin.size() != 1 || importTx.vin[0].scriptSig != (CScript() << E_MARSHAL(ss << EVAL_IMPORTCOIN))) {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "UnmarshalImportTx() incorrect import tx vin" << std::endl);
        return false;
    }

    std::vector<uint8_t> vImportData;
    GetOpReturnData(importTx.vout.back().scriptPubKey, vImportData);
    if (vImportData.empty()) {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "UnmarshalImportTx() no opret" << std::endl);
        return false;
    }

    if (vImportData.begin()[0] == EVAL_TOKENS) {          // if it is tokens
        // get import data after token opret:
        std::vector<std::pair<uint8_t, vscript_t>>  oprets;
        std::vector<uint8_t> vorigpubkey;
        std::string name, desc;

        if (DecodeTokenCreateOpRet(importTx.vout.back().scriptPubKey, vorigpubkey, name, desc, oprets) == 0) {
            LOGSTREAM("importcoin", CCLOG_INFO, stream << "UnmarshalImportTx() could not decode token opret" << std::endl);
            return false;
        }

        GetOpretBlob(oprets, OPRETID_IMPORTDATA, vImportData);  // fetch import data after token opret
        for (std::vector<std::pair<uint8_t, vscript_t>>::const_iterator i = oprets.begin(); i != oprets.end(); i++)
            if ((*i).first == OPRETID_IMPORTDATA) {
                oprets.erase(i);            // remove import data from token opret to restore original payouts:
                break;
            }

        payouts = std::vector<CTxOut>(importTx.vout.begin(), importTx.vout.end()-1);       //exclude opret with import data 
        payouts.push_back(CTxOut(0, EncodeTokenCreateOpRet('c', vorigpubkey, name, desc, oprets)));   // make original payouts token opret (without import data)
    }
    else {
        //payouts = std::vector<CTxOut>(importTx.vout.begin()+1, importTx.vout.end());   // see next
        payouts = std::vector<CTxOut>(importTx.vout.begin(), importTx.vout.end() - 1);   // skip opret; and it is now in the back
    }

    uint8_t evalCode;
    bool retcode = E_UNMARSHAL(vImportData, ss >> evalCode; ss >> proof; ss >> burnTx);
    if (!retcode)
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "UnmarshalImportTx() could not unmarshal import data" << std::endl);
    return retcode;
}

// old format support, for old tx validation, for coins only
bool UnmarshalImportTxOld(const CTransaction &importTx, ImportProof &proof, CTransaction &burnTx, std::vector<CTxOut> &payouts)
{
    std::vector<uint8_t> vData;
    TxProof txproof;

    GetOpReturnData(importTx.vout[0].scriptPubKey, vData);
    if (importTx.vout.size() < 1) return false;
    payouts = std::vector<CTxOut>(importTx.vout.begin() + 1, importTx.vout.end());
    bool retcode = importTx.vin.size() == 1 &&
        importTx.vin[0].scriptSig == (CScript() << E_MARSHAL(ss << EVAL_IMPORTCOIN)) &&
        E_UNMARSHAL(vData, ss >> txproof; ss >> burnTx);

    if (retcode)
        proof = ImportProof(txproof);

    return retcode;
}

// old import tx format support with opret in vout[0], for old tx validation, for coins only
bool UnmarshalImportTxVout0(const CTransaction &importTx, ImportProof &proof, CTransaction &burnTx, std::vector<CTxOut> &payouts)
{
    std::vector<uint8_t> vData;

    GetOpReturnData(importTx.vout[0].scriptPubKey, vData);
    if (importTx.vout.size() < 1) 
        return false;
    payouts = std::vector<CTxOut>(importTx.vout.begin() + 1, importTx.vout.end());
    bool retcode = importTx.vin.size() == 1 &&
                   importTx.vin[0].scriptSig == (CScript() << E_MARSHAL(ss << EVAL_IMPORTCOIN)) &&
                   E_UNMARSHAL(vData, ss >> proof; ss >> burnTx);

    if( retcode )
        LOGSTREAM("importcoin", CCLOG_DEBUG1, stream << "UnmarshalImportTxVout0() parsed old import tx opret" << std::endl);
    return retcode;
}


bool UnmarshalBurnTx(const CTransaction &burnTx, std::string &targetSymbol, uint32_t *targetCCid, uint256 &payoutsHash,std::vector<uint8_t>&rawproof)
{
    std::vector<uint8_t> vburnOpret; uint32_t ccid = 0;
    uint8_t evalCode;

    if (burnTx.vout.size() == 0) 
        return false;

    GetOpReturnData(burnTx.vout.back().scriptPubKey, vburnOpret);
    if (vburnOpret.empty()) {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "UnmarshalBurnTx() cannot unmarshal burn tx: empty burn opret" << std::endl);
        return false;
    }

    if (vburnOpret.begin()[0] == EVAL_TOKENS) {      //if it is tokens
        std::vector<std::pair<uint8_t, vscript_t>>  oprets;
        uint256 tokenid;
        uint8_t evalCodeInOpret;
        std::vector<CPubKey> voutTokenPubkeys;

        //skip token opret:
        if (DecodeTokenOpRet(burnTx.vout.back().scriptPubKey, evalCodeInOpret, tokenid, voutTokenPubkeys, oprets) == 0)
            return false;

        GetOpretBlob(oprets, OPRETID_BURNDATA, vburnOpret);  // fetch burnOpret after token opret
    }
    if (vburnOpret.begin()[0] == EVAL_IMPORTCOIN) {
        uint8_t evalCode;
        return E_UNMARSHAL(vburnOpret,  ss >> evalCode;
                                        ss >> VARINT(*targetCCid);
                                        ss >> targetSymbol;
                                        ss >> payoutsHash;
                                        ss >> rawproof);
    }
    else {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "UnmarshalBurnTx() invalid eval code in opret" << std::endl);
        return false;
    }
}

// old format support for compatibility (no eval code in opret)
bool UnmarshalBurnTxOld(const CTransaction &burnTx, std::string &targetSymbol, uint32_t *targetCCid, uint256 &payoutsHash, std::vector<uint8_t>&rawproof)
{
    std::vector<uint8_t> burnOpret; uint32_t ccid = 0;
    if (burnTx.vout.size() == 0) return false;
    GetOpReturnData(burnTx.vout.back().scriptPubKey, burnOpret);
    bool retcode = E_UNMARSHAL(burnOpret,   ss >> VARINT(*targetCCid);
                                            ss >> targetSymbol;
                                            ss >> payoutsHash;
                                            ss >> rawproof);
    if( retcode )
        LOGSTREAM("importcoin", CCLOG_DEBUG1, stream << "UnmarshalBurnTxOld() parsed old burn tx opret" << std::endl);
    return retcode;
}

/*
 * Required by main
 * in main.cpp the returned value is used as valueIn for the import tx 
 * the returned calue = burned value (which also includes extra txfee for relaying and miners. See migrate_createburntransaction)
 */
CAmount GetCoinImportValue(const CTransaction &tx)
{
    ImportProof proof;
    CTransaction burnTx;
    std::vector<CTxOut> payouts;

    bool isNewImportTx = false;
    if ((isNewImportTx = UnmarshalImportTx(tx, proof, burnTx, payouts)) || UnmarshalImportTxVout0(tx, proof, burnTx, payouts)) {
        if (burnTx.vout.size() > 0)  {
            vscript_t vburnOpret;

            GetOpReturnData(burnTx.vout.back().scriptPubKey, vburnOpret);
            if (vburnOpret.empty()) {
                LOGSTREAM("importcoin", CCLOG_INFO, stream << "GetCoinImportValue() empty burn opret" << std::endl);
                return 0;
            }

            if (isNewImportTx && vburnOpret.begin()[0] == EVAL_TOKENS) {      //if it is tokens
             
                uint8_t evalCodeInOpret;
                uint256 tokenid;
                std::vector<CPubKey> voutTokenPubkeys;
                std::vector<std::pair<uint8_t, vscript_t>>  oprets;

                if (DecodeTokenOpRet(tx.vout.back().scriptPubKey, evalCodeInOpret, tokenid, voutTokenPubkeys, oprets) == 0)
                    return 0;

                uint8_t nonfungibleEvalCode = 0;
                vscript_t vnonfungibleOpret;

                GetOpretBlob(oprets, OPRETID_NONFUNGIBLEDATA, vnonfungibleOpret);
                if (!vnonfungibleOpret.empty())
                    nonfungibleEvalCode = vnonfungibleOpret.begin()[0];

                // calc outputs for burn tx
                int64_t ccBurnOutputs = 0;
                for (auto v : burnTx.vout)
                    if (v.scriptPubKey.IsPayToCryptoCondition() &&
                        CTxOut(v.nValue, v.scriptPubKey) == MakeTokensCC1vout(nonfungibleEvalCode ? nonfungibleEvalCode : EVAL_TOKENS, v.nValue, pubkey2pk(ParseHex(CC_BURNPUBKEY))))  // burned to dead pubkey
                        ccBurnOutputs += v.nValue;

                return ccBurnOutputs + burnTx.vout.back().nValue;   // total token burned value
            }
            else
                return burnTx.vout.back().nValue; // coin burned value
        }
    }
    return 0;
}

/*
 * CoinImport is different enough from normal script execution that it's not worth
 * making all the mods neccesary in the interpreter to do the dispatch correctly.
 */
bool VerifyCoinImport(const CScript& scriptSig, TransactionSignatureChecker& checker, CValidationState &state)
{
    auto pc = scriptSig.begin();
    opcodetype opcode;
    std::vector<uint8_t> evalScript;

    auto f = [&] () {
        if (!scriptSig.GetOp(pc, opcode, evalScript))
            return false;
        if (pc != scriptSig.end())
            return false;
        if (evalScript.size() == 0)
            return false;
        if (evalScript.begin()[0] != EVAL_IMPORTCOIN)   
            return false;
        // Ok, all looks good so far...
        CC *cond = CCNewEval(evalScript);
        bool out = checker.CheckEvalCondition(cond);
        cc_free(cond);
        return out;
    };

    return f() ? true : state.Invalid(false, 0, "invalid-coin-import");
}


void AddImportTombstone(const CTransaction &importTx, CCoinsViewCache &inputs, int nHeight)
{
    uint256 burnHash = importTx.vin[0].prevout.hash;
    //fprintf(stderr,"add tombstone.(%s)\n",burnHash.GetHex().c_str());
    CCoinsModifier modifier = inputs.ModifyCoins(burnHash);
    modifier->nHeight = nHeight;
    modifier->nVersion = 4;//1;
    modifier->vout.push_back(CTxOut(0, CScript() << OP_0));
}


void RemoveImportTombstone(const CTransaction &importTx, CCoinsViewCache &inputs)
{
    uint256 burnHash = importTx.vin[0].prevout.hash;
    //fprintf(stderr,"remove tombstone.(%s)\n",burnHash.GetHex().c_str());
    inputs.ModifyCoins(burnHash)->Clear();
}


int ExistsImportTombstone(const CTransaction &importTx, const CCoinsViewCache &inputs)
{
    uint256 burnHash = importTx.vin[0].prevout.hash;
    //fprintf(stderr,"check tombstone.(%s) in %s\n",burnHash.GetHex().c_str(),importTx.GetHash().GetHex().c_str());
    return inputs.HaveCoins(burnHash);
}