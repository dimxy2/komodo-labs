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

CTransaction MakeImportCoinTransaction(const TxProof proof, const CTransaction burnTx, const std::vector<CTxOut> payouts, uint32_t nExpiryHeightOverride)
{
    //std::vector<uint8_t> payload = E_MARSHAL(ss << EVAL_IMPORTCOIN);
    CScript scriptSig;

    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), komodo_nextheight());
    if (mtx.fOverwintered) 
        mtx.nExpiryHeight = 0;
    mtx.vout = payouts;

    if (mtx.vout.size() == 0)
        return mtx;

    auto importData = E_MARSHAL(ss << proof; ss << burnTx);

    // if it is tokens:
    vscript_t vopret;
    GetOpReturnData(mtx.vout.back().scriptPubKey, vopret);
    if (!vopret.empty() && vopret.begin()[0] == EVAL_TOKENS) {
        vscript_t vorigpubkey;
        uint8_t funcId;
        std::vector <std::pair<uint8_t, vscript_t>> oprets;
        std::string name, desc;
        uint256 srctokenid;

        DecodeTokenImportOpRet(mtx.vout.back().scriptPubKey, vorigpubkey, name, desc, srctokenid, oprets);   // parse token 'i' opret
        mtx.vout.pop_back(); //remove old token opret

        oprets.push_back(std::make_pair(OPRETID_IMPORTDATA, importData));
        mtx.vout.push_back(CTxOut(0, EncodeTokenImportOpRet(vorigpubkey, name, desc, srctokenid, oprets)));   // make new token 'i' opret with importData
                                                                                    
        scriptSig << E_MARSHAL(ss << EVAL_IMPORTCOIN);      // make payload for tokens
    }
    else {
        //mtx.vout.insert(mtx.vout.begin(), CTxOut(0, CScript() << OP_RETURN << importData));     // import tx's opret was in vout[0] 
        mtx.vout.insert(mtx.vout.begin(), CTxOut(0, CScript() << OP_RETURN << importData));     // import tx's opret now is in the vout's tail
                                                                                                
        scriptSig << E_MARSHAL(ss << EVAL_IMPORTCOIN);      // simple payload for coins
    }

    mtx.vin.push_back(CTxIn(COutPoint(burnTx.GetHash(), 10e8), scriptSig));


	if (nExpiryHeightOverride != 0)
		mtx.nExpiryHeight = nExpiryHeightOverride;  //this is for validation code, to make a tx used for validating the import tx
    return CTransaction(mtx);
}


CTxOut MakeBurnOutput(CAmount value, uint32_t targetCCid, std::string targetSymbol, const std::vector<CTxOut> payouts,std::vector<uint8_t> rawproof)
{
    std::vector<uint8_t> opret;
    opret = E_MARSHAL(ss << (uint8_t)EVAL_IMPORTCOIN;   // add opret id
                      ss << VARINT(targetCCid);
                      ss << targetSymbol;
                      ss << SerializeHash(payouts);
                      ss << rawproof);
    return CTxOut(value, CScript() << OP_RETURN << opret);
}


bool UnmarshalImportTx(const CTransaction &importTx, TxProof &proof, CTransaction &burnTx, std::vector<CTxOut> &payouts)
{
    if (importTx.vout.size() < 1) return false;
    
    std::vector<uint8_t> vData;
    //GetOpReturnData(importTx.vout[0].scriptPubKey, vData);  // now it is in the back;
    GetOpReturnData(importTx.vout.back().scriptPubKey, vData);
    if (vData.empty())
        return false;

    if (vData.begin()[0] == EVAL_TOKENS) {          // if it is tokens
        // get import data after token opret:
        std::vector<std::pair<uint8_t, vscript_t>>  oprets;
        vscript_t vorigpubkey;
        std::string name, desc;
        uint256 srctokenid;

        //if (DecodeTokenOpRet(importTx.vout.back().scriptPubKey, evalCodeInOpret, tokenid, voutTokenPubkeys, oprets) == 0)
        if (DecodeTokenImportOpRet(importTx.vout.back().scriptPubKey, vorigpubkey, name, desc, srctokenid, oprets) == 0)
            return false;

        GetOpretBlob(oprets, OPRETID_IMPORTDATA, vData);  // fetch import data after token opret

        // remove import data from token opret (it has not been in payouts)
        for (std::vector<std::pair<uint8_t, vscript_t>>::const_iterator i = oprets.begin(); i != oprets.end(); i++)
            if ((*i).first == OPRETID_IMPORTDATA) {
                oprets.erase(i);
                break;
            }

        payouts = std::vector<CTxOut>(importTx.vout.begin(), importTx.vout.end()-1);    
        payouts.push_back(CTxOut(0, EncodeTokenImportOpRet(vorigpubkey, name, desc, srctokenid, oprets)));   // make payouts token opret 
        
        CScript testScriptSig = (CScript() << E_MARSHAL(ss << EVAL_IMPORTCOIN));
        if (importTx.vin[0].scriptSig != testScriptSig)
            return false;
    }
    else {
        //payouts = std::vector<CTxOut>(importTx.vout.begin()+1, importTx.vout.end());   // see next
        payouts = std::vector<CTxOut>(importTx.vout.begin(), importTx.vout.end() - 1);   // remove opret, it is now in the tail
        if (importTx.vin[0].scriptSig != (CScript() << E_MARSHAL(ss << EVAL_IMPORTCOIN)))
            return false;
    }

    return importTx.vin.size() == 1 &&
           E_UNMARSHAL(vData, ss >> proof; ss >> burnTx);
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
        return E_UNMARSHAL(vburnOpret, ss >> evalCode;
                                       ss >> VARINT(*targetCCid);
                                       ss >> targetSymbol;
                                       ss >> payoutsHash;
                                       ss >> rawproof);
    }

    LOGSTREAM("importcoin", CCLOG_INFO, stream << "UnmarshalBurnTx() cannot unmarshal burn tx: incorrect evalcode" << std::endl);
    return false;
}


/*
 * Required by main
 */
CAmount GetCoinImportValue(const CTransaction &tx)
{
    TxProof proof;
    CTransaction burnTx;
    std::vector<CTxOut> payouts;

    if (UnmarshalImportTx(tx, proof, burnTx, payouts)) {
        if (burnTx.vout.size() > 0)  {
            vscript_t vburnOpret;

            GetOpReturnData(burnTx.vout.back().scriptPubKey, vburnOpret);
            if (vburnOpret.empty()) {
                LOGSTREAM("importcoin", CCLOG_INFO, stream << "GetCoinImportValue() empty burn opret" << std::endl);
                return 0;
            }

            if (vburnOpret.begin()[0] == EVAL_TOKENS) {      //if it is tokens
               
                CAmount ccOutput = 0;
                for (auto v : payouts)
                    if (v.scriptPubKey.IsPayToCryptoCondition())  // burned value goes to cc vout with dead pubkey
                        ccOutput += v.nValue;
                return ccOutput;
            }
            else
                return burnTx.vout.back().nValue;
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
