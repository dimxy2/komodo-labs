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

CTransaction MakeImportCoinTransaction(const TxProof proof, const CTransaction burnTx, const std::vector<CTxOut> payouts, CPubKey vinPubkey, uint32_t nExpiryHeightOverride)
{
    //std::vector<uint8_t> payload = E_MARSHAL(ss << EVAL_IMPORTCOIN);
    CScript scriptSig;
    if (vinPubkey.IsValid()) {  
        // make payload for tokens:
        CC *cond = MakeCCcond1(EVAL_IMPORTCOIN, vinPubkey);
        scriptSig = CCSig(cond);
        cc_free(cond);
    }
    else {
        // simple payload for coins:
        scriptSig << E_MARSHAL(ss << EVAL_IMPORTCOIN);
    }

    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), komodo_nextheight());
    if (mtx.fOverwintered) 
        mtx.nExpiryHeight = 0;
    mtx.vin.push_back(CTxIn(COutPoint(burnTx.GetHash(), 10e8), scriptSig));
    mtx.vout = payouts;

    auto importData = E_MARSHAL(ss << proof; ss << burnTx);

    // if it is tokens:
    vopret_t vopret;
    GetOpReturnData(mtx.vout.back().scriptPubKey, vopret);
    if (!vopret.empty() && vopret.begin()[0] == EVAL_TOKENS) {
        CScript scriptTokensOpret = mtx.vout.back().scriptPubKey;
        mtx.vout.pop_back(); //remove old opret
        mtx.vout.push_back(CTxOut(0, scriptTokensOpret << (uint8_t)OPRETID_IMPORTDATA << importData));   // add importData to tokens opret:
    }
    else {
        //mtx.vout.insert(mtx.vout.begin(), CTxOut(0, CScript() << OP_RETURN << importData));     // import tx's opret was in vout[0] 
        mtx.vout.insert(mtx.vout.begin(), CTxOut(0, CScript() << OP_RETURN << importData));     // import tx's opret now is in the vout's tail
    }

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


bool UnmarshalImportTx(const CTransaction &importTx, TxProof &proof, CTransaction &burnTx, std::vector<CTxOut> &payouts, CPubKey &vinPubkey)
{
    if (importTx.vout.size() < 1) return false;
    
    std::vector<uint8_t> vData;
    //GetOpReturnData(importTx.vout[0].scriptPubKey, vData);  // now it is in the back;
    GetOpReturnData(importTx.vout.back().scriptPubKey, vData);

    if (vData.empty())
        return false;

    if (vData.begin()[0] == EVAL_TOKENS) {          // if it is tokens
        std::vector<std::pair<uint8_t, vopret_t>>  oprets;
        uint256 tokenid;
        uint8_t evalCodeInOpret;
        std::vector<CPubKey> voutTokenPubkeys;

        //skip token opret:
        if (DecodeTokenOpRet(importTx.vout.back().scriptPubKey, evalCodeInOpret, tokenid, voutTokenPubkeys, oprets) == 0)
            return false;

        GetOpretBlob(oprets, OPRETID_BURNDATA, vData);  // fetch import data after token opret
        payouts = std::vector<CTxOut>(importTx.vout.begin(), importTx.vout.end());   // let's importData remain in the token opret in payouts 

        vinPubkey = check_signing_pubkey(importTx.vin[0].scriptSig);
        CC *cond = MakeCCcond1(EVAL_IMPORTCOIN, vinPubkey);
        CScript testScriptSig = CCSig(cond);
        cc_free(cond);
        if (importTx.vin[0].scriptSig != testScriptSig)
            return false;
    }
    else {
        //payouts = std::vector<CTxOut>(importTx.vout.begin()+1, importTx.vout.end());   // see next
        payouts = std::vector<CTxOut>(importTx.vout.begin(), importTx.vout.end() - 1);   // remove opret, it is now in the tail
        vinPubkey = CPubKey();  //empty
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
        std::vector<std::pair<uint8_t, vopret_t>>  oprets;
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
    CPubKey vinPubkey;

    if (UnmarshalImportTx(tx, proof, burnTx, payouts, vinPubkey)) {
        if (burnTx.vout.size() > 0)  {
            vopret_t vburnOpret;

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
        if (evalScript.begin()[0] != EVAL_IMPORTCOIN)   // should also work for tokens: 'cond = MakeCCcond1(EVAL_IMPORTCOIN, vinPubkey); scriptSig = CCSig(cond);'
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
