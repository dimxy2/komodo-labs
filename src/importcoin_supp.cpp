#include "importcoin.h"

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