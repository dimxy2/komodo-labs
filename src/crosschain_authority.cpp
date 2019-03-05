#include "cc/eval.h"
#include "crosschain.h"
#include "notarisationdb.h"
#include "notaries_staked.h"

int GetSymbolAuthority(const char* symbol)
{
    if (strncmp(symbol, "TXSCL", 5) == 0)
        return CROSSCHAIN_TXSCL;
    if (is_STAKED(symbol) != 0) {
        LogPrintf("GetSymbolAuthority RETURNED CROSSCHAIN STAKED AS TRUE\n");
        return CROSSCHAIN_STAKED;
    }
    LogPrintf("GetSymbolAuthority RETURNED CROSSCHAIN KOMODO AS TRUE\n");
    return CROSSCHAIN_KOMODO;
}


bool CheckTxAuthority(const CTransaction &tx, CrosschainAuthority auth)
{
    EvalRef eval;

    if (tx.vin.size() < auth.requiredSigs) return false;

    uint8_t seen[64] = {0};

    BOOST_FOREACH(const CTxIn &txIn, tx.vin)
    {
        // Get notary pubkey
        CTransaction tx;
        uint256 hashBlock;
        if (!eval->GetTxUnconfirmed(txIn.prevout.hash, tx, hashBlock)) return false;
        if (tx.vout.size() < txIn.prevout.n) return false;
        CScript spk = tx.vout[txIn.prevout.n].scriptPubKey;
        if (spk.size() != 35) return false;
        const unsigned char *pk = &spk[0];
        if (pk++[0] != 33) return false;
        if (pk[33] != OP_CHECKSIG) return false;

        // Check it's a notary
        for (int i=0; i<auth.size; i++) {
            if (!seen[i]) {
                if (memcmp(pk, auth.notaries[i], 33) == 0) {
                    seen[i] = 1;
                    LogPrintf("CheckTxAuthority found notary.%i\n",i);
                    goto found;
                } else {
                    //LogPrintf("CheckTxAuthority notary.%i is not valid!\n",i);
                }
            }
        }

        return false;
        found:;
    }

    return true;
}
