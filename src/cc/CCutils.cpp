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

/*
 CCutils has low level functions that are universally useful for all contracts.
 */
#include "CCinclude.h"
#include "komodo_structs.h"

#ifdef TESTMODE           
    #define MIN_NON_NOTARIZED_CONFIRMS 2
#else
    #define MIN_NON_NOTARIZED_CONFIRMS 101
#endif // TESTMODE
int32_t komodo_dpowconfs(int32_t height,int32_t numconfs);
struct komodo_state *komodo_stateptr(char *symbol,char *dest);
extern uint32_t KOMODO_DPOWCONFS;

void endiancpy(uint8_t *dest,uint8_t *src,int32_t len)
{
    int32_t i,j=0;
#if defined(WORDS_BIGENDIAN)
    for (i=31; i>=0; i--)
        dest[j++] = src[i];
#else
    memcpy(dest,src,len);
#endif
}

CC *MakeCCcond1of2(uint8_t evalcode,CPubKey pk1,CPubKey pk2)
{
    std::vector<CC*> pks;
    pks.push_back(CCNewSecp256k1(pk1));
    pks.push_back(CCNewSecp256k1(pk2));
    CC *condCC = CCNewEval(E_MARSHAL(ss << evalcode));
    CC *Sig = CCNewThreshold(1, pks);
    return CCNewThreshold(2, {condCC, Sig});
}

CC *MakeCCcond1(uint8_t evalcode,CPubKey pk)
{
    std::vector<CC*> pks;
    pks.push_back(CCNewSecp256k1(pk));
    CC *condCC = CCNewEval(E_MARSHAL(ss << evalcode));
    CC *Sig = CCNewThreshold(1, pks);
    return CCNewThreshold(2, {condCC, Sig});
}

CTxOut MakeCC1vout(uint8_t evalcode,CAmount nValue,CPubKey pk)
{
    CTxOut vout;
    CC *payoutCond = MakeCCcond1(evalcode,pk);
    vout = CTxOut(nValue,CCPubKey(payoutCond));
    cc_free(payoutCond);
    return(vout);
}

CTxOut MakeCC1of2vout(uint8_t evalcode,CAmount nValue,CPubKey pk1,CPubKey pk2)
{
    CTxOut vout;
    CC *payoutCond = MakeCCcond1of2(evalcode,pk1,pk2);
    vout = CTxOut(nValue,CCPubKey(payoutCond));
    cc_free(payoutCond);
    return(vout);
}

CC *MakeTokensCCcond1of2(uint8_t evalcode, CPubKey pk1, CPubKey pk2)
{
	// make 1of2 sigs cond 
	std::vector<CC*> pks;
	pks.push_back(CCNewSecp256k1(pk1));
	pks.push_back(CCNewSecp256k1(pk2));

	std::vector<CC*> thresholds;
	thresholds.push_back( CCNewEval(E_MARSHAL(ss << evalcode)) );
	if( evalcode != EVAL_TOKENS )	// if evalCode == EVAL_TOKENS, it is actually MakeCCcond1of2()!
		thresholds.push_back(CCNewEval(E_MARSHAL(ss << (uint8_t)EVAL_TOKENS)));	// this is eval token cc
	thresholds.push_back(CCNewThreshold(1, pks));		// this is 1 of 2 sigs cc

	return CCNewThreshold(thresholds.size(), thresholds);
}

CC *MakeTokensCCcond1(uint8_t evalcode, CPubKey pk)
{
	std::vector<CC*> pks;
	pks.push_back(CCNewSecp256k1(pk));

	std::vector<CC*> thresholds;
	thresholds.push_back(CCNewEval(E_MARSHAL(ss << evalcode)));
	if (evalcode != EVAL_TOKENS)  // if evalCode == EVAL_TOKENS, it is actually MakeCCcond1()!
		thresholds.push_back(CCNewEval(E_MARSHAL(ss << (uint8_t)EVAL_TOKENS)));	// this is eval token cc
	thresholds.push_back(CCNewThreshold(1, pks));			// signature

	return CCNewThreshold(thresholds.size(), thresholds);
}

CTxOut MakeTokensCC1of2vout(uint8_t evalcode, CAmount nValue, CPubKey pk1, CPubKey pk2)
{
	CTxOut vout;
	CC *payoutCond = MakeTokensCCcond1of2(evalcode, pk1, pk2);
	vout = CTxOut(nValue, CCPubKey(payoutCond));
	cc_free(payoutCond);
	return(vout);
}

CTxOut MakeTokensCC1vout(uint8_t evalcode, CAmount nValue, CPubKey pk)
{
	CTxOut vout;
	CC *payoutCond = MakeTokensCCcond1(evalcode, pk);
	vout = CTxOut(nValue, CCPubKey(payoutCond));
	cc_free(payoutCond);
	return(vout);
}

CC* GetCryptoCondition(CScript const& scriptSig)
{
    auto pc = scriptSig.begin();
    opcodetype opcode;
    std::vector<unsigned char> ffbin;
    if (scriptSig.GetOp(pc, opcode, ffbin))
        return cc_readFulfillmentBinary((uint8_t*)ffbin.data(), ffbin.size()-1);
    else return(0);
}

bool IsCCInput(CScript const& scriptSig)
{
    CC *cond;
    if ( (cond= GetCryptoCondition(scriptSig)) == 0 )
        return false;
    cc_free(cond);
    return true;
}

int32_t unstringbits(char *buf,uint64_t bits)
{
    int32_t i;
    for (i=0; i<8; i++,bits>>=8)
        if ( (buf[i]= (char)(bits & 0xff)) == 0 )
            break;
    buf[i] = 0;
    return(i);
}

uint64_t stringbits(char *str)
{
    uint64_t bits = 0;
    if ( str == 0 )
        return(0);
    int32_t i,n = (int32_t)strlen(str);
    if ( n > 8 )
        n = 8;
    for (i=n-1; i>=0; i--)
        bits = (bits << 8) | (str[i] & 0xff);
    //printf("(%s) -> %llx %llu\n",str,(long long)bits,(long long)bits);
    return(bits);
}

uint256 revuint256(uint256 txid)
{
    uint256 revtxid; int32_t i;
    for (i=31; i>=0; i--)
        ((uint8_t *)&revtxid)[31-i] = ((uint8_t *)&txid)[i];
    return(revtxid);
}

char *uint256_str(char *dest,uint256 txid)
{
    int32_t i,j=0;
    for (i=31; i>=0; i--)
        sprintf(&dest[j++ * 2],"%02x",((uint8_t *)&txid)[i]);
    dest[64] = 0;
    return(dest);
}

char *pubkey33_str(char *dest,uint8_t *pubkey33)
{
    int32_t i;
    if ( pubkey33 != 0 )
    {
        for (i=0; i<33; i++)
            sprintf(&dest[i * 2],"%02x",pubkey33[i]);
    } else dest[0] = 0;
    return(dest);
}

uint256 Parseuint256(char *hexstr)
{
    uint256 txid; int32_t i; std::vector<unsigned char> txidbytes(ParseHex(hexstr));
    memset(&txid,0,sizeof(txid));
    if ( strlen(hexstr) == 64 )
    {
        for (i=31; i>=0; i--)
            ((uint8_t *)&txid)[31-i] = ((uint8_t *)txidbytes.data())[i];
    }
    return(txid);
}

CPubKey buf2pk(uint8_t *buf33)
{
    CPubKey pk; int32_t i; uint8_t *dest;
    dest = (uint8_t *)pk.begin();
    for (i=0; i<33; i++)
        dest[i] = buf33[i];
    return(pk);
}

CPubKey pubkey2pk(std::vector<uint8_t> pubkey)
{
    CPubKey pk; int32_t i,n; uint8_t *dest,*pubkey33;
    n = pubkey.size();
    dest = (uint8_t *)pk.begin();
    pubkey33 = (uint8_t *)pubkey.data();
    for (i=0; i<n; i++)
        dest[i] = pubkey33[i];
    return(pk);
}

void CCaddr2set(struct CCcontract_info *cp,uint8_t evalcode,CPubKey pk,uint8_t *priv,char *coinaddr)
{
    cp->evalcode2 = evalcode;
    cp->unspendablepk2 = pk;
    memcpy(cp->unspendablepriv2,priv,32);
    strcpy(cp->unspendableaddr2,coinaddr);
}

void CCaddr3set(struct CCcontract_info *cp,uint8_t evalcode,CPubKey pk,uint8_t *priv,char *coinaddr)
{
    cp->evalcode3 = evalcode;
    cp->unspendablepk3 = pk;
    memcpy(cp->unspendablepriv3,priv,32);
    strcpy(cp->unspendableaddr3,coinaddr);
}

// set pubkeys, myprivkey and 1of2 cc addr for spending from 1of2 cryptocondition vout:
void CCaddr1of2set(struct CCcontract_info *cp, CPubKey pk1, CPubKey pk2, char *coinaddr)
{
	cp->coins1of2pk[0] = pk1;
	cp->coins1of2pk[1] = pk2;
	strcpy(cp->coins1of2addr, coinaddr);
}

// set pubkeys, myprivkey and 1of2 cc addr for spending from 1of2 tokens cryptocondition vout:
void CCaddrTokens1of2set(struct CCcontract_info *cp, CPubKey pk1, CPubKey pk2, char *coinaddr)
{
	cp->tokens1of2pk[0] = pk1;
	cp->tokens1of2pk[1] = pk2;
	strcpy(cp->tokens1of2addr, coinaddr);
}

bool Getscriptaddress(char *destaddr,const CScript &scriptPubKey)
{
    CTxDestination address; txnouttype whichType;
    if ( ExtractDestination(scriptPubKey,address) != 0 )
    {
        strcpy(destaddr,(char *)CBitcoinAddress(address).ToString().c_str());
        return(true);
    }
    //fprintf(stderr,"ExtractDestination failed\n");
    return(false);
}

bool GetCCParams(Eval* eval, const CTransaction &tx, uint32_t nIn,
                 CTransaction &txOut, std::vector<std::vector<unsigned char>> &preConditions, std::vector<std::vector<unsigned char>> &params)
{
    uint256 blockHash;

    if (myGetTransaction(tx.vin[nIn].prevout.hash, txOut, blockHash) && txOut.vout.size() > tx.vin[nIn].prevout.n)
    {
        CBlockIndex index;
        if (eval->GetBlock(blockHash, index))
        {
            // read preconditions
            CScript subScript = CScript();
            preConditions.clear();
            if (txOut.vout[tx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(&subScript, preConditions))
            {
                // read any available parameters in the output transaction
                params.clear();
                if (tx.vout.size() > 0 && tx.vout[tx.vout.size() - 1].scriptPubKey.IsOpReturn())
                {
                    if (tx.vout[tx.vout.size() - 1].scriptPubKey.GetOpretData(params) && params.size() == 1)
                    {
                        CScript scr = CScript(params[0].begin(), params[0].end());

                        // printf("Script decoding inner:\n%s\nouter:\n%s\n", scr.ToString().c_str(), tx.vout[tx.vout.size() - 1].scriptPubKey.ToString().c_str());

                        if (!scr.GetPushedData(scr.begin(), params))
                        {
                            return false;
                        }
                        else return true;
                    }
                    else return false;
                }
                else return true;
            }
        }
    }
    return false;
    //fprintf(stderr,"ExtractDestination failed\n");
    return(false);
}

bool pubkey2addr(char *destaddr,uint8_t *pubkey33)
{
    std::vector<uint8_t>pk; int32_t i;
    for (i=0; i<33; i++)
        pk.push_back(pubkey33[i]);
    return(Getscriptaddress(destaddr,CScript() << pk << OP_CHECKSIG));
}

CPubKey CCtxidaddr(char *txidaddr,uint256 txid)
{
    uint8_t buf33[33]; CPubKey pk;
    buf33[0] = 0x02;
    endiancpy(&buf33[1],(uint8_t *)&txid,32);
    pk = buf2pk(buf33);
    Getscriptaddress(txidaddr,CScript() << ParseHex(HexStr(pk)) << OP_CHECKSIG);
    return(pk);
}

bool _GetCCaddress(char *destaddr,uint8_t evalcode,CPubKey pk)
{
    CC *payoutCond;
    destaddr[0] = 0;
    if ( (payoutCond= MakeCCcond1(evalcode,pk)) != 0 )
    {
        Getscriptaddress(destaddr,CCPubKey(payoutCond));
        cc_free(payoutCond);
    }
    return(destaddr[0] != 0);
}

bool GetCCaddress(struct CCcontract_info *cp,char *destaddr,CPubKey pk)
{
    destaddr[0] = 0;
    if ( pk.size() == 0 )
        pk = GetUnspendable(cp,0);
    return(_GetCCaddress(destaddr,cp->evalcode,pk));
}

bool _GetTokensCCaddress(char *destaddr, uint8_t evalcode, CPubKey pk)
{
	CC *payoutCond;
	destaddr[0] = 0;
	if ((payoutCond = MakeTokensCCcond1(evalcode, pk)) != 0)
	{
		Getscriptaddress(destaddr, CCPubKey(payoutCond));
		cc_free(payoutCond);
	}
	return(destaddr[0] != 0);
}

bool GetTokensCCaddress(struct CCcontract_info *cp, char *destaddr, CPubKey pk)
{
	destaddr[0] = 0;
	if (pk.size() == 0)
		pk = GetUnspendable(cp, 0);
	return(_GetTokensCCaddress(destaddr, cp->evalcode, pk));
}


bool GetCCaddress1of2(struct CCcontract_info *cp,char *destaddr,CPubKey pk,CPubKey pk2)
{
    CC *payoutCond;
    destaddr[0] = 0;
    if ( (payoutCond= MakeCCcond1of2(cp->evalcode,pk,pk2)) != 0 )
    {
        Getscriptaddress(destaddr,CCPubKey(payoutCond));
        cc_free(payoutCond);
    }
    return(destaddr[0] != 0);
}

bool GetTokensCCaddress1of2(struct CCcontract_info *cp, char *destaddr, CPubKey pk, CPubKey pk2)
{
	CC *payoutCond;
	destaddr[0] = 0;
	if ((payoutCond = MakeTokensCCcond1of2(cp->evalcode, pk, pk2)) != 0)
	{
		Getscriptaddress(destaddr, CCPubKey(payoutCond));
		cc_free(payoutCond);
	}
	return(destaddr[0] != 0);
}

bool ConstrainVout(CTxOut vout, int32_t CCflag, char *cmpaddr, int64_t nValue)
{
    char destaddr[64];
    if ( vout.scriptPubKey.IsPayToCryptoCondition() != CCflag )
    {
        fprintf(stderr,"constrain vout error isCC %d vs %d CCflag\n", vout.scriptPubKey.IsPayToCryptoCondition(), CCflag);
        return(false);
    }
    else if ( cmpaddr != 0 && (Getscriptaddress(destaddr, vout.scriptPubKey) == 0 || strcmp(destaddr, cmpaddr) != 0) )
    {
        fprintf(stderr,"constrain vout error: check addr %s vs script addr %s\n", cmpaddr!=0?cmpaddr:"", destaddr!=0?destaddr:"");
        return(false);
    }
    else if ( nValue != 0 && nValue != vout.nValue ) //(nValue == 0 && vout.nValue < 10000) || (
    {
        fprintf(stderr,"constrain vout error nValue %.8f vs %.8f\n",(double)nValue/COIN,(double)vout.nValue/COIN);
        return(false);
    }
    else return(true);
}

bool PreventCC(Eval* eval,const CTransaction &tx,int32_t preventCCvins,int32_t numvins,int32_t preventCCvouts,int32_t numvouts)
{
    int32_t i;
    if ( preventCCvins >= 0 )
    {
        for (i=preventCCvins; i<numvins; i++)
        {
            if ( IsCCInput(tx.vin[i].scriptSig) != 0 )
                return eval->Invalid("invalid CC vin");
        }
    }
    if ( preventCCvouts >= 0 )
    {
        for (i=preventCCvouts; i<numvouts; i++)
        {
            if ( tx.vout[i].scriptPubKey.IsPayToCryptoCondition() != 0 )
            {
                fprintf(stderr,"vout.%d is CC\n",i);
                return eval->Invalid("invalid CC vout");
            }
        }
    }
    return(true);
}

std::vector<uint8_t> Mypubkey()
{
    extern uint8_t NOTARY_PUBKEY33[33];
    std::vector<uint8_t> pubkey; int32_t i; uint8_t *dest,*pubkey33;
    pubkey33 = NOTARY_PUBKEY33;
    pubkey.resize(33);
    dest = pubkey.data();
    for (i=0; i<33; i++)
        dest[i] = pubkey33[i];
    return(pubkey);
}

bool Myprivkey(uint8_t myprivkey[])
{
    char coinaddr[64]; std::string strAddress; char *dest; int32_t i,n; CBitcoinAddress address; CKeyID keyID; CKey vchSecret;
    if ( Getscriptaddress(coinaddr,CScript() << Mypubkey() << OP_CHECKSIG) != 0 )
    {
        n = (int32_t)strlen(coinaddr);
        strAddress.resize(n+1);
        dest = (char *)strAddress.data();
        for (i=0; i<n; i++)
            dest[i] = coinaddr[i];
        dest[i] = 0;
        if ( address.SetString(strAddress) != 0 && address.GetKeyID(keyID) != 0 )
        {
#ifdef ENABLE_WALLET
            if ( pwalletMain->GetKey(keyID,vchSecret) != 0 )
            {
                memcpy(myprivkey,vchSecret.begin(),32);
                if ( 0 )
                {
                    for (i=0; i<32; i++)
                        fprintf(stderr,"0x%02x, ",myprivkey[i]);
                    fprintf(stderr," found privkey for %s!\n",dest);
                }
                return(true);
            }
#endif
        }
    }
    fprintf(stderr,"privkey for the -pubkey= address is not in the wallet, importprivkey!\n");
    return(false);
}

CPubKey GetUnspendable(struct CCcontract_info *cp,uint8_t *unspendablepriv)
{
    if ( unspendablepriv != 0 )
        memcpy(unspendablepriv,cp->CCpriv,32);
    return(pubkey2pk(ParseHex(cp->CChexstr)));
}

void CCclearvars(struct CCcontract_info *cp)
{
    cp->evalcode2 = cp->evalcode3 = 0;
    cp->unspendableaddr2[0] = cp->unspendableaddr3[0] = 0;
}

int64_t CCduration(int32_t &numblocks,uint256 txid)
{
    CTransaction tx; uint256 hashBlock; uint32_t txheight,txtime=0; char str[65]; CBlockIndex *pindex; int64_t duration = 0;
    numblocks = 0;
    if ( myGetTransaction(txid,tx,hashBlock) == 0 )
    {
        //fprintf(stderr,"CCduration cant find duration txid %s\n",uint256_str(str,txid));
        return(0);
    }
    else if ( hashBlock == zeroid )
    {
        //fprintf(stderr,"CCduration no hashBlock for txid %s\n",uint256_str(str,txid));
        return(0);
    }
    else if ( (pindex= komodo_getblockindex(hashBlock)) == 0 || (txtime= pindex->nTime) == 0 || (txheight= pindex->GetHeight()) <= 0 )
    {
        fprintf(stderr,"CCduration no txtime %u or txheight.%d %p for txid %s\n",txtime,txheight,pindex,uint256_str(str,txid));
        return(0);
    }
    else if ( (pindex= chainActive.LastTip()) == 0 || pindex->nTime < txtime || pindex->GetHeight() <= txheight )
    {
        if ( pindex->nTime < txtime )
            fprintf(stderr,"CCduration backwards timestamps %u %u for txid %s hts.(%d %d)\n",(uint32_t)pindex->nTime,txtime,uint256_str(str,txid),txheight,(int32_t)pindex->GetHeight());
        return(0);
    }
    numblocks = (pindex->GetHeight() - txheight);
    duration = (pindex->nTime - txtime);
    //fprintf(stderr,"duration %d (%u - %u) numblocks %d (%d - %d)\n",(int32_t)duration,(uint32_t)pindex->nTime,txtime,numblocks,pindex->GetHeight(),txheight);
    return(duration);
}

bool komodo_txnotarizedconfirmed(uint256 txid)
{
    char str[65];
    uint32_t confirms,notarized=0,txheight;
    CTransaction tx;
    uint256 hashBlock;
    CBlockIndex *pindex;    
    char symbol[KOMODO_ASSETCHAIN_MAXLEN],dest[KOMODO_ASSETCHAIN_MAXLEN]; struct komodo_state *sp;

    if ( myGetTransaction(txid,tx,hashBlock) == 0 )
    {
        fprintf(stderr,"komodo_txnotarizedconfirmed cant find txid %s\n",txid.ToString().c_str());
        return(0);
    }
    else if ( hashBlock == zeroid )
    {
        fprintf(stderr,"komodo_txnotarizedconfirmed no hashBlock for txid %s\n",txid.ToString().c_str());
        return(0);
    }
    else if ( (pindex= mapBlockIndex[hashBlock]) == 0 || (txheight= pindex->GetHeight()) <= 0 )
    {
        fprintf(stderr,"komodo_txnotarizedconfirmed no txheight.%d %p for txid %s\n",txheight,pindex,txid.ToString().c_str());
        return(0);
    }
    else if ( (pindex= chainActive.LastTip()) == 0 || pindex->GetHeight() < txheight )
    {
        fprintf(stderr,"komodo_txnotarizedconfirmed backwards heights for txid %s hts.(%d %d)\n",txid.ToString().c_str(),txheight,(int32_t)pindex->GetHeight());
        return(0);
    }    
    confirms=1 + pindex->GetHeight() - txheight;        
    if ((sp= komodo_stateptr(symbol,dest)) != 0 && (notarized=sp->NOTARIZED_HEIGHT) > 0 && txheight > sp->NOTARIZED_HEIGHT)  notarized=0;            
#ifdef TESTMODE           
    notarized=0;
#endif //TESTMODE
    if (notarized>0 && confirms > 1)
        return (true);
    else if (notarized==0 && confirms >= MIN_NON_NOTARIZED_CONFIRMS)
        return (true);
    return (false);
}

CPubKey check_signing_pubkey(CScript scriptSig)
{
	bool found = false;
	CPubKey pubkey;
	
    auto findEval = [](CC *cond, struct CCVisitor _) {
        bool r = false;

        if (cc_typeId(cond) == CC_Secp256k1) {
            *(CPubKey*)_.context=buf2pk(cond->publicKey);
            r = true;
        }
        // false for a match, true for continue
        return r ? 0 : 1;
    };

    CC *cond = GetCryptoCondition(scriptSig);

    if (cond) {
        CCVisitor visitor = { findEval, (uint8_t*)"", 0, &pubkey };
        bool out = !cc_visit(cond, visitor);
        cc_free(cond);

        if (pubkey.IsValid()) {
            return pubkey;
        }
    }
	return CPubKey();
}

bool ProcessCC(struct CCcontract_info *cp,Eval* eval, std::vector<uint8_t> paramsNull,const CTransaction &ctx, unsigned int nIn)
{
    CTransaction createTx; uint256 assetid,assetid2,hashBlock; uint8_t funcid; int32_t height,i,n,from_mempool = 0; int64_t amount; std::vector<uint8_t> origpubkey;
    height = KOMODO_CONNECTING;
    if ( KOMODO_CONNECTING < 0 ) // always comes back with > 0 for final confirmation
        return(true);
    if ( ASSETCHAINS_CC == 0 || (height & ~(1<<30)) < KOMODO_CCACTIVATE )
        return eval->Invalid("CC are disabled or not active yet");
    if ( (KOMODO_CONNECTING & (1<<30)) != 0 )
    {
        from_mempool = 1;
        height &= ((1<<30) - 1);
    }
    //fprintf(stderr,"KOMODO_CONNECTING.%d mempool.%d vs CCactive.%d\n",height,from_mempool,KOMODO_CCACTIVATE);
    // there is a chance CC tx is valid in mempool, but invalid when in block, so we cant filter duplicate requests. if any of the vins are spent, for example
    //txid = ctx.GetHash();
    //if ( txid == cp->prevtxid )
    //    return(true);
    //fprintf(stderr,"process CC %02x\n",cp->evalcode);
    CCclearvars(cp);
    if ( paramsNull.size() != 0 ) // Don't expect params
        return eval->Invalid("Cannot have params");
    //else if ( ctx.vout.size() == 0 )      // spend can go to z-addresses
    //    return eval->Invalid("no-vouts");
    else if ( (*cp->validate)(cp,eval,ctx,nIn) != 0 )
    {
        //fprintf(stderr,"done CC %02x\n",cp->evalcode);
        //cp->prevtxid = txid;
        return(true);
    }
    //fprintf(stderr,"invalid CC %02x\n",cp->evalcode);
    return(false);
}

extern struct CCcontract_info CCinfos[0x100];
extern std::string MYCCLIBNAME;
bool CClib_validate(struct CCcontract_info *cp,int32_t height,Eval *eval,const CTransaction tx,unsigned int nIn);

bool CClib_Dispatch(const CC *cond,Eval *eval,std::vector<uint8_t> paramsNull,const CTransaction &txTo,unsigned int nIn)
{
    uint8_t evalcode; int32_t height,from_mempool; struct CCcontract_info *cp;
    if ( ASSETCHAINS_CCLIB != MYCCLIBNAME )
    {
        fprintf(stderr,"-ac_cclib=%s vs myname %s\n",ASSETCHAINS_CCLIB.c_str(),MYCCLIBNAME.c_str());
        return eval->Invalid("-ac_cclib name mismatches myname");
    }
    height = KOMODO_CONNECTING;
    if ( KOMODO_CONNECTING < 0 ) // always comes back with > 0 for final confirmation
        return(true);
    if ( ASSETCHAINS_CC == 0 || (height & ~(1<<30)) < KOMODO_CCACTIVATE )
        return eval->Invalid("CC are disabled or not active yet");
    if ( (KOMODO_CONNECTING & (1<<30)) != 0 )
    {
        from_mempool = 1;
        height &= ((1<<30) - 1);
    }
    evalcode = cond->code[0];
    if ( evalcode >= EVAL_FIRSTUSER && evalcode <= EVAL_LASTUSER )
    {
        cp = &CCinfos[(int32_t)evalcode];
        if ( cp->didinit == 0 )
        {
            if ( CClib_initcp(cp,evalcode) == 0 )
                cp->didinit = 1;
            else return eval->Invalid("unsupported CClib evalcode");
        }
        CCclearvars(cp);
        if ( paramsNull.size() != 0 ) // Don't expect params
            return eval->Invalid("Cannot have params");
        else if ( CClib_validate(cp,height,eval,txTo,nIn) != 0 )
            return(true);
        return(false); //eval->Invalid("error in CClib_validate");
    }
    return eval->Invalid("cclib CC must have evalcode between 16 and 127");
}
