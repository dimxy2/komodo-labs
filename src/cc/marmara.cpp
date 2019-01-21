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

#include "CCMarmara.h"

/*
 Marmara CC is for the MARMARA project
 
*/

// start of consensus code

int64_t IsMarmaravout(struct CCcontract_info *cp,const CTransaction& tx,int32_t v)
{
    char destaddr[64];
    if ( tx.vout[v].scriptPubKey.IsPayToCryptoCondition() != 0 )
    {
        if ( Getscriptaddress(destaddr,tx.vout[v].scriptPubKey) > 0 && strcmp(destaddr,cp->unspendableCCaddr) == 0 )
            return(tx.vout[v].nValue);
    }
    return(0);
}

/*bool MarmaraExactAmounts(struct CCcontract_info *cp,Eval* eval,const CTransaction &tx,int32_t minage,uint64_t txfee)
{
    static uint256 zerohash;
    CTransaction vinTx; uint256 hashBlock,activehash; int32_t i,numvins,numvouts; int64_t inputs=0,outputs=0,assetoshis;
    numvins = tx.vin.size();
    numvouts = tx.vout.size();
    for (i=0; i<numvins; i++)
    {
        //fprintf(stderr,"vini.%d\n",i);
        if ( (*cp->ismyvin)(tx.vin[i].scriptSig) != 0 )
        {
            //fprintf(stderr,"vini.%d check mempool\n",i);
            if ( eval->GetTxUnconfirmed(tx.vin[i].prevout.hash,vinTx,hashBlock) == 0 )
                return eval->Invalid("cant find vinTx");
            else
            {
                //fprintf(stderr,"vini.%d check hash and vout\n",i);
                if ( hashBlock == zerohash )
                    return eval->Invalid("cant Marmara from mempool");
                if ( (assetoshis= IsMarmaravout(cp,vinTx,tx.vin[i].prevout.n)) != 0 )
                    inputs += assetoshis;
            }
        }
    }
    for (i=0; i<numvouts; i++)
    {
        //fprintf(stderr,"i.%d of numvouts.%d\n",i,numvouts);
        if ( (assetoshis= IsMarmaravout(cp,tx,i)) != 0 )
            outputs += assetoshis;
    }
    if ( inputs != outputs+txfee )
    {
        fprintf(stderr,"inputs %llu vs outputs %llu\n",(long long)inputs,(long long)outputs);
        return eval->Invalid("mismatched inputs != outputs + txfee");
    }
    else return(true);
}*/

int32_t MarmaraRandomize(uint32_t ind)
{
    uint64_t val64; uint32_t val,range = (MARMARA_MAXLOCK - MARMARA_MINLOCK);
    val64 = komodo_block_prg(ind);
    val = (uint32_t)(val64 >> 32);
    val ^= (uint32_t)val64;
    return((val % range) + MARMARA_MINLOCK);
}

int32_t MarmaraUnlockht(int32_t height)
{
    uint32_t ind = height / MARMARA_GROUPSIZE;
    height = (height / MARMARA_GROUPSIZE) * MARMARA_GROUPSIZE;
    return(height + MarmaraRandomize(ind));
}

uint8_t DecodeMaramaraCoinbaseOpRet(const CScript scriptPubKey,CPubKey &pk,int32_t &height,int32_t &unlockht)
{
    std::vector<uint8_t> vopret; uint8_t *script,e,f,funcid;
    GetOpReturnData(scriptPubKey,vopret);
    script = (uint8_t *)vopret.data();
    if ( 0 )
    {
        int32_t i;
        for (i=0; i<vopret.size(); i++)
            fprintf(stderr,"%02x",script[i]);
        fprintf(stderr," <- opret\n");
    }
    if ( vopret.size() > 2 && script[0] == EVAL_MARMARA )
    {
        if ( script[1] == 'C' || script[1] == 'P' )
        {
            if ( E_UNMARSHAL(vopret,ss >> e; ss >> f; ss >> pk; ss >> height; ss >> unlockht) != 0 )
            {
                return(script[1]);
            } else fprintf(stderr,"DecodeMaramaraCoinbaseOpRet unmarshal error for %c\n",script[1]);
        } else fprintf(stderr,"script[1] is %d != 'C' %d or 'P' %d\n",script[1],'C','P');
    } else fprintf(stderr,"vopret.size() is %d\n",(int32_t)vopret.size());
    return(0);
}

CScript EncodeMarmaraCoinbaseOpRet(uint8_t funcid,CPubKey pk,int32_t ht)
{
    CScript opret; int32_t unlockht; uint8_t evalcode = EVAL_MARMARA;
    unlockht = MarmaraUnlockht(ht);
    opret << OP_RETURN << E_MARSHAL(ss << evalcode << funcid << pk << ht << unlockht);
    if ( 0 )
    {
        std::vector<uint8_t> vopret; uint8_t *script,i;
        GetOpReturnData(opret,vopret);
        script = (uint8_t *)vopret.data();
        {
            for (i=0; i<vopret.size(); i++)
                fprintf(stderr,"%02x",script[i]);
            fprintf(stderr," <- gen opret.%c\n",funcid);
        }
    }
    return(opret);
}

CScript MarmaraLoopOpret(uint8_t funcid,uint256 createtxid,CPubKey senderpk,int64_t amount,int32_t matures,std::string currency)
{
    CScript opret; uint8_t evalcode = EVAL_MARMARA;
    opret << OP_RETURN << E_MARSHAL(ss << evalcode << funcid << createtxid << senderpk << amount << matures << currency);
    return(opret);
}

CScript Marmara_scriptPubKey(int32_t height,CPubKey pk)
{
    CTxOut ccvout;
    if ( height > 0 && (height & 1) == 0 && pk.size() == 33 )
        ccvout = MakeCC1vout(EVAL_MARMARA,0,pk);
    return(ccvout.scriptPubKey);
}

CScript MarmaraCoinbaseOpret(uint8_t funcid,int32_t height,CPubKey pk)
{
    uint8_t *ptr;
    //fprintf(stderr,"height.%d pksize.%d\n",height,(int32_t)pk.size());
    if ( height > 0 && (height & 1) == 0 && pk.size() == 33 )
        return(EncodeMarmaraCoinbaseOpRet(funcid,pk,height));
    return(CScript());
}

int32_t MarmaraValidateCoinbase(int32_t height,CTransaction tx)
{
    struct CCcontract_info *cp,C; CPubKey pk; int32_t ht,unlockht; CTxOut ccvout;
    cp = CCinit(&C,EVAL_MARMARA);
    if ( 0 )
    {
        int32_t d,histo[365*2+30];
        memset(histo,0,sizeof(histo));
        for (ht=2; ht<100; ht++)
            fprintf(stderr,"%d ",MarmaraUnlockht(ht));
        fprintf(stderr," <- first 100 unlock heights\n");
        for (ht=2; ht<1000000; ht+=MARMARA_GROUPSIZE)
        {
            d = (MarmaraUnlockht(ht) - ht) / 1440;
            if ( d < 0 || d > sizeof(histo)/sizeof(*histo) )
                fprintf(stderr,"d error.%d at ht.%d\n",d,ht);
            else histo[d]++;
        }
        for (ht=0; ht<sizeof(histo)/sizeof(*histo); ht++)
            fprintf(stderr,"%d ",histo[ht]);
        fprintf(stderr,"<- unlock histogram[%d] by days locked\n",(int32_t)(sizeof(histo)/sizeof(*histo)));
    }
    if ( (height & 1) != 0 )
        return(0);
    if ( tx.vout.size() == 2 && tx.vout[1].nValue == 0 )
    {
        if ( DecodeMaramaraCoinbaseOpRet(tx.vout[1].scriptPubKey,pk,ht,unlockht) == 'C' )
        {
            if ( ht == height && MarmaraUnlockht(height) == unlockht )
            {
                //fprintf(stderr,"ht.%d -> unlock.%d\n",ht,unlockht);
                ccvout = MakeCC1vout(EVAL_MARMARA,0,pk);
                if ( ccvout.scriptPubKey == tx.vout[0].scriptPubKey )
                    return(0);
                fprintf(stderr,"ht.%d mismatched CCvout scriptPubKey\n",height);
            } else fprintf(stderr,"ht.%d %d vs %d unlock.%d\n",height,MarmaraUnlockht(height),ht,unlockht);
        } else fprintf(stderr,"ht.%d error decoding coinbase opret\n",height);
    }
    return(-1);
}

bool MarmaraValidate(struct CCcontract_info *cp,Eval* eval,const CTransaction &tx, uint32_t nIn)
{
    std::vector<uint8_t> vopret; CTransaction vinTx; uint256 hashBlock;  int32_t numvins,numvouts,i,ht,unlockht,vht,vunlockht; uint8_t funcid,vfuncid,*script; CPubKey pk,vpk;
    numvins = tx.vin.size();
    numvouts = tx.vout.size();
    if ( numvouts < 1 )
        return eval->Invalid("no vouts");
    else if ( tx.vout.size() >= 2 )
    {
        GetOpReturnData(tx.vout[tx.vout.size()-1].scriptPubKey,vopret);
        script = (uint8_t *)vopret.data();
        if ( vopret.size() < 2 || script[0] != EVAL_MARMARA )
            return eval->Invalid("no opreturn");
        funcid = script[1];
        if ( funcid == 'P' )
        {
            funcid = DecodeMaramaraCoinbaseOpRet(tx.vout[tx.vout.size()-1].scriptPubKey,pk,ht,unlockht);
            for (i=0; i<numvins; i++)
            {
                if ( (*cp->ismyvin)(tx.vin[i].scriptSig) != 0 )
                {
                    if ( eval->GetTxUnconfirmed(tx.vin[i].prevout.hash,vinTx,hashBlock) == 0 )
                        return eval->Invalid("cant find vinTx");
                    else
                    {
                        if ( vinTx.IsCoinBase() == 0 )
                            return eval->Invalid("noncoinbase input");
                        else if ( vinTx.vout.size() != 2 )
                            return eval->Invalid("coinbase doesnt have 2 vouts");
                        vfuncid = DecodeMaramaraCoinbaseOpRet(vinTx.vout[1].scriptPubKey,vpk,vht,vunlockht);
                        if ( vfuncid != 'C' || vpk != pk || vunlockht != unlockht )
                            return eval->Invalid("mismatched opreturn");
                    }
                }
            }
            return(true);
        }
        else if ( funcid == 'L' ) // lock -> lock funds with a unlockht
        {
            return(true);
        }
        else if ( funcid == 'R' ) // receive -> agree to receive 'I' from pk, amount, currency, dueht
        {
            return(true);
        }
        else if ( funcid == 'I' ) // issue -> issue currency to pk with due date height
        {
            return(true);
        }
        else if ( funcid == 'T' ) // transfer -> given 'R' transfer 'I' or 'T' to the pk of 'R'
        {
            return(true);
        }
        else if ( funcid == 'S' ) // collect -> automatically spend issuers locked funds, given 'I'
        {
            return(true); // iterate from issuer all remainder after maturity
        }
        // staking only for locked utxo
    }
    return eval->Invalid("fall through error");
}
// end of consensus code

// helper functions for rpc calls in rpcwallet.cpp

int64_t AddMarmaraCoinbases(struct CCcontract_info *cp,CMutableTransaction &mtx,int32_t firstheight,CPubKey poolpk,int32_t maxinputs)
{
    char coinaddr[64]; CPubKey pk; int64_t nValue,totalinputs = 0; uint256 txid,hashBlock; CTransaction vintx; int32_t unlockht,ht,vout,unlocks,n = 0;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;
    GetCCaddress(cp,coinaddr,poolpk);
    SetCCunspents(unspentOutputs,coinaddr);
    unlocks = MarmaraUnlockht(firstheight);
    //fprintf(stderr,"check coinaddr.(%s)\n",coinaddr);
    for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >::const_iterator it=unspentOutputs.begin(); it!=unspentOutputs.end(); it++)
    {
        txid = it->first.txhash;
        vout = (int32_t)it->first.index;
        //fprintf(stderr,"txid.%s/v%d\n",txid.GetHex().c_str(),vout);
        if ( GetTransaction(txid,vintx,hashBlock,false) != 0 )
        {
            if ( vintx.IsCoinBase() != 0 && vintx.vout.size() == 2 && vintx.vout[1].nValue == 0 )
            {
                if ( DecodeMaramaraCoinbaseOpRet(vintx.vout[1].scriptPubKey,pk,ht,unlockht) == 'C' && unlockht == unlocks && pk == poolpk && ht >= firstheight )
                {
                    if ( (nValue= vintx.vout[vout].nValue) > 0 && myIsutxo_spentinmempool(txid,vout) == 0 )
                    {
                        if ( maxinputs != 0 )
                            mtx.vin.push_back(CTxIn(txid,vout,CScript()));
                        nValue = it->second.satoshis;
                        totalinputs += nValue;
                        n++;
                        if ( maxinputs > 0 && n >= maxinputs )
                            break;
                    } //else fprintf(stderr,"nValue.%8f\n",(double)nValue/COIN);
                } //else fprintf(stderr,"decode error unlockht.%d vs %d pk.%d\n",unlockht,unlocks,pk == poolpk);
            } else fprintf(stderr,"not coinbase\n");
        } else fprintf(stderr,"error getting tx\n");
    }
    return(totalinputs);
}

UniValue MarmaraReceive(uint64_t txfee,CPubKey senderpk,int64_t amount,std::string currency,int32_t matures,uint256 createtxid)
{
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), komodo_nextheight());
    UniValue result(UniValue::VOBJ); CPubKey mypk; struct CCcontract_info *cp,C; std::string rawtx; char *errorstr=0; int32_t needbaton = 0;
    cp = CCinit(&C,EVAL_MARMARA);
    if ( txfee == 0 )
        txfee = 10000;
    // check for batonownership by senderpk and parameters match createtxid
    mypk = pubkey2pk(Mypubkey());
    if ( currency != "MARMARA" )
        errorstr = (char *)"for now, only MARMARA loops are supported";
    else if ( amount < txfee )
        errorstr = (char *)"amount must be for more than txfee";
    else if ( matures <= chainActive.LastTip()->GetHeight() )
        errorstr = (char *)"it must mature in the future";
    if ( errorstr == 0 )
    {
        if ( createtxid == zeroid )
            needbaton = 1;
        if ( AddNormalinputs(mtx,mypk,(1+needbaton)*txfee,1) > 0 )
        {
            errorstr = (char *)"couldnt finalize CCtx";
            if ( needbaton != 0 )
                mtx.vout.push_back(MakeCC1vout(EVAL_MARMARA,txfee,senderpk));
            rawtx = FinalizeCCTx(0,cp,mtx,mypk,txfee,MarmaraLoopOpret('R',createtxid,senderpk,amount,matures,currency));
            if ( rawtx.size() > 0 )
                errorstr = 0;
        } else errorstr = (char *)"dont have enough normal inputs for 2*txfee";
    }
    if ( rawtx.size() == 0 || errorstr != 0 )
    {
        result.push_back(Pair("result","error"));
        if ( errorstr != 0 )
            result.push_back(Pair("error",errorstr));
    }
    else
    {
        result.push_back(Pair("result",(char *)"success"));
        result.push_back(Pair("rawtx",rawtx));
        result.push_back(Pair("funcid","R"));
        result.push_back(Pair("createtxid",createtxid.GetHex()));
        result.push_back(Pair("senderpk",HexStr(senderpk)));
        result.push_back(Pair("amount",ValueFromAmount(amount)));
        result.push_back(Pair("matures",matures));
        result.push_back(Pair("currency",currency));
    }
    return(result);
}

UniValue MarmaraIssue(uint64_t txfee,uint8_t funcid,CPubKey receiverpk,int64_t amount,std::string currency,int32_t matures,uint256 createtxid)
{
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), komodo_nextheight());
    UniValue result(UniValue::VOBJ); CPubKey mypk; struct CCcontract_info *cp,C; std::string rawtx; char *errorstr=0;
    cp = CCinit(&C,EVAL_MARMARA);
    if ( txfee == 0 )
        txfee = 10000;
    // make sure if transfer that it is not too late
    mypk = pubkey2pk(Mypubkey());
    if ( currency != "MARMARA" )
        errorstr = (char *)"for now, only MARMARA loops are supported";
    else if ( amount < txfee )
        errorstr = (char *)"amount must be for more than txfee";
    else if ( matures <= chainActive.LastTip()->GetHeight() )
        errorstr = (char *)"it must mature in the future";
    if ( errorstr == 0 )
    {
        if ( AddNormalinputs(mtx,mypk,2*txfee,1) > 0 )
        {
            errorstr = (char *)"couldnt finalize CCtx";
            mtx.vout.push_back(MakeCC1vout(EVAL_MARMARA,txfee,receiverpk));
            rawtx = FinalizeCCTx(0,cp,mtx,mypk,txfee,MarmaraLoopOpret(funcid,createtxid,receiverpk,amount,matures,currency));
            if ( rawtx.size() > 0 )
                errorstr = 0;
        } else errorstr = (char *)"dont have enough normal inputs for 2*txfee";
    }
    if ( rawtx.size() == 0 || errorstr != 0 )
    {
        result.push_back(Pair("result","error"));
        if ( errorstr != 0 )
            result.push_back(Pair("error",errorstr));
    }
    else
    {
        result.push_back(Pair("result",(char *)"success"));
        result.push_back(Pair("rawtx",rawtx));
        char str[2]; str[0] = funcid, str[1] = 0;
        result.push_back(Pair("funcid",str));
        result.push_back(Pair("createtxid",createtxid.GetHex()));
        result.push_back(Pair("receiverpk",HexStr(receiverpk)));
        result.push_back(Pair("amount",ValueFromAmount(amount)));
        result.push_back(Pair("matures",matures));
        result.push_back(Pair("currency",currency));
    }
    return(result);
}

std::string MarmaraFund(uint64_t txfee,int64_t funds)
{
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), komodo_nextheight());
    CPubKey mypk,Marmarapk; CScript opret; struct CCcontract_info *cp,C;
    cp = CCinit(&C,EVAL_MARMARA);
    if ( txfee == 0 )
        txfee = 10000;
    mypk = pubkey2pk(Mypubkey());
    Marmarapk = GetUnspendable(cp,0);
    if ( AddNormalinputs(mtx,mypk,funds+txfee,64) > 0 )
    {
        mtx.vout.push_back(MakeCC1vout(EVAL_MARMARA,funds,Marmarapk));
        return(FinalizeCCTx(0,cp,mtx,mypk,txfee,opret));
    }
    return("");
}

UniValue MarmaraInfo()
{
    UniValue result(UniValue::VOBJ); char numstr[64];
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), komodo_nextheight());
    CPubKey Marmarapk; struct CCcontract_info *cp,C; int64_t funding;
    result.push_back(Pair("result","success"));
    result.push_back(Pair("name","Marmara"));
    cp = CCinit(&C,EVAL_MARMARA);
    Marmarapk = GetUnspendable(cp,0);
    return(result);
}

UniValue MarmaraPoolPayout(uint64_t txfee,int32_t firstheight,double perc,char *jsonstr) // [[pk0, shares0], [pk1, shares1], ...]
{
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), komodo_nextheight());
    UniValue result(UniValue::VOBJ),a(UniValue::VARR); cJSON *item,*array; std::string rawtx; int32_t i,n; uint8_t buf[33]; CPubKey Marmarapk,pk,poolpk; int64_t payout,poolfee=0,total,totalpayout=0; double poolshares,share,shares = 0.; char *pkstr,*errorstr=0; struct CCcontract_info *cp,C;
    poolpk = pubkey2pk(Mypubkey());
    if ( txfee == 0 )
        txfee = 10000;
    cp = CCinit(&C,EVAL_MARMARA);
    Marmarapk = GetUnspendable(cp,0);
    if ( (array= cJSON_Parse(jsonstr)) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            if ( (pkstr= jstr(jitem(item,0),0)) != 0 && strlen(pkstr) == 66 )
                shares += jdouble(jitem(item,1),0);
            else
            {
                errorstr = (char *)"all items must be of the form [<pubke>, <shares>]";
                break;
            }
        }
        if ( errorstr == 0 && shares > SMALLVAL )
        {
            shares += shares * perc;
            if ( (total= AddMarmaraCoinbases(cp,mtx,firstheight,poolpk,60)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( (share= jdouble(jitem(item,1),0)) > SMALLVAL )
                    {
                        payout = (share * (total - txfee)) / shares;
                        if ( payout > 0 )
                        {
                            if ( (pkstr= jstr(jitem(item,0),0)) != 0 && strlen(pkstr) == 66 )
                            {
                                UniValue x(UniValue::VOBJ);
                                totalpayout += payout;
                                decode_hex(buf,33,pkstr);
                                mtx.vout.push_back(MakeCC1of2vout(EVAL_MARMARA,payout,Marmarapk,buf2pk(buf)));
                                x.push_back(Pair(pkstr, (double)payout/COIN));
                                a.push_back(x);
                            }
                        }
                    }
                }
                if ( totalpayout > 0 && total > totalpayout-txfee )
                {
                    poolfee = (total - totalpayout - txfee);
                    mtx.vout.push_back(MakeCC1of2vout(EVAL_MARMARA,poolfee,Marmarapk,poolpk));
                }
                rawtx = FinalizeCCTx(0,cp,mtx,poolpk,txfee,MarmaraCoinbaseOpret('P',firstheight,poolpk));
                if ( rawtx.size() == 0 )
                    errorstr = (char *)"couldnt finalize CCtx";
            } else errorstr = (char *)"couldnt find any coinbases to payout";
        }
        else if ( errorstr == 0 )
            errorstr = (char *)"no valid shares submitted";
        free(array);
    } else errorstr = (char *)"couldnt parse poolshares jsonstr";
    if ( rawtx.size() == 0 || errorstr != 0 )
    {
        result.push_back(Pair("result","error"));
        if ( errorstr != 0 )
            result.push_back(Pair("error",errorstr));
    }
    else
    {
        result.push_back(Pair("result",(char *)"success"));
        result.push_back(Pair("rawtx",rawtx));
        if ( totalpayout > 0 && total > totalpayout-txfee )
        {
            result.push_back(Pair("firstheight",firstheight));
            result.push_back(Pair("lastheight",((firstheight / MARMARA_GROUPSIZE)+1) * MARMARA_GROUPSIZE  - 1));
            result.push_back(Pair("total",ValueFromAmount(total)));
            result.push_back(Pair("totalpayout",ValueFromAmount(totalpayout)));
            result.push_back(Pair("totalshares",shares));
            result.push_back(Pair("poolfee",ValueFromAmount(poolfee)));
            result.push_back(Pair("perc",ValueFromAmount((int64_t)(100. * (double)poolfee/totalpayout * COIN))));
            result.push_back(Pair("payouts",a));
        }
    }
    return(result);
}
