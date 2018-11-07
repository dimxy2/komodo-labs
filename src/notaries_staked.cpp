
#include "notaries_staked.h"
#include "crosschain.h"
#include "cc/CCinclude.h"
#include <cstring>

extern char NOTARYADDRS[64][36];
extern std::string NOTARY_ADDRESS,NOTARY_PUBKEY;
extern int32_t STAKED_ERA,IS_STAKED_NOTARY,IS_KOMODO_NOTARY;
extern pthread_mutex_t staked_mutex;
extern uint8_t NOTARY_PUBKEY33[33],NUM_NOTARIES;

// Era 1 set of pubkeys
const char *notaries_STAKED1[][2] =
{
    {"blackjok3r", "021914947402d936a89fbdd1b12be49eb894a1568e5e17bb18c8a6cffbd3dc106e" }, // RTVti13NP4eeeZaCCmQxc2bnPdHxCJFP9x
    {"alright", "0285657c689b903218c97f5f10fe1d10ace2ed6595112d9017f54fb42ea1c1dda8" }, //RXmXeQ8LfJK6Y1aTM97cRz9Gu5f6fmR3sg
    {"webworker01", "031d1fb39ae4dca28965c3abdbd21faa0f685f6d7b87a60561afa7c448343fef6d" }, //RGsQiArk5sTmjXZV9UzGMW5njyvtSnsTN8
    {"CrisF", "03f87f1bccb744d90fdbf7fad1515a98e9fc7feb1800e460d2e7565b88c3971bf3" }, //RMwEpnaVe3cesWbMqqKYPPkaLcDkooTDgZ
    {"smk762", "02eacef682d2f86e0103c18f4da46116e17196f3fb8f73ed931acb78e81d8e1aa5" }, // RQVvzJ8gepCDVjhqCAc5Tia1kTmt8KDPL9
    {"jorian", "02150c410a606b898bcab4f083e48e0f98a510e0d48d4db367d37f318d26ae72e3" }, // RFgzxZe2P4RWKx6E9QGPK3rx3TXeWxSqa8
    {"TonyL", "021a559101e355c907d9c553671044d619769a6e71d624f68bfec7d0afa6bd6a96" }, // RHq3JsvLxU45Z8ufYS6RsDpSG4wi6ucDev
    {"Emman", "038f642dcdacbdf510b7869d74544dbc6792548d9d1f8d73a999dd9f45f513c935" }, //RN2KsQGW36Ah4NorJDxLJp2xiYJJEzk9Y6
    {"CHMEX", "03ed125d1beb118d12ff0a052bdb0cee32591386d718309b2924f2c36b4e7388e6" }, // RF4HiVeuYpaznRPs7fkRAKKYqT5tuxQQTL
    {"metaphilibert", "0344182c376f054e3755d712361672138660bda8005abb64067eb5aa98bdb40d10" }, // RG28QSnYFADBg1dAVkH1uPGYS6F8ioEUM2
    {"jusoaresf", "02dfb7ed72a23f6d07f0ea2f28192ee174733cc8412ec0f97b073007b78fab6346" }, // RBQGfE5Hxsjm1BPraTxbneRuNasPDuoLnu
    {"mylo", "03f6b7fcaf0b8b8ec432d0de839a76598b78418dadd50c8e5594c0e557d914ec09" }, // RXN4hoZkhUkkrnef9nTUDw3E3vVALAD8Kx
    {"blackjok3r2", "02f7597468703c1c5c8465dd6d43acaae697df9df30bed21494d193412a1ea193e" }, // RWHGbrLSP89fTzNVF9U9xiekDYJqcibTca
    {"blackjok3r3", "03c3e4c0206551dbf3a4b24d18e5d2737080541184211e3bfd2b1092177410b9c2" }, // RMMav2AVse5XHPvDfTzRpMbFhK3GqFmtSN
    {"kmdkrazy", "02f7597468703c1c5c8465dd6d43acaae697df9df30bed21494d193412a1ea193e" }, // RWHGbrLSP89fTzNVF9U9xiekDYJqcibTca
    {"alrighttest", "02e9dfe248f453b499315a90375e58a1c9ad79f5f3932ecb2205399a0f262d65fc" }, // RBevSstS8JtDXMEFNcJws4QTYN4PcE2VL5
    {"alrighttest1", "03527c7ecd6a8c5db6d685a64e6e18c1edb49e2f057a434f56c3f1253a26e9c6a2" }, // RBw2jNU3dnGk86ZLqPMadJwRwg3NU8eC6s
};

int num_notaries_STAKED1 = (sizeof(notaries_STAKED1)/sizeof(*notaries_STAKED1));

// Era 2 set of pubkeys
const char *notaries_STAKED2[][2] =
{
    {"blackjok3r", "021914947402d936a89fbdd1b12be49eb894a1568e5e17bb18c8a6cffbd3dc106e" }, // RTVti13NP4eeeZaCCmQxc2bnPdHxCJFP9x
    {"alright", "0285657c689b903218c97f5f10fe1d10ace2ed6595112d9017f54fb42ea1c1dda8" }, //RXmXeQ8LfJK6Y1aTM97cRz9Gu5f6fmR3sg
    {"webworker01", "031d1fb39ae4dca28965c3abdbd21faa0f685f6d7b87a60561afa7c448343fef6d" }, //RGsQiArk5sTmjXZV9UzGMW5njyvtSnsTN8
    {"CrisF", "03f87f1bccb744d90fdbf7fad1515a98e9fc7feb1800e460d2e7565b88c3971bf3" }, //RMwEpnaVe3cesWbMqqKYPPkaLcDkooTDgZ
    {"smk762", "02eacef682d2f86e0103c18f4da46116e17196f3fb8f73ed931acb78e81d8e1aa5" }, // RQVvzJ8gepCDVjhqCAc5Tia1kTmt8KDPL9
    {"jorian", "02150c410a606b898bcab4f083e48e0f98a510e0d48d4db367d37f318d26ae72e3" }, // RFgzxZe2P4RWKx6E9QGPK3rx3TXeWxSqa8
    {"TonyL", "021a559101e355c907d9c553671044d619769a6e71d624f68bfec7d0afa6bd6a96" }, // RHq3JsvLxU45Z8ufYS6RsDpSG4wi6ucDev
    {"Emman", "038f642dcdacbdf510b7869d74544dbc6792548d9d1f8d73a999dd9f45f513c935" }, //RN2KsQGW36Ah4NorJDxLJp2xiYJJEzk9Y6
    {"CHMEX", "03ed125d1beb118d12ff0a052bdb0cee32591386d718309b2924f2c36b4e7388e6" }, // RF4HiVeuYpaznRPs7fkRAKKYqT5tuxQQTL
    {"metaphilibert", "0344182c376f054e3755d712361672138660bda8005abb64067eb5aa98bdb40d10" }, // RG28QSnYFADBg1dAVkH1uPGYS6F8ioEUM2
    {"jusoaresf", "02dfb7ed72a23f6d07f0ea2f28192ee174733cc8412ec0f97b073007b78fab6346" }, // RBQGfE5Hxsjm1BPraTxbneRuNasPDuoLnu
    {"mylo", "03f6b7fcaf0b8b8ec432d0de839a76598b78418dadd50c8e5594c0e557d914ec09" }, // RXN4hoZkhUkkrnef9nTUDw3E3vVALAD8Kx
    {"blackjok3r2", "02f7597468703c1c5c8465dd6d43acaae697df9df30bed21494d193412a1ea193e" }, // RWHGbrLSP89fTzNVF9U9xiekDYJqcibTca
    {"blackjok3r3", "03c3e4c0206551dbf3a4b24d18e5d2737080541184211e3bfd2b1092177410b9c2" }, // RMMav2AVse5XHPvDfTzRpMbFhK3GqFmtSN
    {"kmdkrazy", "02f7597468703c1c5c8465dd6d43acaae697df9df30bed21494d193412a1ea193e" }, // RWHGbrLSP89fTzNVF9U9xiekDYJqcibTca
    {"alrighttest", "02e9dfe248f453b499315a90375e58a1c9ad79f5f3932ecb2205399a0f262d65fc" }, // RBevSstS8JtDXMEFNcJws4QTYN4PcE2VL5
    {"alrighttest1", "03527c7ecd6a8c5db6d685a64e6e18c1edb49e2f057a434f56c3f1253a26e9c6a2" }, // RBw2jNU3dnGk86ZLqPMadJwRwg3NU8eC6s
};

int num_notaries_STAKED2 = (sizeof(notaries_STAKED2)/sizeof(*notaries_STAKED2));

// Era 3 set of pubkeys
const char *notaries_STAKED3[][2] =
{
    {"blackjok3r", "021914947402d936a89fbdd1b12be49eb894a1568e5e17bb18c8a6cffbd3dc106e" }, // RTVti13NP4eeeZaCCmQxc2bnPdHxCJFP9x
    {"alright", "0285657c689b903218c97f5f10fe1d10ace2ed6595112d9017f54fb42ea1c1dda8" }, //RXmXeQ8LfJK6Y1aTM97cRz9Gu5f6fmR3sg
    {"webworker01", "031d1fb39ae4dca28965c3abdbd21faa0f685f6d7b87a60561afa7c448343fef6d" }, //RGsQiArk5sTmjXZV9UzGMW5njyvtSnsTN8
    {"CrisF", "03f87f1bccb744d90fdbf7fad1515a98e9fc7feb1800e460d2e7565b88c3971bf3" }, //RMwEpnaVe3cesWbMqqKYPPkaLcDkooTDgZ
    {"smk762", "02eacef682d2f86e0103c18f4da46116e17196f3fb8f73ed931acb78e81d8e1aa5" }, // RQVvzJ8gepCDVjhqCAc5Tia1kTmt8KDPL9
    {"jorian", "02150c410a606b898bcab4f083e48e0f98a510e0d48d4db367d37f318d26ae72e3" }, // RFgzxZe2P4RWKx6E9QGPK3rx3TXeWxSqa8
    {"TonyL", "021a559101e355c907d9c553671044d619769a6e71d624f68bfec7d0afa6bd6a96" }, // RHq3JsvLxU45Z8ufYS6RsDpSG4wi6ucDev
    {"Emman", "038f642dcdacbdf510b7869d74544dbc6792548d9d1f8d73a999dd9f45f513c935" }, //RN2KsQGW36Ah4NorJDxLJp2xiYJJEzk9Y6
    {"CHMEX", "03ed125d1beb118d12ff0a052bdb0cee32591386d718309b2924f2c36b4e7388e6" }, // RF4HiVeuYpaznRPs7fkRAKKYqT5tuxQQTL
    {"metaphilibert", "0344182c376f054e3755d712361672138660bda8005abb64067eb5aa98bdb40d10" }, // RG28QSnYFADBg1dAVkH1uPGYS6F8ioEUM2
    {"jusoaresf", "02dfb7ed72a23f6d07f0ea2f28192ee174733cc8412ec0f97b073007b78fab6346" }, // RBQGfE5Hxsjm1BPraTxbneRuNasPDuoLnu
    {"mylo", "03f6b7fcaf0b8b8ec432d0de839a76598b78418dadd50c8e5594c0e557d914ec09" }, // RXN4hoZkhUkkrnef9nTUDw3E3vVALAD8Kx
    {"blackjok3r2", "02f7597468703c1c5c8465dd6d43acaae697df9df30bed21494d193412a1ea193e" }, // RWHGbrLSP89fTzNVF9U9xiekDYJqcibTca
    {"blackjok3r3", "03c3e4c0206551dbf3a4b24d18e5d2737080541184211e3bfd2b1092177410b9c2" }, // RMMav2AVse5XHPvDfTzRpMbFhK3GqFmtSN
    {"kmdkrazy", "02f7597468703c1c5c8465dd6d43acaae697df9df30bed21494d193412a1ea193e" }, // RWHGbrLSP89fTzNVF9U9xiekDYJqcibTca
    {"alrighttest", "02e9dfe248f453b499315a90375e58a1c9ad79f5f3932ecb2205399a0f262d65fc" }, // RBevSstS8JtDXMEFNcJws4QTYN4PcE2VL5
    {"alrighttest1", "03527c7ecd6a8c5db6d685a64e6e18c1edb49e2f057a434f56c3f1253a26e9c6a2" }, // RBw2jNU3dnGk86ZLqPMadJwRwg3NU8eC6s
};

int num_notaries_STAKED3 = (sizeof(notaries_STAKED3)/sizeof(*notaries_STAKED3));

// Era 4 set of pubkeys
const char *notaries_STAKED4[][2] =
{
    {"blackjok3r", "021914947402d936a89fbdd1b12be49eb894a1568e5e17bb18c8a6cffbd3dc106e" }, // RTVti13NP4eeeZaCCmQxc2bnPdHxCJFP9x
    {"alright", "0285657c689b903218c97f5f10fe1d10ace2ed6595112d9017f54fb42ea1c1dda8" }, //RXmXeQ8LfJK6Y1aTM97cRz9Gu5f6fmR3sg
    {"webworker01", "031d1fb39ae4dca28965c3abdbd21faa0f685f6d7b87a60561afa7c448343fef6d" }, //RGsQiArk5sTmjXZV9UzGMW5njyvtSnsTN8
    {"CrisF", "03f87f1bccb744d90fdbf7fad1515a98e9fc7feb1800e460d2e7565b88c3971bf3" }, //RMwEpnaVe3cesWbMqqKYPPkaLcDkooTDgZ
    {"smk762", "02eacef682d2f86e0103c18f4da46116e17196f3fb8f73ed931acb78e81d8e1aa5" }, // RQVvzJ8gepCDVjhqCAc5Tia1kTmt8KDPL9
    {"jorian", "02150c410a606b898bcab4f083e48e0f98a510e0d48d4db367d37f318d26ae72e3" }, // RFgzxZe2P4RWKx6E9QGPK3rx3TXeWxSqa8
    {"TonyL", "021a559101e355c907d9c553671044d619769a6e71d624f68bfec7d0afa6bd6a96" }, // RHq3JsvLxU45Z8ufYS6RsDpSG4wi6ucDev
    {"Emman", "038f642dcdacbdf510b7869d74544dbc6792548d9d1f8d73a999dd9f45f513c935" }, //RN2KsQGW36Ah4NorJDxLJp2xiYJJEzk9Y6
    {"CHMEX", "03ed125d1beb118d12ff0a052bdb0cee32591386d718309b2924f2c36b4e7388e6" }, // RF4HiVeuYpaznRPs7fkRAKKYqT5tuxQQTL
    {"metaphilibert", "0344182c376f054e3755d712361672138660bda8005abb64067eb5aa98bdb40d10" }, // RG28QSnYFADBg1dAVkH1uPGYS6F8ioEUM2
    {"jusoaresf", "02dfb7ed72a23f6d07f0ea2f28192ee174733cc8412ec0f97b073007b78fab6346" }, // RBQGfE5Hxsjm1BPraTxbneRuNasPDuoLnu
    {"mylo", "03f6b7fcaf0b8b8ec432d0de839a76598b78418dadd50c8e5594c0e557d914ec09" }, // RXN4hoZkhUkkrnef9nTUDw3E3vVALAD8Kx
    {"blackjok3r2", "02f7597468703c1c5c8465dd6d43acaae697df9df30bed21494d193412a1ea193e" }, // RWHGbrLSP89fTzNVF9U9xiekDYJqcibTca
    {"blackjok3r3", "03c3e4c0206551dbf3a4b24d18e5d2737080541184211e3bfd2b1092177410b9c2" }, // RMMav2AVse5XHPvDfTzRpMbFhK3GqFmtSN
    {"kmdkrazy", "02f7597468703c1c5c8465dd6d43acaae697df9df30bed21494d193412a1ea193e" }, // RWHGbrLSP89fTzNVF9U9xiekDYJqcibTca
    {"alrighttest", "02e9dfe248f453b499315a90375e58a1c9ad79f5f3932ecb2205399a0f262d65fc" }, // RBevSstS8JtDXMEFNcJws4QTYN4PcE2VL5
    {"alrighttest1", "03527c7ecd6a8c5db6d685a64e6e18c1edb49e2f057a434f56c3f1253a26e9c6a2" }, // RBw2jNU3dnGk86ZLqPMadJwRwg3NU8eC6s
};

int num_notaries_STAKED4 = (sizeof(notaries_STAKED4)/sizeof(*notaries_STAKED4));

int is_STAKED(const char *chain_name) {
  int STAKED = 0;
  if ( (strcmp(chain_name, "STAKED") == 0) || (strncmp(chain_name, "STAKED", 6) == 0) )
    STAKED = 1;
  else if ( (strcmp(chain_name, "STKD") == 0) || (strncmp(chain_name, "STKD", 4) == 0) )
    STAKED = 2;
  else if ( (strcmp(chain_name, "CFEK") == 0) || (strncmp(chain_name, "CFEK", 4) == 0) )
    STAKED =  3;
  //fprintf(stderr, "This chains is: %s which is: %d\n", chain_name,STAKED);
  return(STAKED);
};

int STAKED_era(int timestamp)
{
  int8_t era = 0;
  if (timestamp <= STAKED_NOTARIES_TIMESTAMP1)
    era = 1;
  else if (timestamp <= STAKED_NOTARIES_TIMESTAMP2 && timestamp >= (STAKED_NOTARIES_TIMESTAMP1 + STAKED_ERA_GAP))
    era = 2;
  else if (timestamp <= STAKED_NOTARIES_TIMESTAMP3 && timestamp >= (STAKED_NOTARIES_TIMESTAMP2 + STAKED_ERA_GAP))
    era = 3;
  else if (timestamp <= STAKED_NOTARIES_TIMESTAMP4 && timestamp >= (STAKED_NOTARIES_TIMESTAMP3 + STAKED_ERA_GAP))
    era = 4;
  else
    era = 0;
  // if we are in a gap, return era 0, this allows to invalidate notarizations when in GAP.
  return(era);
};

#ifdef SERVER
int8_t updateStakedNotary() {
    std::string notaryname;
    if ( NOTARY_ADDRESS.empty() ) {
      char Raddress[18]; uint8_t pubkey33[33];
      decode_hex(pubkey33,33,(char *)NOTARY_PUBKEY.c_str());
      pubkey2addr((char *)Raddress,(uint8_t *)pubkey33);
      NOTARY_ADDRESS.assign(Raddress);
    }
    return(StakedNotaryID(notaryname,(char *)NOTARY_ADDRESS.c_str()));
}
#else
int8_t updateStakedNotary() {
    return(-1);
}
#endif

int8_t StakedNotaryID(std::string &notaryname, char *Raddress) {
  int8_t notaryID = -1;
    if ( STAKED_ERA != 0 ) {
      switch (STAKED_ERA) {
        case 1:
          notaryID = ScanStakedArray(notaries_STAKED1,num_notaries_STAKED1,Raddress,notaryname);
          break;
        case 2:
          notaryID = ScanStakedArray(notaries_STAKED2,num_notaries_STAKED2,Raddress,notaryname);
          break;
        case 3:
          notaryID = ScanStakedArray(notaries_STAKED3,num_notaries_STAKED3,Raddress,notaryname);
          break;
        case 4:
          notaryID = ScanStakedArray(notaries_STAKED4,num_notaries_STAKED4,Raddress,notaryname);
          break;
      }
    }
    return(notaryID);
}

int8_t numStakedNotaries(uint8_t pubkeys[64][33],int8_t era) {
    int i; int8_t retval = 0;
    static uint8_t staked_pubkeys1[64][33],staked_pubkeys2[64][33],didstaked1,didstaked2;
    static uint8_t staked_pubkeys3[64][33],staked_pubkeys4[64][33],didstaked3,didstaked4;
    static char ChainName[65];

    if ( ChainName[0] == 0 )
    {
        if ( ASSETCHAINS_SYMBOL[0] == 0 )
            strcpy(ChainName,"KMD");
        else
            strcpy(ChainName,ASSETCHAINS_SYMBOL);
    }

    if ( era != 0 ) {
      switch (era) {
        case 1:
          if ( didstaked1 == 0 )
          {
              for (i=0; i<num_notaries_STAKED1; i++) {
                  decode_hex(staked_pubkeys1[i],33,(char *)notaries_STAKED1[i][1]);
              }
              didstaked1 = 1;
              printf("%s is a STAKED chain in era 1 \n",ChainName);
          }
          memcpy(pubkeys,staked_pubkeys1,num_notaries_STAKED1 * 33);
          retval = num_notaries_STAKED1;
          break;
        case 2:
          if ( didstaked2 == 0 )
          {
              for (i=0; i<num_notaries_STAKED2; i++) {
                  decode_hex(staked_pubkeys2[i],33,(char *)notaries_STAKED2[i][1]);
              }
              didstaked2 = 1;
              printf("%s is a STAKED chain in era 2 \n",ChainName);
          }
          memcpy(pubkeys,staked_pubkeys2,num_notaries_STAKED2 * 33);
          retval = num_notaries_STAKED2;
          break;
        case 3:
          if ( didstaked3 == 0 )
          {
              for (i=0; i<num_notaries_STAKED3; i++) {
                  decode_hex(staked_pubkeys3[i],33,(char *)notaries_STAKED3[i][1]);
              }
              didstaked3 = 1;
              printf("%s is a STAKED chain in era 3 \n",ChainName);
          }
          memcpy(pubkeys,staked_pubkeys3,num_notaries_STAKED3 * 33);
          retval = num_notaries_STAKED3;
          break;
        case 4:
          if ( didstaked4 == 0 )
          {
              for (i=0; i<num_notaries_STAKED4; i++) {
                  decode_hex(staked_pubkeys4[i],33,(char *)notaries_STAKED4[i][1]);
              }
              didstaked4 = 1;
              printf("%s is a STAKED chain in era 4 \n",ChainName);
          }
          memcpy(pubkeys,staked_pubkeys4,num_notaries_STAKED4 * 33);
          retval = num_notaries_STAKED4;
          break;
      }
    }
    else
    {
        // era is zero so we need to null out the pubkeys.
        memset(pubkeys,0,64 * 33);
        printf("%s is a STAKED chain and is in an ERA GAP.\n",ASSETCHAINS_SYMBOL);
        return(64);
    }
    return(retval);
}

void UpdateNotaryAddrs(uint8_t pubkeys[64][33],int8_t numNotaries) {
    static int didinit;
    if ( didinit == 0 ) {
        pthread_mutex_init(&staked_mutex,NULL);
    }
    if ( pubkeys[0][0] == 0 )
    {
        // null pubkeys, era 0.
#ifdef SERVER
        pthread_mutex_lock(&staked_mutex);
        memset(NOTARYADDRS,0,sizeof(NOTARYADDRS));
        NUM_NOTARIES = 0;
        pthread_mutex_unlock(&staked_mutex);
#endif
    }
    else
    {
        // staked era is set.
#ifdef SERVER
        pthread_mutex_lock(&staked_mutex);
        for (int i = 0; i<numNotaries; i++) {
            pubkey2addr((char *)NOTARYADDRS[i],(uint8_t *)pubkeys[i]);
            NUM_NOTARIES = numNotaries;
        }
        pthread_mutex_unlock(&staked_mutex);
#endif
    }
}

int8_t ScanStakedArray(const char *notaries_chosen[][2],int num_notaries,char *Raddress,std::string &notaryname) {
    for (size_t i = 0; i < num_notaries; i++) {
        //fprintf(stderr, "address [%ld]: %s\n",i,NOTARYADDRS[i]);
        if ( strcmp(Raddress,NOTARYADDRS[i]) == 0 ) {
            notaryname.assign(notaries_chosen[i][0]);
            //printf("notary number: %ld\n",i );
            return(i);
        }
    }
    return(-1);
}

CrosschainAuthority Choose_auth_STAKED(int chosen_era) {
  CrosschainAuthority auth;
  switch (chosen_era) {
    case 1:
      auth = auth_STAKED_chosen(notaries_STAKED1,num_notaries_STAKED1);
      break;
    case 2:
      auth = auth_STAKED_chosen(notaries_STAKED2,num_notaries_STAKED2);
      break;
    case 3:
      auth = auth_STAKED_chosen(notaries_STAKED3,num_notaries_STAKED3);
      break;
    case 4:
      auth = auth_STAKED_chosen(notaries_STAKED4,num_notaries_STAKED4);
      break;
  }
  return(auth);
};

CrosschainAuthority auth_STAKED_chosen(const char *notaries_chosen[][2],int num_notaries) {
    CrosschainAuthority auth;
    auth.requiredSigs = (num_notaries / 5);
    auth.size = num_notaries;
    for (int n=0; n<auth.size; n++)
        for (size_t i=0; i<33; i++)
            sscanf(notaries_chosen[n][1]+(i*2), "%2hhx", auth.notaries[n]+i);
    return auth;
};
