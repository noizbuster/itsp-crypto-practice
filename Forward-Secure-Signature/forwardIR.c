#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h> //for big number

//==================================================
//=====================Constant=====================
//==================================================

#define KEYBIT_LEN  1024 //2048
#define KEY_SIZE    160
#define IR_T        1000 //PERIOD 1000 10000 100000


//==================================================
//====================Data Model====================
//==================================================

typedef struct IR_seed{
BIGNUM *seed;
}IR_seed;

typedef struct IR_SK_i{
    int i;      //sequence
    int T;      //period
    BIGNUM n;
    BIGNUM s_i;
    BIGNUM ti_plus_1;
    BIGNUM e_i;
    IR_seed seed;
}IR_SK_i;

typedef struct IR_PK{
    int T;      //period
    BIGNUM n;
    BIGNUM v;
}IR_PK;

typedef struct SIGNATURE{
    int j;
    BIGNUM *Y;
    BIGNUM *Z;
}sign;


//==================================================
//======================Tools=======================
//==================================================

static void printHex(const char *title, const unsigned char *s, int len)
{
    int     n;
    printf("%s:", title);
    for (n = 0; n < len; ++n) {
        if ((n % 16) == 0) {
            printf("\n%04x", n);
        }
        printf(" %02x", s[n]);
    }
    printf("\n");
}


void hexTobin(unsigned char *hex, unsigned char *bin){
    int i,j;
    for(i=0;i<KEY_SIZE;i++){
        bin[i] = (hex[(int)(i/8)]>>i)&1;
    }

}

void sqrN(BIGNUM *r, BIGNUM *bn,BIGNUM *modulus, int a,BN_CTX *bnctx){

    int i;
    BN_sqr(r,bn,bnctx);

    for(i=0;i<a;i++)
        BN_mod_mul(r,r,r,modulus,bnctx);

}


//==================================================
//=================Primitive Method=================
//==================================================

IR_seed* SEED_new(){
    IR_seed newSeed = (IR_seed*)malloc(sizeof(IR_Seed));
    newSeed->seed = BN_new();
    return newSeed;
}

void SEED_free(IR_seed* irseed){
    BN_free(irseed->seed);
    free(irseed);
}

IR_SK_i* SK_new(){
    IR_SK_i* newSK;
    newSK = (IR_SK_i*)malloc(sizeof(IR_SK_i));
    newSK->T = IR_T;    //set IR_T as default
    newSK->i = 0;
    newSK->n = BN_new();
    newSK->s_i = BN_new();
    newSK->ti_plus_1 = BN_new();
    newSK->e_i = BN_new();
    newSK->seed = SEED_new();
    return newSK;
}

void SK_free(IR_SK_i* SK){
    //no need to free T, i
    BN_free(SK->n);
    BN_free(SK->s_i);
    BN_free(SK->ti_plus_1);
    BN_free(SK->e_i);
    SEED_free(SK->seed);
    free(SK);
}

IR_PK* PK_new(){
    IR_PK* newPK;
    newPK = (IR_PK*)malloc(sizeof(IR_PK));
    newPK->T = IR_T;    //set IR_T as default
    newPK->n = BN_new();
    newPK->v = BN_new();
    return newPK;
}

void PK_free(IR_PK* PK){
    //no need to free T
    BN_free(PK->n);
    BN_free(PK->v);
    fre(PK);
}


//==================================================
//==============Scheme Related Methods==============
//==================================================

void IRKeyGenWithPrime(int k, int l, int T, SK *sk1, PK *pk,
               BIGNUM *N, BIGNUM *p, BIGNUM *q, BN_CTX *bnctx){

    BIGNUM *gcd;
    BIGNUM *t1;
    gcd = BN_new();

    //t1
    t1 = BN_new();
    BN_rand_range(t1, N);

    //ei : e1 ~ eT
    for(cnt=0;cnt<k;cnt++){
        while(1){
            BN_rand_range(sk0->S[cnt],N);
            BN_gcd(gcd,sk0->S[cnt],N,bnctx);
            if(BN_is_one(gcd)==1)
                break;
        }
     //   printf("SK[%d] : %s\n",i,BN_bn2hex(sk0->S[i]));
        sqrN(pk->U[i],sk0->S[i],N,PERIOD+1,bnctx);
     //   printf("U[%d] : %s\n",i,BN_bn2hex(pk->U[i]));
    }

}

void IRKeyGen(int k, int l, int T, SK *sk1, PK *pk){
    //attributes for keygen
    BIGNUM *N;
    BIGNUM *p;
    BIGNUM *q;
    BN_CTX *bnctx;
    //attributes for generate prime
    BIGNUM *mod,*rem;
    BIGNUM *gcd;
    int cnt;

    //bootstraping for generate prime
    bnctx   = BN_CTX_new();
    mod     = BN_new();
    rem     = BN_new();
    BN_dec2bn(&rem,"3");
    BN_dec2bn(&mod,"4");
    //generate prime p,q & make N
    p = BN_new();
    q = BN_new();
    N = BN_new();
    BN_generate_prime_ex(p,k/2,1,mod,rem,NULL);
    BN_generate_prime_ex(q,k/2,1,mod,rem,NULL);
    BN_mul(N,p,q, bnctx);

    IRKeyGenWithPrime(k, l, T, sk1, pk, N, p, q, bnctx);

}

void KeyGen(int k,int l,int T,SK *sk0, PK *pk, BIGNUM *N, BIGNUM *p, BIGNUM *q,BN_CTX *bnctx){
    //
    // BIGNUM *mod,*rem;
    // int i;
    //
    // mod = BN_new();
    // rem= BN_new();
    //
    // BN_dec2bn(&rem,"3");
    // BN_dec2bn(&mod,"4");
    //
    // p = BN_new();
    // q = BN_new();
    //
    //
    // BN_generate_prime_ex(p,KEYBIT_LEN/2,1,mod,rem,NULL);
    // BN_generate_prime_ex(q,KEYBIT_LEN/2,1,mod,rem,NULL);
    //
    // BN_mul(N,p,q, bnctx);
    //
    // BN_copy(sk0->N, N);
    // BN_copy(pk->N,N);
    //
    // //printf("p : %s\nq : %s\nN : %s\n",BN_bn2hex(p),BN_bn2hex(q),BN_bn2hex(N));
    //
    // gcd = BN_new();
    //
    // for(i=0;i<KEY_SIZE;i++){
    //
    //     while(1)
    //     {
    //         BN_rand_range(sk0->S[i],N);
    //         BN_gcd(gcd,sk0->S[i],N,bnctx);
    //         if(BN_is_one(gcd)==1)
    //             break;
    //     }
    //  //   printf("SK[%d] : %s\n",i,BN_bn2hex(sk0->S[i]));
    //     sqrN(pk->U[i],sk0->S[i],N,PERIOD+1,bnctx);
    //  //   printf("U[%d] : %s\n",i,BN_bn2hex(pk->U[i]));
    // }

    BN_free(p);
    BN_free(q);

    BN_free(gcd);
    BN_free(mod);
    BN_free(rem);

}

SK *Upd(SK *skj, int j,BN_CTX *bnctx){
    int i;
    SK *skn;

    skn = (SK*)malloc(sizeof(SK));
    initSK(skn,PERIOD,j+1);

    if(j==PERIOD) return;

    for(i=0;i<KEY_SIZE;i++){
        BN_sqr(skn->S[i],skj->S[i],bnctx);
    }

    skn->N = BN_new();

    BN_copy(skn->N,skj->N);

    return skn;
}


sign *Sign(SK *skj,char *msg, BN_CTX *bnctx){
    BIGNUM *R,*Y, *M,*Z,*gcd,*temp;

    unsigned char hash[SHA_DIGEST_LENGTH];
    char bin[KEY_SIZE];
    unsigned int signLen;
    int i;
    sign *s;


    int cnt=0;
    char *dummy;
    unsigned char *test;
    int ret=0;

    s = (sign*)malloc(sizeof(sign));

    R = BN_new();
    Y = BN_new();
    M = BN_new();
    Z = BN_new();
    temp = BN_new();
    gcd = BN_new();

    dummy = (char*)malloc(128);
    memset(dummy,0,128);

    //printf("sign start\n");

    while(1)
    {
        BN_rand_range(R,skj->N);
        BN_gcd(gcd,R,skj->N,bnctx);
        if(BN_is_one(gcd)==1)
            break;
    }

    //printf("select R\n");
    sqrN(Y,R,skj->N,(PERIOD+1-skj->i),bnctx);

    //BN_hex2bn(&M,msg);
    BN_bin2bn(msg,strlen(msg),M);
    //printHex("M",BN_bn2hex(M),5);
    //BN_bin2bn(msg,sizeof(msg),M);
    //printHex("Y",BN_bn2hex(Y),128);
    //msg = BN_bn2hex(M);
    //printf("msg1: %s\n",msg);
    BN_add(temp,M,Y);

    BN_bn2bin(temp,dummy);
    //printHex("addm",dummy,128);
    SHA1(dummy, 128, hash);

    hexTobin(hash,bin);

    //printf("msg :%s\n",msg);
    //printHex("hash",hash,SHA_DIGEST_LENGTH);
    //printHex("bin",bin,KEY_SIZE);
    BN_copy(Z,R);
    //printf("ok\n");
    for(i=0;i<KEY_SIZE;i++){
        if(bin[i]==1){
            BN_mod_mul(Z,Z,skj->S[i],skj->N,bnctx);
            cnt++;
        }
    }

    //printf("signok %d\n",cnt);


    s->j=skj->i;
    s->Y = BN_new();
    s->Z = BN_new();
    BN_copy(s->Y,Y);
    BN_copy(s->Z,Z);

    //test = BN_bn2hex(s->Z);
    //printHex("test",test,128);

    return s;

}

int Verify(char *msg, sign *s,PK *p,BN_CTX *bnctx){
    int i,cnt=0;
    unsigned char hash[SHA_DIGEST_LENGTH];
    unsigned char bin[KEY_SIZE];
    BIGNUM *M,*Z,*Z_ver,*temp;
    unsigned char *test;
    char *dummy;

    M = BN_new();
    Z = BN_new();
    Z_ver = BN_new();
    temp = BN_new();
    dummy = (char*)malloc(128);
    memset(dummy,0,128);

    //BN_hex2bn(&M,msg);
    BN_bin2bn(msg,strlen(msg),M);
    //printHex("M",BN_bn2hex(M),5);
    //msg = BN_bn2hex(M);
    BN_add(temp,M,s->Y);

    BN_bn2bin(temp,dummy);
    //printHex("addm",dummy,128);
    SHA1(dummy,128,hash);

    //printf("msg : %s\n",msg);

    //printHex("Y",BN_bn2hex(s->Y),128);
    //printHex("hash",hash,SHA_DIGEST_LENGTH);

    hexTobin(hash,bin);

    //printHex("bin",bin,KEY_SIZE);

    //test = BN_bn2hex(s->Z);
    //printHex("test",test,128);

    sqrN(Z,s->Z,p->N,(PERIOD+1-s->j),bnctx);

    BN_copy(Z_ver,s->Y);
    for(i=0;i<KEY_SIZE;i++){
        if(bin[i]==1){
            BN_mod_mul(Z_ver,Z_ver,p->U[i],p->N,bnctx);
            cnt++;
        }
    }
    //printf("verfiy %d\n",cnt);
    if(BN_cmp(Z,Z_ver)==0) return 1;
    else return 0;
}

int main(int argc, char *argv[]){

    BIGNUM *p,*q;
    BIGNUM *N;
    BN_CTX *bnctx;
    SK *sk0;
    PK *pk;
    sign *s;

    SK *sk1;

    char msg[]="itsp";
    char msg2[]="itsp";
    int ret;
    //key setting


    bnctx = BN_CTX_new();

    N = BN_new();

    sk0 = (SK*)malloc(sizeof(SK));
    sk1 = (SK*)malloc(sizeof(SK));
    pk = (PK*)malloc(sizeof(PK));
    s = (sign*)malloc(sizeof(PK));

    initSK(sk0,PERIOD,0);
    initPK(pk,PERIOD);
    printf("ok\n");
    KeyGen(KEYBIT_LEN,KEY_SIZE,PERIOD,sk0,pk,N,p,q,bnctx);

    sk1 = Upd(sk0,0,bnctx);
    s = Sign(sk1,msg,bnctx);
    ret = Verify(msg2,s,pk,bnctx);
    printf("%d\n",ret);
    freeSK(sk0);
    freePK(pk);
    BN_free(N);
    return 0;
}
