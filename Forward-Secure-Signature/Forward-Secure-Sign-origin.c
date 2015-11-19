#include <stdio.h>
#include<stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include<time.h>

#define KEYBIT_LEN 1024    
#define KEY_SIZE 160
#define PERIOD 10000 //10000 100000

typedef struct SK{
    BIGNUM *N;
    int T;
    int i;
    BIGNUM *S[KEY_SIZE];
}SK;

typedef struct PK{
    BIGNUM *N;
    int T;
    BIGNUM *U[KEY_SIZE];
}PK;

typedef struct sign{
    int j;
    BIGNUM *Y;
    BIGNUM *Z;
}sign;

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
        bin[i] = (hex[i/8]>>i) &1;
        //printf("%c",bin[i]+'0');
    }
    //printf("\n");

}

void initSK(SK *sk,int T,int i){
    int j;


    sk->N = BN_new();
    sk->T=T;
    sk->i=i;
    for(j=0;j<KEY_SIZE;j++){
        sk->S[j] = BN_new();
    }
}

void freeSK(SK *sk){
    int i;
    BN_free(sk->N);
    for(i=0;i<KEY_SIZE;i++)
        BN_free(sk->S[i]);
}

void initPK(PK *pk,int T){
    int i;
    pk->N = BN_new();
    pk->T = T;
    for(i=0;i<KEY_SIZE;i++)
        pk->U[i] = BN_new();
}

void freePK(PK *pk){
    int i;
    BN_free(pk->N);
    for(i=0;i<KEY_SIZE;i++)
        BN_free(pk->U[i]);
}
void sqrN(BIGNUM *r, BIGNUM *bn,BIGNUM *modulus, int a,BN_CTX *bnctx){

    int i;
    BN_sqr(r,bn,bnctx);

    for(i=0;i<a;i++)
        BN_mod_mul(r,r,r,modulus,bnctx);

}

void KeyGen(int k,int l,int T,SK *sk0, PK *pk, BIGNUM *N, BIGNUM *p, BIGNUM *q,BN_CTX *bnctx){

    BIGNUM *mod,*rem;
    BIGNUM *gcd;
    int i;

    mod = BN_new();
    rem= BN_new();

    BN_dec2bn(&rem,"3");
    BN_dec2bn(&mod,"4");

    p = BN_new();
    q = BN_new();


    BN_generate_prime_ex(p,KEYBIT_LEN/2,1,mod,rem,NULL);
    BN_generate_prime_ex(q,KEYBIT_LEN/2,1,mod,rem,NULL);

    BN_mul(N,p,q, bnctx);

    BN_copy(sk0->N, N);
    BN_copy(pk->N,N);

    //printf("p : %s\nq : %s\nN : %s\n",BN_bn2hex(p),BN_bn2hex(q),BN_bn2hex(N));

    gcd = BN_new();

    for(i=0;i<KEY_SIZE;i++){

        while(1)
        {
            BN_rand_range(sk0->S[i],N);
            BN_gcd(gcd,sk0->S[i],N,bnctx);
            if(BN_is_one(gcd)==1)
                break;
        }
        //   printf("SK[%d] : %s\n",i,BN_bn2hex(sk0->S[i]));
        sqrN(pk->U[i],sk0->S[i],N,PERIOD+1,bnctx);
        //   printf("U[%d] : %s\n",i,BN_bn2hex(pk->U[i]));
    }

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
    unsigned char bin[KEY_SIZE];
    unsigned int signLen;
    int i;
    sign *s;
    unsigned char *dummy;


    int cnt=0;
    unsigned char *test;
    int ret=0;
    int len;

    s = (sign*)malloc(sizeof(sign));

    R = BN_new();
    Y = BN_new();
    M = BN_new();
    Z = BN_new();
    temp = BN_new();
    s->Y = BN_new();
    s->Z = BN_new();
    gcd = BN_new();





    //printf("sign start\n");

    while(1)
    {
        BN_rand_range(R,skj->N);
        BN_gcd(gcd,R,skj->N,bnctx);
        if(BN_is_one(gcd)==1)
            break;
        else{
            BN_free(gcd);
        }
    }

    //printf("select R\n");
    sqrN(Y,R,skj->N,(PERIOD+1-skj->i),bnctx);

    //BN_hex2bn(&M,msg);
    BN_bin2bn(msg,strlen(msg),M);
    //printHex("M",BN_bn2hex(M),BN_num_bytes(M));
    //BN_bin2bn(msg,sizeof(msg),M);
    //printHex("Y",BN_bn2hex(Y),128);
    //msg = BN_bn2hex(M);
    //printf("msg1: %s\n",msg);
    BN_add(temp,M,Y);
    len = BN_num_bytes(temp);
    dummy = (char*)malloc(len);
    memset(dummy,0,len);

    BN_bn2bin(temp,dummy);
    //printHex("addm",dummy,len);
    SHA1(dummy, len, hash);
    //printHex("hash",hash,SHA_DIGEST_LENGTH);

    hexTobin(hash,bin);

    //printf("msg :%s\n",msg);
    //printHex("hash",hash,SHA_DIGEST_LENGTH);
    //printHex("bin",bin,KEY_SIZE);
    BN_copy(Z,R);
    //printf("ok\n");
    for(i=0;i<KEY_SIZE;i++){
        if(bin[i]==1){
            BN_mod_mul(Z,Z,skj->S[i],skj->N,bnctx);
        }
    }

    //printf("signok %d\n",cnt);

    //BN_new();

    s->j=skj->i;
    BN_copy(s->Y,Y);
    BN_copy(s->Z,Z);

    //test = BN_bn2hex(s->Z);
    //printHex("test",test,128);
    BN_free(M);
    BN_free(Y);
    BN_free(Z);
    BN_free(R);
    BN_free(temp);
    free(dummy);

    //BN_free(gcd);

    return s;

}

int Verify(unsigned char *msg, sign *s,PK *p,BN_CTX *bnctx){
    int i,cnt=0;
    unsigned char hash[SHA_DIGEST_LENGTH];
    unsigned char bin[KEY_SIZE];
    BIGNUM *M,*Z,*Z_ver,*temp;
    unsigned char *test;
    char *dummy;
    int len;
    M = BN_new();
    Z = BN_new();
    Z_ver = BN_new();
    temp = BN_new();


    /*
       BN_init(&M);
       BN_init(&Z);
       BN_init(&Z_ver);
       BN_init(&temp);
       */
    //BN_hex2bn(&M,msg);
    BN_bin2bn(msg,strlen(msg),M);
    //printHex("M",BN_bn2hex(M),BN_num_bytes(M));
    //msg = BN_bn2hex(M);
    BN_add(temp,M,s->Y);
    len = BN_num_bytes(temp);
    dummy = (char*)malloc(len);
    memset(dummy,0,len);

    BN_bn2bin(temp,dummy);
    //printHex("addm",dummy,len);
    SHA1(dummy,len,hash);
    
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

    free(dummy);
    BN_free(M);
    BN_free(temp);
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
    float start, end;

    SK *sk1;

    unsigned char msg[]="itsp";
    unsigned char msg2[]="itsp";
    int ret;
    //key setting


    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_state(0);
    EVP_cleanup();
    bnctx = BN_CTX_new();

    N = BN_new();

    sk0 = (SK*)malloc(sizeof(SK));
    sk1 = (SK*)malloc(sizeof(SK));
    pk = (PK*)malloc(sizeof(PK));
    s = (sign*)malloc(sizeof(sign));

    printf("==========Kegen Start==========\n");
    start = clock();
    initSK(sk0,PERIOD,0);
    initPK(pk,PERIOD);
    //printf("ok\n");
    KeyGen(KEYBIT_LEN,KEY_SIZE,PERIOD,sk0,pk,N,p,q,bnctx);
    end = clock();
    printf("Kegen Time : %f\n", (end - start)/CLOCKS_PER_SEC);
    printf("==========Kegen End===========\n");

    printf("==========Update Start==========\n");
    start = clock();
    sk1 = Upd(sk0,0,bnctx);
    end = clock();
    printf("Update time : %f\n", (end-start)/CLOCKS_PER_SEC);
    printf("==========Update End==========\n");

    printf("==========Sign Start==========\n");
    start = clock();
    s = Sign(sk1,msg,bnctx);
    end = clock();
    printf("Sign Time : %f\n", (end - start)/CLOCKS_PER_SEC);
    printf("==========Sign End===========\n");

    printf("==========Verify End=========\n");
    start = clock();
    ret = Verify(msg2,s,pk,bnctx);
    end = clock();
    printf("Verify : %s\n",ret? "Yes":"No");
    printf("Verify Time : %f\n",(end - start)/CLOCKS_PER_SEC);
    printf("==========Verify End=========\n");
    freeSK(sk0);
    freePK(pk);
    BN_free(N);
    return 0;
}

