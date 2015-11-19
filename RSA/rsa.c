#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/bn.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/evp.h>
#include<openssl/bio.h>
#include<openssl/sha.h>

BIGNUM* exEuclid(BIGNUM* a,BIGNUM* b, BIGNUM** x){
    BIGNUM* c = BN_new();
    BIGNUM* d = BN_new();
    BIGNUM* uc = BN_new();
    BIGNUM* vc = BN_new();
    BIGNUM* ud = BN_new();
    BIGNUM* vd = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* temp1 = BN_new();
    BIGNUM* temp2 = BN_new();
    BIGNUM* temp3 = BN_new();
    BIGNUM* temp4 = BN_new();
    BN_CTX *bnCtx = BN_CTX_new();

    c = BN_dup(a);
    d = BN_dup(b);

    BN_one(uc);
    BN_zero(vc);

    BN_zero(ud);
    BN_one(vd);

    while(!BN_is_zero(c)){
        BN_div(q,r,d,c,bnCtx);
        d = BN_dup(c);
        c = BN_dup(r);

        temp1 = BN_dup(ud);
        temp2 = BN_dup(vd);
        ud = BN_dup(uc);
        vd = BN_dup(vc);

        BN_mul(temp3,q,uc,bnCtx);
        BN_mul(temp4,q,vc,bnCtx);

        BN_sub(uc,temp1,temp3);
        BN_sub(vc,temp2,temp4);

    }

    *x = BN_dup(ud);

    return d;
}

void bytesToBits(unsigned char* bytes,int bytesLen,unsigned char** bits,int bitsLen){

    int i, j, idx;
    char unsigned source;
    int bitNum = 8;
    idx = 0;

    for( i = 0; i < bytesLen; i++){
        source = bytes[i];

        for(j = 0; j < bitNum; j++){
            bits[0][idx+j] = ((source & (1 << j)) > 0);
            #ifdef DEBUG
            printf("%c",bits[0][idx+j]);
            #endif
        }

        idx+=8;
        #ifdef DEBUG
        printf("source : %d byteidx: %d idx : %d\n",source,i,idx);
        #endif
    }
    #ifdef DEBUG
    printf("%s\n",*bits);
    #endif
}

void sqrAndMul(BIGNUM *x, BIGNUM *p, BIGNUM *m,BIGNUM** result){

    BIGNUM *z= BN_new();
    BN_CTX *bnCtx = BN_CTX_new();
    int i;
    unsigned char* bytes;
    unsigned char* bits;

    bytes = (char*)malloc(BN_num_bytes(p));
    memset(bytes,0,BN_num_bytes(p));
    BN_bn2bin(p,bytes);

    bits = (char*)malloc(BN_num_bits(p));
    memset(bits,0,BN_num_bits(p));
    bytesToBits(bytes,BN_num_bytes(p),&bits,BN_num_bits(p));

    printf("-- %d --\n",BN_num_bits(p));
    printf("-- %d --\n",BN_num_bytes(p));

    BN_one(z);

    for(i = BN_num_bits(p)-1; i >= 0; i--){

        BN_mod_sqr(z, z, m, bnCtx);
        #ifdef DEBUG
        printf("%c",bits[i]);
        #endif
        if(bits[i] == 1){
            BN_mod_mul(z,z,x,m,bnCtx);
        }
        if(bits[i] != 0 && bits[i] != 1){
            printf("bit :%c:%d ",bits[i],i);
        }
    }
    BN_mod(NULL,z,m,bnCtx);

    printf("\n");

    *result = BN_dup(z);
}

void test(){
    BIGNUM* two =BN_new();
    BIGNUM* mod =BN_new();
    BIGNUM* byte =BN_new();
    BIGNUM* result = BN_new();
    char *re;
    char *ttwo, *tmod,*tbyte;

    BN_dec2bn(&two,"2");
    BN_dec2bn(&mod,"7");
    BN_dec2bn(&byte,"10");

    printf("------------------start-----------\n");

    ttwo = (char*)malloc(BN_num_bytes(two));
    BN_bn2bin(two, ttwo);
    tmod = (char*)malloc(BN_num_bytes(mod));
    BN_bn2bin(mod, tmod);
    tbyte = (char*)malloc(BN_num_bytes(byte));
    BN_bn2bin(byte, tbyte);

    BN_bin2bn(ttwo, BN_num_bytes(two), two);
    BN_bin2bn(tmod, BN_num_bytes(mod), mod);
    BN_bin2bn(tbyte, BN_num_bytes(byte), byte);

    sqrAndMul(two,byte,mod,&result);

    re =BN_bn2dec(result);

    printf("2^3 mod 7 result : %s\n",re);
}

int main(int argc,char* argv[]){

    BIGNUM *prime1 = BN_new();
    BIGNUM *prime2 = BN_new();
    BIGNUM *modular = BN_new();
    BIGNUM *temp1 = BN_new();
    BIGNUM *temp2 = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *encMsg = BN_new();

    BN_CTX *bnCtx = BN_CTX_new();

    char* msg = "ITSP7501";
    char* decMsg;

    BN_dec2bn(&e,"65537");

    //setup
    do{
        BN_generate_prime_ex(prime1,512,1,NULL,NULL,NULL);
        BN_generate_prime_ex(prime2,512,1,NULL,NULL,NULL);

        BN_mul(modular,prime1,prime2,bnCtx);

        BN_sub(temp1,prime1,BN_value_one());
        BN_sub(temp2,prime2,BN_value_one());
        BN_mul(phi,temp1,temp2,bnCtx);
        BN_gcd(temp1,e,phi,bnCtx);
    }while(!BN_is_one(temp1));

    exEuclid(e,phi,&d);

    BN_mod_mul(temp1,e,d,phi,bnCtx);

    if(BN_is_one(temp1)){
        printf("OK\n");
    }else{
        printf("error exEuclid\n");
        return 1;
    }

    //encryption
    printf("msg : %s\n",msg);

    BN_bin2bn(msg,strlen(msg),encMsg);
    BN_mod_exp(temp1,encMsg,e,modular,bnCtx);

    printf("1:%s\n",BN_bn2dec(temp1));

    sqrAndMul(encMsg,e,modular,&temp2);

    printf("2:%s\n",BN_bn2dec(temp2));

    //decryption
    BN_mod_exp(temp1,temp1,d,modular,bnCtx);

    printf("3:%s\n",BN_bn2dec(temp1));

    sqrAndMul(temp2,d,modular,&temp1);

    printf("4:%s\n",BN_bn2dec(temp1));

    decMsg = (char*)malloc(BN_num_bytes(temp1));

    BN_bn2bin(temp1,decMsg);

    #ifdef DEBUG
    printf("dec msg :%s\n",decMsg);
    #endif

    test();

    return 0;
}
