#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/bn.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/evp.h>
#include<openssl/bio.h>
#include<openssl/sha.h>

#define KEYSIZE 512

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
    
    //TODO free must locate here
    return d;
}

int getBit(BIGNUM *data, int idx, BN_CTX *bnCtx){
    BIGNUM *output = BN_new();
    BIGNUM *two = BN_new();
    BN_dec2bn(&two, "2");
    
    BN_rshift(output, data, idx);
    BN_mod(output, output, two, bnCtx);
    
    BN_clear_free(two);
    if(BN_is_one(output)){
        BN_clear_free(output);
        return 1;
    }
    else{
        BN_clear_free(output);
        return 0;
    }
}

void sqrAndMul(BIGNUM **ret, BIGNUM *x, BIGNUM *p, BIGNUM *m, BN_CTX * bnCtx){
    //result = x ^ p % m
    BIGNUM *x1 = BN_new();
    BIGNUM *x2 = BN_new();
    int i;
    int k;  //length of exponent bits

    //x1, x2 for calculate
    k = BN_num_bits(p);
    x1 = BN_dup(x);
    x2 = BN_dup(x);
    BN_mod_sqr(x2, x2, m, bnCtx);

    //Montgomery's ladder technique
    for(i = k-2; i >= 0; i--){
        if(getBit(p, i, bnCtx)  == 0){
            BN_mod_mul(x2, x1, x2, m, bnCtx);
            BN_mod_sqr(x1, x1, m, bnCtx);
        } else {
            BN_mod_mul(x1, x1, x2, m, bnCtx);
            BN_mod_sqr(x2, x2, m, bnCtx);
        }
    }
#ifdef DEBUG
    printf("x1:%s\n",BN_bn2dec(x1));*/
#endif
    BN_clear_free(*ret); //prevent memleak

    //return
    *ret = BN_dup(x1);

    //mem free
    BN_clear_free(x1);
    BN_clear_free(x2);
}

int main(int argc,char* argv[]){
    BN_CTX *bnCtx = BN_CTX_new();
    BIGNUM *prime1 = BN_new();
    BIGNUM *prime2 = BN_new();
    BIGNUM *modular = BN_new();
    BIGNUM *temp1 = BN_new();
    BIGNUM *temp2 = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *encMsg = BN_new();
    BIGNUM *final = BN_new();
    char* msg = "ITSP7501";
    char* decMsg;

    BN_dec2bn(&e,"65537");

    //KEYGEN START
    do{
        BN_generate_prime_ex(prime1, KEYSIZE, 1, NULL, NULL, NULL);
        BN_generate_prime_ex(prime2, KEYSIZE, 1, NULL, NULL, NULL);
        BN_mul(modular, prime1, prime2, bnCtx);
        BN_sub(temp1, prime1, BN_value_one());
        BN_sub(temp2, prime2, BN_value_one());
        BN_mul(phi, temp1, temp2, bnCtx);
        BN_gcd(temp1, e, phi, bnCtx);
    }while(!BN_is_one(temp1));
    //calculate d
    exEuclid(e,phi,&d);
    BN_nnmod(d, d, phi, bnCtx); //to positive number
#ifdef DEBUG
    BN_mod_mul(temp1,e,d,phi,bnCtx);
    if(BN_is_one(temp1)){
        printf("e * d is 1 ... OK\n");
    }else{
        printf("error exEuclid\n");
        return 1;
    }
#endif
    //END OF KEYGEN

    //ENC
    printf("msg : %s\n",msg);
    BN_bin2bn(msg, strlen(msg), encMsg);
    printf("0:%s\n", BN_bn2dec(encMsg));
    BN_bn2bin(encMsg, decMsg);
    printf("0:%s\n", decMsg);
    BN_mod_exp(temp1, encMsg, e, modular, bnCtx);
    printf("1:%s\n", BN_bn2dec(temp1));
    sqrAndMul(&temp2, encMsg, e, modular, bnCtx);
    printf("2:%s\n", BN_bn2dec(temp2));
    printf("\n");

    //DEC
    printf("3c:%s\n",BN_bn2dec(temp1));
    printf("4c:%s\n",BN_bn2dec(temp2));
    printf("\n");
    printf("3d:%s\n",BN_bn2dec(d));
    printf("4d:%s\n",BN_bn2dec(d));
    printf("\n");
    printf("3m:%s\n",BN_bn2dec(modular));
    printf("4m:%s\n",BN_bn2dec(modular));
    printf("\n");
    //temp1 = temp1 ^ d % modular
    BN_mod_exp(temp1, temp1, d, modular, bnCtx);
    printf("3p:%s\n",BN_bn2dec(temp1));
    //temp2 = temp2 ^ d % modular
    sqrAndMul(&final, temp2, d, modular, bnCtx);
    printf("4p:%s\n",BN_bn2dec(final));
    printf("\n");

    decMsg = (char*)malloc(BN_num_bytes(temp2));
    BN_bn2bin(temp1,decMsg);
    printf("3 dec msg :%s\n",decMsg);
    free(decMsg);

    decMsg = (char*)malloc(BN_num_bytes(final));
    BN_bn2bin(final,decMsg);
    printf("4 dec msg :%s\n",decMsg);

    return 0;
}
