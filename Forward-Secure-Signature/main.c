#include <stdio.h>

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>


//Global attributes
#define KEY_BIT     1024        // k
#define SIG_BIT     160         // l
BN_CTX *context;


//Data Models
typedef struct SK{
    BIGNUM *n;
    BIGNUM *s;
    BIGNUM *e;
}SK;

typedef struct PK{
    BIGNUM *n;
    BIGNUM *v;
    BIGNUM *e;
}PK;


//function defines
int GQ_BOOTSTRAP(){
    context = BN_CTX_new();
}

//TODO move to util
int PHI_N(BIGNUM *ret, BIGNUM *p, BIGNUM *q, BN_CTX *bnctx){
    //TODO error handling
    BIGNUM *phi_p;
    BIGNUM *phi_q;

    phi_p = BN_new();
    phi_q = BN_new();
    BN_sub(phi_p, p, BN_value_one());
    BN_sub(phi_q, q, BN_value_one());
    BN_mul(ret, phi_p, phi_q, bnctx);

    return 1;
}

//CAUTION: Misuse of this function may cause a memory leak.
BIGNUM* BN_value(unsigned int value){
    BIGNUM* ret = BN_new();
    BN_set_word(ret, value);
    return ret;
}

int GQ_KEYGEN(int k, int l, SK* skout, PK* pkout){
    BIGNUM *p1;
    BIGNUM *p2;
    BIGNUM *n;
    BIGNUM *s;
    BIGNUM *e;
    BIGNUM *bottom;
    BIGNUM *top;
    BIGNUM *gcd;
    BIGNUM *phi_n;

    //generate two random primes
    p1 = BN_new();
    p2 = BN_new();
    //generate prime by OpenSSL
    //http://www.eng.lsu.edu/mirrors/openssl/docs/crypto/BN_generate_prime.html
    BN_generate_prime_ex(p1, SECURE_PARAMETER/2, 1, NULL, NULL, NULL);
    BN_generate_prime_ex(p2, SECURE_PARAMETER/2, 1, NULL, NULL, NULL);

    //n is p1*p2
    n = BN_new();
    BN_mul(n, p1, p2, context);

    //s is random of z_n^*
    s = BN_new();
    BN_rand_range(s,n);

    //prepare phi_n
    gcd = BN_new();
    phi_n = BN_new();
    PHI_N(phi_n, p1, p2, context);

    //e is random( [2^l,2^(l+1) ) )
    //  such that gcd(e, pi(n)) == 1
    e = BN_new();
    BIGNUM *two;
    BIGNUM *exp_l;
    BIGNUM *exp_l_plus_one;
    two = BN_value(2);
    exp_l = BN_value(l);
    exp_l_plus_one = BN_value(l+1);
    BN_exp(bottom, two, exp_l, context);
    BN_exp(top, two, exp_l_plus_one, context);
    BN_free(two);
    BN_free(exp_l);
    BN_free(exp_l_plus_one);

    do{
        BN_rand(e, k, bottom, top);
        BN_gcd(gcd, e, phi_n, context);
    }
    while(BN_is_one(gcd));

    //sk is (n, s, e)
    BN_copy(SK->n, n);
    BN_copy(SK->s, s);
    BN_copy(SK->e, e);

    //pk is (n, v, e)
    BN_copy(PK->n, n);
    BN_copy(PK->v, v);
    BN_copy(PK->e, e);


    //free
    BN_free(p1);
    BN_free(p2);
    BN_free(n);
    BN_free(s);
    BN_free(e);
    BN_free(bottom);
    BN_free(top);
    BN_free(gcd);
    BN_free(phi_n);
    BN_free(phi_p1);
    BN_free(phi_p2);

    return 1; //success
}


int main(void)
{
    printf("hello world!\n");
    return 1;
}
