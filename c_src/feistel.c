#include "feistel.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Minimal SHA256 implementation - public domain minimal version
// For brevity this uses a tiny reference implementation adapted for embedding.
// In production, replace with a vetted implementation or hardware crypto.

// ---- Begin tiny-sha256 ----
typedef struct { uint32_t state[8]; uint64_t bitcount; uint8_t buf[64]; } sha256_ctx;
static uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };

static uint32_t rotr(uint32_t x,int r){return (x>>r)|(x<<(32-r));}

static void sha256_transform(sha256_ctx *ctx,const uint8_t *blk){
  uint32_t W[64];
  for(int i=0;i<16;i++){
    W[i]=((uint32_t)blk[4*i]<<24)|((uint32_t)blk[4*i+1]<<16)|((uint32_t)blk[4*i+2]<<8)|((uint32_t)blk[4*i+3]);
  }
  for(int t=16;t<64;t++){
    uint32_t s0 = rotr(W[t-15],7)^rotr(W[t-15],18)^(W[t-15]>>3);
    uint32_t s1 = rotr(W[t-2],17)^rotr(W[t-2],19)^(W[t-2]>>10);
    W[t]=W[t-16]+s0+W[t-7]+s1;
  }
  uint32_t a=ctx->state[0],b=ctx->state[1],c=ctx->state[2],d=ctx->state[3];
  uint32_t e=ctx->state[4],f=ctx->state[5],g=ctx->state[6],h=ctx->state[7];
  for(int t=0;t<64;t++){
    uint32_t S1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t temp1 = h + S1 + ch + K[t] + W[t];
    uint32_t S0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp2 = S0 + maj;
    h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
  }
  ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
  ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(sha256_ctx *ctx){
  ctx->state[0]=0x6a09e667;ctx->state[1]=0xbb67ae85;ctx->state[2]=0x3c6ef372;ctx->state[3]=0xa54ff53a;
  ctx->state[4]=0x510e527f;ctx->state[5]=0x9b05688c;ctx->state[6]=0x1f83d9ab;ctx->state[7]=0x5be0cd19;
  ctx->bitcount=0; memset(ctx->buf,0,64);
}

static void sha256_update(sha256_ctx *ctx,const uint8_t *data,size_t len){
  size_t idx = (ctx->bitcount>>3) & 0x3F;
  ctx->bitcount += ((uint64_t)len)<<3;
  while(len){
    size_t take = 64 - idx; if(take>len) take=len;
    memcpy(ctx->buf+idx,data,take);
    idx+=take; data+=take; len-=take;
    if(idx==64){ sha256_transform(ctx,ctx->buf); idx=0; }
  }
}

static void sha256_final(sha256_ctx *ctx,uint8_t out[32]){
  uint8_t pad[64]; memset(pad,0,64); pad[0]=0x80;
  uint8_t lenbuf[8]; uint64_t bits = ctx->bitcount;
  for(int i=0;i<8;i++) lenbuf[7-i]=(uint8_t)(bits & 0xFF), bits>>=8;
  size_t idx = (ctx->bitcount>>3) & 0x3F;
  size_t padlen = (idx < 56) ? (56 - idx) : (120 - idx);
  sha256_update(ctx,pad,padlen);
  sha256_update(ctx,lenbuf,8);
  for(int i=0;i<8;i++){
    out[4*i+0] = (uint8_t)(ctx->state[i] >> 24);
    out[4*i+1] = (uint8_t)(ctx->state[i] >> 16);
    out[4*i+2] = (uint8_t)(ctx->state[i] >> 8);
    out[4*i+3] = (uint8_t)(ctx->state[i] >> 0);
  }
}

static void sha256(const uint8_t *data,size_t len,uint8_t out[32]){
  sha256_ctx ctx; sha256_init(&ctx); sha256_update(&ctx,data,len); sha256_final(&ctx,out);
}
// ---- End tiny-sha256 ----

// HMAC-SHA256 (key len arbitrary)
static void hmac_sha256(const uint8_t *key,size_t key_len,const uint8_t *data,size_t data_len,uint8_t out[32]){
  uint8_t keyb[64]; memset(keyb,0,64);
  if(key_len>64){ sha256(key,key_len,keyb); } else { memcpy(keyb,key,key_len); }
  uint8_t okey[64], ikey[64];
  for(int i=0;i<64;i++){ okey[i]=keyb[i]^0x5c; ikey[i]=keyb[i]^0x36; }
  uint8_t tmp[32];
  sha256_ctx ctx; sha256_init(&ctx); sha256_update(&ctx,ikey,64); sha256_update(&ctx,data,data_len); sha256_final(&ctx,tmp);
  sha256_init(&ctx); sha256_update(&ctx,okey,64); sha256_update(&ctx,tmp,32); sha256_final(&ctx,out);
}

// Feistel context
struct FeistelCtx { uint8_t *master_key; size_t master_len; unsigned rounds; unsigned block_size; unsigned half; uint8_t *round_keys; };

FeistelCtx *feistel_create(const uint8_t *master_key, size_t master_key_len, unsigned rounds, unsigned block_size){
  if(block_size%2!=0 || block_size==0 || block_size>32) return NULL;
  if(rounds<1) return NULL;
  FeistelCtx *ctx = (FeistelCtx*)calloc(1,sizeof(FeistelCtx));
  if(!ctx) return NULL;
  ctx->master_key = (uint8_t*)malloc(master_key_len);
  memcpy(ctx->master_key, master_key, master_key_len);
  ctx->master_len = master_key_len;
  ctx->rounds = rounds; ctx->block_size = block_size; ctx->half = block_size/2;
  ctx->round_keys = (uint8_t*)malloc((size_t)rounds * ctx->half);
  if(!ctx->round_keys){ feistel_free(ctx); return NULL; }
  // derive round keys
  uint8_t tmp[16];
  uint8_t digest[32];
  for(unsigned i=0;i<rounds;i++){
    uint8_t data[9]; memcpy(data,"FEISTEL",7); data[7]=(uint8_t)((i>>8)&0xff); data[8]=(uint8_t)(i&0xff);
    hmac_sha256(ctx->master_key, ctx->master_len, data, 9, digest);
    memcpy(ctx->round_keys + (size_t)i * ctx->half, digest, ctx->half);
  }
  return ctx;
}

void feistel_free(FeistelCtx *ctx){ if(!ctx) return; if(ctx->master_key) free(ctx->master_key); if(ctx->round_keys) free(ctx->round_keys); free(ctx); }

static void xor_bytes(uint8_t *dst,const uint8_t *a,const uint8_t *b,size_t n){ for(size_t i=0;i<n;i++) dst[i]=a[i]^b[i]; }

static void round_fn(const uint8_t *right, size_t half, const uint8_t *rk, uint8_t *out){
  uint8_t tmp[64]; memcpy(tmp, right, half); memcpy(tmp+half, rk, half);
  uint8_t digest[32]; sha256(tmp, half+half, digest);
  memcpy(out, digest, half);
}

static void encrypt_block(FeistelCtx *ctx,const uint8_t *in,uint8_t *out){
  unsigned half = ctx->half;
  uint8_t L[32], R[32], F[32];
  memcpy(L, in, half); memcpy(R, in+half, half);
  for(unsigned r=0;r<ctx->rounds;r++){
    round_fn(R, half, ctx->round_keys + (size_t)r*half, F);
    uint8_t newL[32]; xor_bytes(newL, L, F, half);
    memcpy(L, R, half); memcpy(R, newL, half);
  }
  memcpy(out, L, half); memcpy(out+half, R, half);
}

static void decrypt_block(FeistelCtx *ctx,const uint8_t *in,uint8_t *out){
  unsigned half = ctx->half;
  uint8_t L[32], R[32], F[32];
  memcpy(L, in, half); memcpy(R, in+half, half);
  for(int ri=(int)ctx->rounds-1; ri>=0; --ri){
    round_fn(L, half, ctx->round_keys + (size_t)ri*half, F);
    uint8_t newR[32]; xor_bytes(newR, R, F, half);
    memcpy(R, L, half); memcpy(L, newR, half);
  }
  memcpy(out, L, half); memcpy(out+half, R, half);
}

// PKCS#7
static uint8_t *pkcs7_pad(const uint8_t *in,size_t in_len,size_t block_size,size_t *out_len){
  size_t pad = block_size - (in_len % block_size);
  if(pad==0) pad = block_size;
  *out_len = in_len + pad;
  uint8_t *out = (uint8_t*)malloc(*out_len);
  if(!out) return NULL;
  memcpy(out,in,in_len);
  memset(out+in_len, (int)pad, pad);
  return out;
}

static int pkcs7_unpad(uint8_t *buf,size_t *len,size_t block_size){
  if(*len==0 || (*len%block_size)!=0) return -1;
  uint8_t pad = buf[*len-1];
  if(pad==0 || pad>block_size) return -1;
  for(size_t i=0;i<pad;i++) if(buf[*len-1-i]!=pad) return -1;
  *len -= pad; return 0;
}

int feistel_encrypt(FeistelCtx *ctx, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len){
  size_t padded_len; uint8_t *padded = pkcs7_pad(in,in_len,ctx->block_size,&padded_len);
  if(!padded) return -1;
  uint8_t *ct = (uint8_t*)malloc(padded_len);
  if(!ct){ free(padded); return -2; }
  for(size_t i=0;i<padded_len;i+=ctx->block_size){ encrypt_block(ctx,padded+i,ct+i); }
  free(padded);
  *out = ct; *out_len = padded_len; return 0;
}

int feistel_decrypt(FeistelCtx *ctx, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len){
  if((in_len % ctx->block_size)!=0) return -1;
  uint8_t *pt = (uint8_t*)malloc(in_len);
  if(!pt) return -2;
  for(size_t i=0;i<in_len;i+=ctx->block_size){ decrypt_block(ctx,in+i,pt+i); }
  size_t len = in_len;
  if(pkcs7_unpad(pt,&len,ctx->block_size)!=0){ free(pt); return -3; }
  *out = pt; *out_len = len; return 0;
}

void print_hex(const uint8_t *buf,size_t len){ for(size_t i=0;i<len;i++) printf("%02x",buf[i]); printf("\n"); }

// Demo main when built as host tool
#ifdef FEISTEL_DEMO_MAIN
#include <stdio.h>
int main(void){
  const uint8_t key[] = "host-demo-key-123";
  FeistelCtx *ctx = feistel_create(key, sizeof(key)-1, 12, 8);
  const uint8_t msg[] = "hello feistel demo";
  uint8_t *ct; size_t ctlen;
  if(feistel_encrypt(ctx,msg,sizeof(msg)-1,&ct,&ctlen)!=0){ printf("encrypt failed\n"); return 1; }
  printf("ciphertext: "); print_hex(ct,ctlen);
  uint8_t *pt; size_t ptlen;
  if(feistel_decrypt(ctx,ct,ctlen,&pt,&ptlen)!=0){ printf("decrypt failed\n"); return 2; }
  printf("recovered: %.*s\n", (int)ptlen, (char*)pt);
  free(ct); free(pt); feistel_free(ctx);
  return 0;
}
#endif
