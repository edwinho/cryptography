/* International Data Encryption Algorithm */

#include <stdio.h>

typedef unsigned short uint16;
typedef unsigned int uint32;
typedef unsigned char uchar8;

#define ROUNDS 8
#define KEY_LENGTH 16
#define NUM_SUBKEYS 52
  
uint16 enkey[9][6];
uint16 dekey[9][6];
uint32 longkeys[4];

uint16 message[4];

/* multiplication modulo 2^16+1 of 16-bit integers
 * with the zero subblock corresponding to 2^16
 */
uint16 mul_mod(uint16 a, uint16 b){
  
  uint32 p;
  if (a != 0) {
    if (b != 0) {
      p = a * b;
      b = p & 0xFFFF;
      a = p >> 16;
      return (uint16)(b - a + (b < a ? 1 : 0));
    } else
      return (uint16)(1 - a);
  } else
    return (uint16)(1 - b);

}

uint16 mul_mod_reverse(uint16 x){
  int MODMUL = 0x10001; // modulus being used is (2^16)+1

  int g0,g1,g2,v0,v1,v2,y;	// assorted variables for inverse calc

  // 0 and 1 are self-inverse
  if(x <= 1)
    return x;

  /* initialise values for extended GCD calculation */
  g0 = MODMUL; g1 = x; g2 = 0;
  v0 = 0; v1 = 1; v2 = 0;

  /* find the inverse using extended GCD algorithm */
  while(g1 != 0) {
    y  = g0 / g1;
    g2 = g0 - y * g1;
    v2 = v0 - y * v1;
    /* Shift everything back one i.e. g1 -> g0 ready to do it again */
    g0 = g1; g1 = g2;
    v0 = v1; v1 = v2;
  }
  /* Result is v0 but if v0 < 0 need to mod it */
  if(v0 < 0)
    v0 = v0 + MODMUL;       /* add MODMUL so positive */

  return ((uint16)v0);
}

/* addition modulo 2^16 of 16-bit integers */
uint16 add_mod(uint16 x, uint16 y){
  return (x + y) & 0xFFFF;
}

uint16 add_mod_reverse(uint16 x){
  return (65536 - x) & 0xFFFF;
}

void tobit16(uchar8 *ciphertext){
  uint16 i, j;
  i = 0;
  for(j=0; j<8; j+=2){
    message[i] = ((uint16)ciphertext[j])<<8 | ((uint16)ciphertext[j+1]);

    i++;
  }
  
}

void tobit32(uchar8 *key){

  uint16 i, j;
  i = 0;
  for(j=0; j<16; j+=4){
    longkeys[i] = ((uint32)key[j])<<24 | ((uint32)key[j+1])<<16 | ((uint32)key[j+2])<<8 | ((uint32)key[j+3]);

    i++;
  }

}

/* the 128-bit key register is rotated by 25 bit
 * positions to the left.
 */
void RL25()
{
  uint32 top25;

  top25 = (longkeys[0]>>7);	/* save MSB's top 25 bits for rotate */
  longkeys[0]= (longkeys[0]<<25) | (longkeys[1]>>7);	/* rotate each long in turn */
  longkeys[1]= (longkeys[1]<<25) | (longkeys[2]>>7);
  longkeys[2]= (longkeys[2]<<25) | (longkeys[3]>>7);
  longkeys[3]= (longkeys[3]<<25) | top25;		/* using saved top 25 bits */

}

void setKey(uchar8 *key) {

  uint16 i, j, skn;	// loop indices i,j; subkey number

  if (key == NULL)
    return;

  tobit32(key);	// convert key to long array 
  
  skn = 0;            /* counts which output subkey we are up to */
  for(i=0;i<7;i++) {  /* loop over 8 use and rotate iterations   */
    for(j=0;j<4;j++) {
      enkey[skn/6][skn%6] = (uint16)(longkeys[j]>>16);
      enkey[skn/6][(skn+1)%6] = (uint16)(longkeys[j]);
      skn = skn + 2;
      // break out when have created all subkeys
      if (skn >= NUM_SUBKEYS)
        break;
    }
    RL25();  /* rotate longkey left & repeat */
  }

  for(i=0;i<9;i++) {   /* For 8 rounds plus output, find decrypt keys */
    dekey[i][0] = mul_mod_reverse(enkey[8-i][0]);       /* multiplicative inverse */

    /* For rounds 2 to 8, decrypt subkeys 2,3 should be swapped */
    if(i!=0&&i!=8) {
      dekey[i][1] = (uint16) add_mod_reverse(enkey[8-i][2]);  /* additive inverse */
      dekey[i][2] = (uint16) add_mod_reverse(enkey[8-i][1]);  /* additive inverse */
    } else {
      dekey[i][1] = (uint16) add_mod_reverse(enkey[8-i][1]);  /* additive inverse */
      dekey[i][2] = (uint16) add_mod_reverse(enkey[8-i][2]);  /* additive inverse */
    }

    dekey[i][3] = mul_mod_reverse(enkey[8-i][3]);       /* multiplicative inverse */

    /* Don't need 5th and 6th decrypt subkeys for output round */
    if(i!=8) {
      dekey[i][4] = enkey[8-i-1][4];
      dekey[i][5] = enkey[8-i-1][5];
    }
  }

}

void encrypt(){
  uint16 i;
  uint16 data[4] = {message[0], message[1], message[2], message[3]};  //data[i]:16-bit plaintext subblock
  uint16 step[14];

  for (i=0;i<8;i++) {		/* for each of 8 rounds in IDEA */

    /* perform 14 steps per round */
    step[0] = mul_mod(data[0],enkey[i][0]); /* data1 * subkey1 */
    step[1] = data[1] + enkey[i][1];    /* data2 + subkey2 */
    step[2] = data[2] + enkey[i][2];    /* data3 + subkey3 */
    step[3] = mul_mod(data[3],enkey[i][3]); /* data4 * subkey4 */
    step[4] = step[0] ^ step[2];      /* step 1 XOR step 3 */
    step[5] = step[1] ^ step[3];      /* step 2 XOR step 4 */
    step[6] = mul_mod(step[4],enkey[i][4]); /* step 5 * subkey 5 */
    step[7] = step[5] + step[6];      /* step 6 + step 7 */
    step[8] = mul_mod(step[7],enkey[i][5]); /* step 8 * subkey 6 */
    step[9] = step[6] + step[8];     /* step 7 + step 9 */
    step[10] = step[0] ^ step[8];    /* step 1 XOR step 9 */
    step[11] = step[2] ^ step[8];    /* step 3 XOR step 9 */
    step[12] = step[1] ^ step[9];    /* step 2 XOR step 10 */
    step[13] = step[3] ^ step[9];    /* step 4 XOR step 10 */

    /* There is an inherent swap from one round to the next (no need to
       do it here) - a trap for young players */
    data[0] = step[10];
    data[1] = step[11];
    data[2] = step[12];
    data[3] = step[13];
      
  }
  
  /* For output transformation must UNswap 12 and 13 */
  data[1] = step[12];
  data[2] = step[11];
  
  /* Now need to do the output transformation */
  data[0] = mul_mod(data[0],enkey[8][0]);   /* data 1 * out subkey 1 */
  data[1] = data[1] + enkey[8][1];      /* data 2 + out subkey 2 */
  data[2] = data[2] + enkey[8][2];      /* data 3 + out subkey 3 */
  data[3] = mul_mod(data[3],enkey[8][3]);   /* data 4 * out subkey 4 */


  uint16 k;
  /* print the ciphertext */
  printf("cipertext:");
  for(k=0; k<4; k++){
    printf("%04X", data[k]);
    message[k] = data[k];
  }
  printf("\n");
}

void decrypt(){
  uint16 i;
  uint16 data[4] = {message[0], message[1], message[2], message[3]};  //data[i]:16-bit ciphertext subblock
  uint16 step[14];

  for (i=0;i<8;i++) {		/* for each of 8 rounds in IDEA */

    /* perform 14 steps per round */
    step[0] = mul_mod(data[0],dekey[i][0]); /* data1 * subkey1 */
    step[1] = data[1] + dekey[i][1];    /* data2 + subkey2 */
    step[2] = data[2] + dekey[i][2];    /* data3 + subkey3 */
    step[3] = mul_mod(data[3],dekey[i][3]); /* data4 * subkey4 */
    step[4] = step[0] ^ step[2];      /* step 1 XOR step 3 */
    step[5] = step[1] ^ step[3];      /* step 2 XOR step 4 */
    step[6] = mul_mod(step[4],dekey[i][4]); /* step 5 * subkey 5 */
    step[7] = step[5] + step[6];      /* step 6 + step 7 */
    step[8] = mul_mod(step[7],dekey[i][5]); /* step 8 * subkey 6 */
    step[9] = step[6] + step[8];     /* step 7 + step 9 */
    step[10] = step[0] ^ step[8];    /* step 1 XOR step 9 */
    step[11] = step[2] ^ step[8];    /* step 3 XOR step 9 */
    step[12] = step[1] ^ step[9];    /* step 2 XOR step 10 */
    step[13] = step[3] ^ step[9];    /* step 4 XOR step 10 */

    /* There is an inherent swap from one round to the next (no need to
       do it here) - a trap for young players */
    data[0] = step[10];
    data[1] = step[11];
    data[2] = step[12];
    data[3] = step[13];
   
  }
  
  /* For output transformation must UNswap 12 and 13 */
  data[1] = step[12];
  data[2] = step[11];
    
  /* Now need to do the output transformation */
  data[0] = mul_mod(data[0],dekey[8][0]);   /* data 1 * out subkey 1 */
  data[1] = data[1] + dekey[8][1];      /* data 2 + out subkey 2 */
  data[2] = data[2] + dekey[8][2];      /* data 3 + out subkey 3 */
  data[3] = mul_mod(data[3],dekey[8][3]);   /* data 4 * out subkey 4 */

  uint16 k;
  /* print a result of decryption */
  printf("decryption:");
  for(k=0; k<4; k++){
    printf("%c%c", data[k]>>8,data[k]);
  }
  printf("\n");
}

int main(){

  uchar8 key[16];
  uchar8 ciphertext[8];

  /* input 8 characters as plaintext */
  printf("Input plaintext:");
  scanf("%s",ciphertext);
  tobit16(ciphertext);

  /* input 16 characters as key */
  printf("Input the key to encrypt:");
  scanf("%s",key);

  setKey(key);
  encrypt();
  decrypt();
  
  return 0;
}
