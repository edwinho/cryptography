/* difference distribution table */

#include <stdio.h>

#define LEN 16
/* CIPHERTWO */
//int sbox[LEN] = {0x6,0x4,0xc,0x5,0x0,0x7,0x2,0xe,0x1,0xf,0x3,0xd,0x8,0xa,0x9,0xb};

/* PRESENT */
int sbox[LEN] = {0xc,0x5,0x6,0xb,0x9,0x0,0xa,0xd,0x3,0xe,0xf,0x8,0x4,0x7,0x1,0x2};

int main(){
  int i,j,k,value;
  int table[LEN][LEN];

  for(i=0;i<LEN;i++)
    for(j=0;j<LEN;j++)
      table[i][j] = 0;
  
  for(k=0;k<LEN;k++){
    for(i=0;i<LEN;i++){
      j = i^k;
      value = sbox[i]^sbox[j];
      table[k][value]++;
    }
  }

  printf("  |");
  for(i=0;i<LEN;i++)
    printf("%2x",i);
  printf("\n");
  for(i=0;i<LEN;i++){
    printf("%2x|",i);
    for(j=0;j<LEN;j++){
      table[i][j]>0?printf("%2d",table[i][j]):printf(" -");
    }
    printf("\n");
  }
  
  return 0;
}
