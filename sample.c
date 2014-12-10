#include "oracle.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

void modifyCipherText(unsigned char* buff, int index) {
    buff[index]++;
}

void changeLastNBytes(unsigned char* buff, int nBytes, unsigned char target_value) {
    int i;
    for (i = 47; i >= nBytes; i--) {
        buff[i] = buff[i] ^ target_value ^ buff[i%16];
    }
}

int findDecryptBreak(unsigned char * buff ) {
  unsigned char buff_cpy[48];
  int ret, byte_index;

  memcpy(buff_cpy, buff, 48);

  byte_index = 16;

  while (true) {

    ret = Oracle_Send(buff_cpy, 3); // the first argument is an unsigned char array ctext;
                               // the second argument indicates how many blocks ctext has
    if (ret == 1) {
      modifyCipherText(buff_cpy, byte_index);
      byte_index++;
    }
    else {
      printf("Failed decrypt after modifying byte position: %d\n", byte_index);
      break;
    }

  }
}

// Read a ciphertext from a file, send it to the server, and get back a result.
// If you run this using the challenge ciphertext (which was generated correctly),
// you should get back a 1. If you modify bytes of the challenge ciphertext, you
// may get a different result...

// Note that this code assumes a 3-block ciphertext.

int main(int argc, char *argv[]) {
  unsigned char ctext[48]; // allocate space for 48 bytes, i.e., 3 blocks
  unsigned char buff_cpy[48];
  int i, tmp, ret;
  FILE *fpIn;

  if (argc != 2) {
    printf("Usage: sample <filename>\n");
    return -1;
  }

  fpIn = fopen(argv[1], "r");

  for(i=0; i<48; i++) {
    fscanf(fpIn, "%02x", &tmp);
    ctext[i] = tmp;
  }

  fclose(fpIn);

  Oracle_Connect();

  memcpy(buff_cpy, ctext, 48);
  while (true) {
    int failed_on_byte;
    int target_padding_value;
    int xor_value;

    failed_on_byte = findDecryptBreak(buff_cpy);
    printf("Failed to decrypt on %d\n", failed_on_byte);
    memcpy(buff_cpy, ctext, 48);
    target_padding_value = (48 - failed_on_byte) + 1;
    changeLastNBytes(buff_cpy, 48 - failed_on_byte, target_padding_value);
  }

  Oracle_Disconnect();
}
