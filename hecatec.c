#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "reddye_kdf.c"

/* Heqet */

void usage() {
    printf("hecatec <encrypt/decrypt> <input file> <output file> <password>\n");
    exit(0);
}

int keylen = 32;
uint64_t h[8] = {0};
uint64_t k[8];

uint64_t rotate(uint64_t a, uint64_t b) {
    return ((a << b) | (a >> (64 - b)));
}

/* H(h) Sh */

void H(uint64_t *h) {
    int i;
    uint64_t x;
    for (i = 0; i < 8; i++) {
        x = h[i];
	h[i] = (h[i] + h[(i + 4) & 0x07]);
	h[i] = h[i] ^ x;
	h[i] = rotate(h[i], 2);
    }
}

void n(unsigned char *key, unsigned *keya) {
    uint64_t n[4];
    int i;
    int m = 0;
    int inc = 8;
    for (i = 0; i < (keylen / 8); i++) {
        h[i] = ((uint64_t)(key[m]) << 56) + ((uint64_t)key[m+1] << 48) + ((uint64_t)key[m+2] << 40) + ((uint64_t)key[m+3] << 32) + ((uint64_t)key[m+4] << 24) + ((uint64_t)key[m+5] << 16) + ((uint64_t)key[m+6] << 8) + (uint64_t)key[m+7];
        m += inc;
    }

    for (i = 0; i < (keylen / 8); i++) {
        h[i] = ((uint64_t)(keya[m]) << 56) + ((uint64_t)keya[m+1] << 48) + ((uint64_t)keya[m+2] << 40) + ((uint64_t)keya[m+3] << 32) + ((uint64_t)keya[m+4] << 24) + ((uint64_t)keya[m+5] << 16) + ((uint64_t)keya[m+6] << 8) + (uint64_t)keya[m+7];
        m += inc;
    }
}

int main(int argc, char *argv[]) {
    FILE *infile, *outfile, *randfile;
    char *in, *out, *mode;
    unsigned char *data = NULL;
    unsigned char *buf = NULL;
    int x = 0;
    int i = 0;
    int ch;
    int buflen = 131072;
    int bsize;
    uint64_t output;
    unsigned char *key[keylen];
    unsigned char *keya[keylen];
    unsigned char *password;
    int iterations = 20;
    unsigned char *salt = "HecateMyLove";
    unsigned char block[buflen];
    if (argc != 5) {
        usage();
    }
    mode = argv[1];
    in = argv[2];
    out = argv[3];
    password = argv[4];
    infile = fopen(in, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    outfile = fopen(out, "wb");
    int c = 0;
    if (strcmp(mode, "encrypt") == 0) {
        long blocks = fsize / buflen;
        long extra = fsize % buflen;
        if (extra != 0) {
            blocks += 1;
        }
        kdf(password, key, salt, iterations, keylen);
        n(key, keya);
        for (int d = 0; d < blocks; d++) {
            fread(block, buflen, 1, infile);
            bsize = sizeof(block);
	    c = 0;
            for (int b = 0; b < (bsize / 8); b++) {
		H(h);
		output = ((((h[1] ^ h[7]) ^ h[3]) + h[5]));
		k[0] = (output & 0x00000000000000FF);
		k[1] = (output & 0x000000000000FF00) >> 8;
		k[2] = (output & 0x0000000000FF0000) >> 16;
		k[3] = (output & 0x00000000FF000000) >> 24;
		k[4] = (output & 0x000000FF00000000) >> 32;
		k[5] = (output & 0x0000FF0000000000) >> 40;
		k[6] = (output & 0x00FF000000000000) >> 48;
		k[7] = (output & 0xFF00000000000000) >> 56;
		for (c = (b * 8); c < ((b *8) + 8); c++) {
                    block[c] = block[c] ^ k[c & 0x07];
		}
            }
            if (d == (blocks - 1) && extra != 0) {
                bsize = extra;
            }
            fwrite(block, 1, bsize, outfile);
        }
    }
    else if (strcmp(mode, "decrypt") == 0) {
        long blocks = (fsize) / buflen;
        long extra = (fsize) % buflen;
        if (extra != 0) {
            blocks += 1;
        }
        kdf(password, key, salt, iterations, keylen);
        n(key, keya);
        for (int d = 0; d < blocks; d++) {
            fread(block, buflen, 1, infile);
            bsize = sizeof(block);
            for (int b = 0; b < (bsize / 8); b++) {
		H(h);
		output = ((((h[1] ^ h[7]) ^ h[3]) + h[5]));
		k[0] = (output & 0x00000000000000FF);
		k[1] = (output & 0x000000000000FF00) >> 8;
		k[2] = (output & 0x0000000000FF0000) >> 16;
		k[3] = (output & 0x00000000FF000000) >> 24;
		k[4] = (output & 0x000000FF00000000) >> 32;
		k[5] = (output & 0x0000FF0000000000) >> 40;
		k[6] = (output & 0x00FF000000000000) >> 48;
		k[7] = (output & 0xFF00000000000000) >> 56;
		for (c = (b * 8); c < ((b *8) + 8); c++) {
                    block[c] = block[c] ^ k[c & 0x07];
		}
            }
            if ((d == (blocks - 1)) && extra != 0) {
                bsize = extra;
            }
            fwrite(block, 1, bsize, outfile);
        }
    }
    fclose(infile);
    fclose(outfile);
    return 0;
}
