#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "md5.h"
const int PASS_LEN = 20;        
const int HASH_LEN = 33;        
char * tryWord(char * plaintext, char * hashFilename)
{
    (void)hashFilename;
    if (plaintext == NULL) return NULL;
    char *hex = md5(plaintext, (int)strlen(plaintext));
    if (hex == NULL) return NULL;
    char *out = strdup(hex);
    if (out == NULL) return NULL;
    for (char *p = out; *p; ++p) *p = (char)tolower((unsigned char)*p);
    return out;
}
int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }
    const char *hashFile = argv[1];
    const char *dictFile = argv[2];
    FILE *hf = fopen(hashFile, "r");
    if (!hf) { perror("opening hash file"); exit(2); }
    char **hashes = NULL;
    size_t hashes_sz = 0, hashes_cap = 0;
    char line[256];
    while (fgets(line, sizeof line, hf)) 
    {
        size_t L = strlen(line);
        while (L > 0 && (line[L-1] == '\n' || line[L-1] == '\r')) { line[--L] = '\0'; }
        if (L == 0) continue;
        if (L != 32) continue;
        if (hashes_sz == hashes_cap) 
        {
            size_t nc = hashes_cap ? hashes_cap * 2 : 16;
            char **tmp = realloc(hashes, nc * sizeof(char*));
            if (!tmp) { perror("realloc"); fclose(hf); exit(3); }
            hashes = tmp; hashes_cap = nc;
        }
        hashes[hashes_sz++] = strdup(line);
    }
    fclose(hf);
    if (hashes_sz == 0) 
    {
        fprintf(stderr, "No hashes from %s\n", hashFile);
        free(hashes);
        return 0;
    }
    int *found_flags = calloc(hashes_sz, sizeof *found_flags);
    if (!found_flags) { perror("calloc"); for (size_t i=0;i<hashes_sz;++i) free(hashes[i]); free(hashes); exit(4); 
    }
    FILE *df = fopen(dictFile, "r");
    if (!df) { perror("opening dictionary"); for (size_t i=0;i<hashes_sz;++i) free(hashes[i]); free(hashes); free(found_flags); exit(5); 
    }
    char word[512];
    size_t cracked = 0;
    while (fgets(word, sizeof word, df)) 
    {
        size_t wl = strlen(word);
        while (wl > 0 && (word[wl-1] == '\n' || word[wl-1] == '\r')) { word[--wl] = '\0'; }
        if (wl == 0) continue;
        char *cand = tryWord(word, (char *)hashFile);
        if (!cand) continue;
        for (size_t i = 0; i < hashes_sz; ++i) {
            if (found_flags[i]) continue;
            if (strcmp(cand, hashes[i]) == 0) {
                printf("%s %s\n", hashes[i], word);
                found_flags[i] = 1;
                cracked++;
            }
        }
        free(cand);
        if (cracked == hashes_sz) break;
    }
    fclose(df);
    printf("%zu hashes cracked!\n", cracked);
    for (size_t i = 0; i < hashes_sz; ++i) free(hashes[i]);
    free(hashes);
    free(found_flags);
}