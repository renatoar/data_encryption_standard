// Data Encription Standard Algorithm
// Disciplina: Introducao a Criptografia
// Renato Araujo Rizzo - 587788
// Renato Candido Kurosaki - 587834

#include <stdio.h>
#include <string.h>

// ============ Estrutura das chaves 28 bits =================
// Obs.: Uso de bitfield para simular chaves (variaveis) tamanhos especificos

typedef struct _key {
  unsigned int c : 28;
  unsigned int d : 28;
} key;

// ===========================================================
// ============== Functions declarations =====================
// ===========================================================

void permutacaoGenerica (unsigned char entrada[], unsigned char saida[], unsigned int tam, unsigned int matriz[][8]);
void imprimeHexadecimal (unsigned char vetorChar[],unsigned  int tam);
void divideTexto (unsigned char texto[], unsigned char left[], unsigned char right[]);
key divideChave (unsigned char chavePosPC1[]);
key leftShiftCircular (key keyBit, unsigned int i);
void juntaChaveCiDi (key roundKey, unsigned char key56bits[]);
void juntaTextoLeftRight (unsigned char texto[], unsigned char left[], unsigned char right[]);
void limpaBits (unsigned char vetorChar[], unsigned int tam);
unsigned int sBoxEncoding(unsigned char indice, unsigned int sbox[][16]);
void converteIntParaChar (unsigned int sboxInt, unsigned char sboxKey[], unsigned int tam);

// ===========================================================
// ======================= Main ==============================
// ===========================================================

int main(){
    // MATRIZ IP
    static unsigned int ip[8][8] = {
    {58, 50, 42, 34, 26, 18, 10, 2},
    {60, 52, 44, 36, 28, 20, 12, 4},
    {62, 54, 46, 38, 30, 22, 14, 6},
    {64, 56, 48, 40, 32, 24, 16, 8},
    {57, 49, 41, 33, 25, 17,  9, 1},
    {59, 51, 43, 35, 27, 19, 11, 3},
    {61, 53, 45, 37, 29, 21, 13, 5},
    {63, 55, 47, 39, 31, 23, 15, 7}};
    // MATRIZ IP INVERSA
    static unsigned int ipI[8][8] = {
    {40, 8, 48, 16, 56, 24, 64, 32},
    {39, 7, 47, 15, 55, 23, 63, 31},
    {38, 6, 46, 14, 54, 22, 62, 30},
    {37, 5, 45, 13, 53, 21, 61, 29},
    {36, 4, 44, 12, 52, 20, 60, 28},
    {35, 3, 43, 11, 51, 19, 59, 27},
    {34, 2, 42, 10, 50, 18, 58, 26},
    {33, 1, 41, 9, 49, 17, 57, 25}};
    // MATRIZ EXPANSAO E
    static unsigned int e[6][8] = {
    {32, 1, 2, 3, 4, 5, 4, 5},
    {6, 7, 8, 9, 8, 9, 10, 11},
    {12, 13, 12, 13, 14, 15, 16, 17},
    {16, 17, 18, 19, 20, 21, 20, 21},
    {22, 23, 24, 25, 24, 25, 26, 27},
    {28, 29, 28, 29, 30, 31, 32, 1}};
    // MATRIZ PERMUTED CHOICE 1 PC1
    static unsigned int pc1[7][8] = {
    {57, 49, 41, 33, 25, 17,  9, 1},
    {58, 50, 42, 34, 26, 18, 10, 2},
    {59, 51, 43, 35, 27, 19, 11, 3},
    {60, 52, 44, 36, 63, 55, 47, 39},
    {31, 23, 15, 7, 62, 54, 46, 38},
    {30, 22, 14, 6, 61, 53, 45, 37},
    {29, 21, 13,  5, 28, 20, 12, 4}};
    // MATRIZ PERMUTED CHOICE 2 PC2
    static unsigned int pc2[6][8] = {
    {14, 17, 11, 24,  1,  5, 3, 28},
    {15, 6, 21, 10, 23, 19, 12,  4},
    {26,  8, 16,  7, 27, 20, 13, 2},
    {41, 52, 31, 37, 47, 55, 30, 40},
    {51, 45, 33, 48, 44, 49, 39, 56},
    {34, 53, 46, 42, 50, 36, 29, 32}};
    // MATRIZ PERMUTACAO P
    static unsigned int p[4][8] = {
    {16, 7, 20, 21, 29, 12, 28, 17},
    {1, 15, 23, 26, 5, 18, 31, 10},
    {2, 8, 24, 14, 32, 27, 3, 9},
    {19, 13, 30, 6, 22, 11, 4, 25}};
    // S-BOX 1
    static unsigned int s1[4][16] = {
    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
    {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
    {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
    {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}};
    // S-BOX 2
    static unsigned int s2[4][16] = {
    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
    {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
    {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
    {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}};
    // S-BOX 3
    static unsigned int s3[4][16] = {
    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
    {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
    {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
    {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}};
    // S-BOX 4
    static unsigned int s4[4][16] = {
    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
    {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
    {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
    {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}};
    // S-BOX 5
    static unsigned int s5[4][16] = {
    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
    {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
    {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
    {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}};
    // S-BOX 6
    static unsigned int s6[4][16] = {
    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
    {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
    {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
    {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}};
    // S-BOX 7
    static unsigned int s7[4][16] = {
    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
    {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
    {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
    {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}};
    // S-BOX 8
    static unsigned int s8[4][16] = {
    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
    {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
    {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
    {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

    key keyBit;
    unsigned int hex_input[8], i = 0, k = 0, rodada = 0, sboxInt = 0;
    unsigned char chavePosPC1[7] = {'\0', '\0', '\0', '\0', '\0', '\0', '\0'};
    unsigned char plaintext[8] = {'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0'};
    unsigned char plaintext_permutado[8] = {'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0'};
    unsigned char cyphertext[8] = {'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0'};
    unsigned char swapFinal[8] = {'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0'};
    unsigned char chave[8] = {'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0'};
    unsigned char chave56bits[7] = {'\0', '\0', '\0', '\0', '\0', '\0', '\0'};
    unsigned char left[4] = {'\0', '\0', '\0', '\0'};
    unsigned char right[4] = {'\0', '\0', '\0', '\0'};
    unsigned char novoLeft[4] = {'\0', '\0', '\0', '\0'};
    unsigned char right_expandido[6] = {'\0', '\0', '\0', '\0', '\0', '\0'};
    unsigned char subchave[6] = {'\0', '\0', '\0', '\0', '\0', '\0'};
    unsigned char textoXORchave48bits[6] = {'\0', '\0', '\0', '\0', '\0', '\0'};
    unsigned char sboxKey[4] = {'\0', '\0', '\0', '\0'};
    unsigned char saidaP[4] = {'\0', '\0', '\0', '\0'};
    unsigned char aux = 0;
    unsigned long long int char48ToInt = 0, bit64 = 0;


    // LEITURA DO TEXTO PLANO
    printf("PLAIN TEXT\n");
    for(i = 0; i < 8; i++) {
        scanf("%X", &hex_input[i]);
        plaintext[i] = (unsigned char) hex_input[i];
    }

    // Permutação inicial do plaintext IP
    printf("\nIP\n");
    limpaBits(plaintext_permutado, sizeof (plaintext_permutado));
    permutacaoGenerica(plaintext, plaintext_permutado, (sizeof(ip)/sizeof(ip[0])), ip);
    imprimeHexadecimal(plaintext_permutado, sizeof (plaintext_permutado));

    // Divide o plaintext permutado em 2 partes 32bits cada
    divideTexto(plaintext_permutado, left, right);


    // LEITURA DA CHAVE
    printf("\nCHAVE\n");
    for(i = 0; i < 8; i++) {
        scanf("%X", &hex_input[i]);
        chave[i] = (unsigned char) hex_input[i];
    }

    // Primeira permutacao da chave
    limpaBits(chavePosPC1, sizeof (chavePosPC1));
    permutacaoGenerica(chave, chavePosPC1, (sizeof(pc1)/sizeof(pc1[0])), pc1);
    printf("\nPC1 - SELECIONA CHAVE\n");
    imprimeHexadecimal(chavePosPC1, sizeof (chavePosPC1));

    // Divisao da chave em duas parte 28 bits cada
    keyBit = divideChave(chavePosPC1);


    // ================================ Inicio das rodadas =================================

    for (rodada = 0; rodada < 16; rodada++) {

        // Gera chave da rodada e imprime (saida da permuted choice 2)
        keyBit = leftShiftCircular(keyBit, rodada);
        juntaChaveCiDi(keyBit, chave56bits);
        limpaBits(subchave, sizeof (subchave));
        permutacaoGenerica(chave56bits, subchave, (sizeof(pc2)/sizeof(pc2[0])), pc2);
        printf("\nCHAVE DE ROUND %d\n", rodada+1);
        printf("Deslocamento: ");
        imprimeHexadecimal(chave56bits, sizeof (chave56bits));
        printf("PC2: ");
        imprimeHexadecimal(subchave, sizeof (subchave));
        imprimeHexadecimal(subchave, sizeof (subchave));

        // Manipulacoes com texto (Funcao F) e imprime Round
        printf("\nROUND %d\n", rodada+1);
        imprimeHexadecimal(plaintext_permutado, sizeof (plaintext_permutado));

        // Copia metade direita do texto para ser usado na proxima rodada como lado esquerdo
        for(k = 0; k < 4; k++) novoLeft[k] = right[k];

        // Expande parte direita do texto com matriz E
        limpaBits(right_expandido, sizeof (right_expandido));
        permutacaoGenerica(right, right_expandido, (sizeof(e)/sizeof(e[0])), e);
        printf("Expansao: ");
        imprimeHexadecimal(right_expandido, sizeof (right_expandido));

        // XOR da chave permutada com texto expandido (Funcao F)
        for (i = 0; i < 6; i++) textoXORchave48bits[i] = right_expandido[i] ^ subchave[i];
        printf("Add Key: ");
        imprimeHexadecimal(textoXORchave48bits, sizeof (textoXORchave48bits));

        // S-BOX encoding.
        // Primeiro converte vetor de char para inteiro para manipular 6bits inves de 8bits
        char48ToInt = 0;
        sboxInt = 0;
        for (i = 0; i < 6; i++){
            bit64 = textoXORchave48bits[i];
            char48ToInt = char48ToInt | bit64;
            if(i != 5) char48ToInt = char48ToInt << 8;
        }
        aux = (char48ToInt >> 42) & 63;
        aux = (unsigned char) sBoxEncoding(aux, s1);
        sboxInt = sboxInt | aux;
        sboxInt = (sboxInt << 4);

        aux = (char48ToInt >> 36) & 63;
        aux = (unsigned char) sBoxEncoding(aux, s2);
        sboxInt = sboxInt | aux;
        sboxInt = (sboxInt << 4);

        aux = (char48ToInt >> 30) & 63;
        aux = (unsigned char) sBoxEncoding(aux, s3);
        sboxInt = sboxInt | aux;
        sboxInt = (sboxInt << 4);

        aux = (char48ToInt >> 24) & 63;
        aux = (unsigned char) sBoxEncoding(aux, s4);
        sboxInt = sboxInt | aux;
        sboxInt = (sboxInt << 4);

        aux = (char48ToInt >> 18) & 63;
        aux = (unsigned char) sBoxEncoding(aux, s5);
        sboxInt = sboxInt | aux;
        sboxInt = (sboxInt << 4);

        aux = (char48ToInt >> 12) & 63;
        aux = (unsigned char) sBoxEncoding(aux, s6);
        sboxInt = sboxInt | aux;
        sboxInt = (sboxInt << 4);

        aux = (char48ToInt >> 6) & 63;
        aux = (unsigned char) sBoxEncoding(aux, s7);
        sboxInt = sboxInt | aux;
        sboxInt = (sboxInt << 4);

        aux = (char48ToInt >> 0) & 63;
        aux = (unsigned char) sBoxEncoding(aux, s8);
        sboxInt = sboxInt | aux;

        // Converte a saida das S-BOX de inteiro para char
        converteIntParaChar(sboxInt, sboxKey, sizeof (sboxKey));

        // Imprime saida da S-BOX
        printf("S-Box: ");
        imprimeHexadecimal(sboxKey, sizeof (sboxKey));

        // Permuta a saida da S-BOX com a matriz P
        limpaBits(saidaP, sizeof (saidaP));
        permutacaoGenerica(sboxKey, saidaP, (sizeof(p)/sizeof(p[0])), p);
        printf("Permuta: ");
        imprimeHexadecimal(saidaP, sizeof (saidaP));

        // XOR entre a saida da Funcao F(saidaP) e a parte esquerda do texto e imprime.
        for (k = 0; k < 4; k++) right[k] = left[k] ^ saidaP[k];
        printf("Add Left: ");
        imprimeHexadecimal(right, sizeof (right));

        // Novo L usado como L na proxima rodada
        for (k = 0; k < 4; k++) left[k] = novoLeft[k];

        // Imprime o texto resultante do final da rodada
        juntaTextoLeftRight(plaintext_permutado, novoLeft, right);
        imprimeHexadecimal(plaintext_permutado, sizeof (plaintext_permutado));

    }

    // Swap final
    printf("\nSwap: ");
    juntaTextoLeftRight(swapFinal, right, novoLeft);
    imprimeHexadecimal(swapFinal, sizeof (swapFinal));

    // Permutacao inversa
    limpaBits(cyphertext, sizeof (cyphertext));
    permutacaoGenerica(swapFinal, cyphertext, (sizeof(ipI)/sizeof(ipI[0])), ipI);
    printf("\nIP Inverso: ");
    imprimeHexadecimal(cyphertext, sizeof (cyphertext));

    return 0;
}


// ===========================================================
// ============= Functions implementations ===================
// ===========================================================

// Realiza permutacao usando matriz e a entrada para gerar a saida. Aceita qualquer permutacao
void permutacaoGenerica (unsigned char entrada[], unsigned char saida[], unsigned int tam, unsigned int matriz[][8]){
    // i:linha j:coluna bitIndice:bit dentro do indice da entrada 0 a 7
    // indice:indice do vetor de entrada
    unsigned int i, j, bitIndice, resultado, indice, aux;

    for(i = 0; i < tam; i++){
        bitIndice = 7;
        for(j = 0; j < 8; j++){
            indice = (matriz[i][j] / 8);
            if ((matriz[i][j] % 8) == 0) indice--;
            resultado = ((indice+1) * 8);
            resultado = resultado - matriz[i][j];
            aux = entrada[indice] & (1 << (resultado));
            aux = aux >> (resultado);
            saida[i] = (unsigned char) (saida[i] | (aux << bitIndice));
            bitIndice--;
        }
    }
}

// Imprime qualquer vetor de char em hexadecimal
void imprimeHexadecimal(unsigned char vetorChar[], unsigned int tam){
    for(unsigned int i = 0; i < tam; i++) {
        printf("%.2X ", (unsigned char)vetorChar[i]);
    }
    printf("\n");
}

// Divide texto dado como entrada em duas parte de 32bits cada
void divideTexto (unsigned char texto[], unsigned char left[], unsigned char right[]){
    unsigned int i, j = 0;
    for(i = 0; i < 8; i++) {
        if(i < 4) {
            left[i] = texto[i];
        } else {
            right[j] = texto[i];
            j++;
        }
    }
}

// Divide chave dada como entrada em duas parte de 28bits cada e retorna
key divideChave(unsigned char chavePosPC1[]){
    key dividir;
    dividir.c = 0; dividir.d = 0;
    int i, j, bitIndice = 0;

    for (i = 0; i < 7; i++) {
        for (j = 7; j >= 0; j--){
            if (bitIndice < 28) {
                dividir.c = dividir.c | ((chavePosPC1[i] >> j) & 1);
                if (bitIndice != 27) dividir.c = (unsigned int) dividir.c << 1;
            } else {
                dividir.d = dividir.d | ((chavePosPC1[i] >> j) & 1);
                if (bitIndice != 55) dividir.d = (unsigned int) dividir.d << 1;
            }
            bitIndice++;
        }
    }
    return dividir;
}

// Realiza left shift circular nas chaves de 28bits
key leftShiftCircular(key keyBit, unsigned int i){

    if (i == 0 || i == 1 || i == 8 || i == 15){
        keyBit.c = (unsigned int) (keyBit.c << 1) | ( keyBit.c >> (28 - 1));
        keyBit.d = (unsigned int) (keyBit.d << 1) | ( keyBit.d >> (28 - 1));
    } else {
        keyBit.c = (unsigned int) (keyBit.c << 2) | ( keyBit.c >> (28 - 2));
        keyBit.d = (unsigned int) (keyBit.d << 2) | ( keyBit.d >> (28 - 2));
    }
    return keyBit;
}

// Usa as chaves divididas em duas partes de 28bits e gera uma de 56bits
void juntaChaveCiDi(key roundKey, unsigned char key56bits[]){
    unsigned int i;
    unsigned char charAux;

    for (i = 0; i < 7; i++) {
        if (i < 3) {
            key56bits[i] = (roundKey.c >> 20) & 255;
            roundKey.c = (unsigned int) roundKey.c << 8;
        } else {
            if (i == 3) {
                charAux = (roundKey.c >> 24) & 15;
                charAux = charAux << 4;
                charAux = charAux | ((roundKey.d >> 24) & 15);
                key56bits[i] = charAux;
                roundKey.d = (unsigned int) roundKey.d << 4;
            } else {
                key56bits[i] = (roundKey.d >> 20) & 255;
                roundKey.d = (unsigned int) roundKey.d << 8;
            }
        }
    }
    key56bits[i] = 0;
}

// Junta texto esquerdo 32bits com direito 32 bits
void juntaTextoLeftRight (unsigned char texto[], unsigned char left[], unsigned char right[]){
    int i = 0, j = 0;
    for (i = 0; i < 8; i++) {
        if (i < 4) {
            texto[i] = left[i];
        } else {
            texto[i] = right[j];
            j++;
        }
    }
}

// Limpa vetor de char
void limpaBits (unsigned char vetorChar[], unsigned int tam){
    for(unsigned int i = 0; i < tam; i++) vetorChar[i] = 0;
}

// Retorna 6 bits da sbox dado o indice dado como entrada
unsigned int sBoxEncoding (unsigned char indice, unsigned int sbox[][16]){
    unsigned int coluna = 0, linha = 0;

    coluna = (indice >> 1) & 15;
    linha = ((indice >> 5) & 1);
    linha = linha << 1;
    linha = linha | (indice & 1);

    return sbox[linha][coluna];
}

// Converte o inteiro entrada para o vetor de char saida
void converteIntParaChar (unsigned int entrada, unsigned char saida[], unsigned int tam){
    for (int i = (tam-1); i >= 0; i--) {
        saida[i] = entrada & 255;
        entrada = entrada >> 8;
    }
}
