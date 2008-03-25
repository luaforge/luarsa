/**
*  $Id: luarsa.c,v 1.1 2008-03-25 18:02:02 jasonsantos Exp $
*  RSA encrypt/decrypt bindings for Lua
*  @author  Luis Eduardo Jason Santos
*  based on code for md5 by Roberto Ierusalimschy 
*/


#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <lua.h>
#include <lauxlib.h>

#include <xyssl/sha1.h>
#include <xyssl/rsa.h>
#include <xyssl/havege.h>


#define KEY_SIZE 1024
#define EXPONENT 65537

int mpi_push_field(lua_State*L, const char *fieldname, mpi *X, int radix);

static int sha1_sum (lua_State *L);

static int rsa_genkey (lua_State *L);

static int luarsa_pkcs1_encrypt (lua_State *L);

static int luarsa_pkcs1_decrypt (lua_State *L);


void mpi_print(char* format, mpi *X) {
    char buffer[1024];
    int length = 1024;
    int res;
    memset(buffer, 0, 1024);
    printf(format, "");
    res = mpi_write_string(X, 16, buffer, &length);
    if(res==0)
        printf(format, buffer);
    printf(".");
}


int mpi_push_field(lua_State*L, const char *fieldname, mpi *X, int radix) {
	int res = 0;
	int slen = KEY_SIZE*2;
	
	char *buffer = (char*)malloc(slen);
	memset(buffer, 0, slen);
	
	res = mpi_write_string(X, radix, buffer, &slen);
	
	if(!res) {
		lua_pushstring(L, fieldname);
		lua_pushlstring(L, buffer, slen);
	    lua_settable(L, -3);
	}
	
    free(buffer);
    return res;
}

int mpi_get_field(lua_State*L, int index, const char *fieldname, mpi *X, int radix) {
	char *buff;
	int res = -1;

	if(lua_istable(L, index)) {
		lua_getfield(L, index, fieldname);
		
		buff = (char*)lua_tostring(L, -1);
		
		res = mpi_read_string(X, radix, buff);
	}
    return res;
}

int push_public_key(lua_State* L, rsa_context* Prsa) {
    int ret = 0;
    
    lua_newtable(L);
        
    if ( !Prsa || ( ret = mpi_push_field(L, "N", &Prsa->N, 16) ) != 0 ||
            ( ret = mpi_push_field(L, "E", &Prsa->E, 16) ) != 0 ) {
        lua_pop(L, 1);
    }
    
    return ret;
}

int to_public_key(lua_State* L, rsa_context* Prsa) {
    int ret = 0;
    int index;
    
    if ( !Prsa)
    	return -1;
    memset( Prsa, 0, sizeof( rsa_context ) );
    
    index = lua_gettop(L);
    
    ret = mpi_get_field(L, index, "N", &Prsa->N, 16);
    ret = mpi_get_field(L, index, "E", &Prsa->E, 16);
    mpi_init(&Prsa->D, NULL);
    mpi_init(&Prsa->P, NULL);
    mpi_init(&Prsa->Q, NULL);
    mpi_init(&Prsa->DP, NULL);
    mpi_init(&Prsa->DQ, NULL);
    mpi_init(&Prsa->QP, NULL);

    mpi_init(&Prsa->RN, NULL);
    mpi_init(&Prsa->RP, NULL);
    mpi_init(&Prsa->RQ, NULL);
    
    if((ret = rsa_check_pubkey(Prsa))!=0)
    	printf("Erro na chave publica (%d)", ret);

    return ret;
}

int push_private_key(lua_State* L, rsa_context* Prsa) {
    int ret = 0;
    
    lua_newtable(L);
    
    if ( !Prsa || 
        ( ret = mpi_push_field(L, "N" , &Prsa->N , 16 ) ) != 0 ||
        ( ret = mpi_push_field(L, "E" , &Prsa->E , 16 ) ) != 0 ||
        ( ret = mpi_push_field(L, "D" , &Prsa->D , 16 ) ) != 0 ||
        ( ret = mpi_push_field(L, "P" , &Prsa->P , 16 ) ) != 0 ||
        ( ret = mpi_push_field(L, "Q" , &Prsa->Q , 16 ) ) != 0 ||
        ( ret = mpi_push_field(L, "DP", &Prsa->DP, 16 ) ) != 0 ||
        ( ret = mpi_push_field(L, "DQ", &Prsa->DQ, 16 ) ) != 0 ||
        ( ret = mpi_push_field(L, "QP", &Prsa->QP, 16 ) ) != 0 ) {
             
        lua_pop(L, 1);
    }
    
    return ret;
}

int to_private_key(lua_State* L, rsa_context* Prsa) {
    int ret = 0;
    int index;
    
    if ( !Prsa)
    	return -1;
    memset( Prsa, 0, sizeof( rsa_context ) );
    
    index = lua_gettop(L);
    
	ret += mpi_get_field(L, index, "N" , &Prsa->N , 16 );
    ret += mpi_get_field(L, index, "E" , &Prsa->E , 16 );
    ret += mpi_get_field(L, index, "D" , &Prsa->D , 16 );
    ret += mpi_get_field(L, index, "P" , &Prsa->P , 16 );
    ret += mpi_get_field(L, index, "Q" , &Prsa->Q , 16 );
    ret += mpi_get_field(L, index, "DP", &Prsa->DP, 16 );
    ret += mpi_get_field(L, index, "DQ", &Prsa->DQ, 16 );
    ret += mpi_get_field(L, index, "QP", &Prsa->QP, 16 );
        
    if(ret = rsa_check_privkey(Prsa))
    	printf("Erro na chave privada (%d)", ret);
    
    return ret;
}

/**
*/
static int rsa_genkey (lua_State *L) {
    rsa_context rsa;
    havege_state hs;
    int ret=0;
    
    rsa_init( &rsa, RSA_PKCS_V15, 0, havege_rand, &hs );
    
    if( ( ret = rsa_gen_key( &rsa, KEY_SIZE, EXPONENT ) ) != 0 )
    {
        luaL_error(L, "Error generating key (%d)", ret);
    }
    
    /* Public Key */
    if(ret = push_public_key(L, &rsa))
    {
    	luaL_error(L, "failed to obtain public key: error %d", ret );
    }
    
    /* Private Key */
    if(ret = push_private_key(L, &rsa))
    {
    	luaL_error(L, "failed to obtain private key: error %d", ret );
    }
    
    rsa_free( &rsa );
    
    return 2;
}


static int sha1_sum (lua_State *L) {
    size_t lmsg;
    char *msg = (char*)luaL_checklstring(L, 1, &lmsg); /* message */
    
    sha1_context ctx;

    char result[20];
    
    sha1_starts(&ctx);
    sha1_update(&ctx, msg, lmsg);
    sha1_finish(&ctx, result);
    
    memset(&ctx, 0, sizeof(sha1_context));
    
    lua_pushstring(L, result); /* digest */

    return 1;
}


static int isPrivateKey(lua_State*L, int tableIndex) {
	int ret = 0;
    lua_getfield(L, tableIndex, "N");
    ret += lua_isstring(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, tableIndex, "E");
    ret += lua_isstring(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, tableIndex, "D");
    ret += lua_isstring(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, tableIndex, "P");
    ret += lua_isstring(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, tableIndex, "Q");
    ret += lua_isstring(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, tableIndex, "DP");
    ret += lua_isstring(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, tableIndex, "DQ");
    ret += lua_isstring(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, tableIndex, "QP");
    ret += lua_isstring(L, -1);
    lua_pop(L, 1);
    return (ret==8);
}

static int isPublicKey(lua_State*L, int tableIndex) {
	int ret = 0;
    lua_getfield(L, tableIndex, "N");
    ret += lua_isstring(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, tableIndex, "E");
    ret += lua_isstring(L, -1);
    lua_pop(L, 1);
    return (ret==2);
}


static int processKey(lua_State*L, int tableIndex, rsa_context* Prsa) {
	int mode;
	int res = -1;
    luaL_checktype(L, tableIndex, LUA_TTABLE); /* keytable */
    
    // check key mode
    printf("check key mode\n");
    if(isPrivateKey(L, tableIndex)){
    	// convert private key table to rsa_context
        printf("convert private key table to rsa_context\n");
        lua_pushvalue(L, tableIndex);
    	res = to_private_key(L, Prsa);
    	mode = RSA_PRIVATE;
    } else if(isPublicKey(L, tableIndex)) {
    	// convert public key table to rsa_context
        printf("convert public key table to rsa_context\n");
        lua_pushvalue(L, tableIndex);
    	res = to_public_key(L, Prsa);
    	mode = RSA_PUBLIC;
    } 
    
    printf("Ok\n");
    if(res!=0) {
    	luaL_error(L, "Invalid/Malformed Key (%d)", res);
    }
    printf("key processing is done\n");
    return mode;
}

/**
*  Adds padding and encrypts a string using either private or public key. 
* (depending on mode).
*  @param message: arbitrary binary string to be encrypted.
*  @param keytable: table containing either the public or the private key, as generated by gen_key.
*  @return  The cyphertext (as a binary string).
*  @see  rsa_genkey
*/
static int luarsa_pkcs1_encrypt (lua_State *L) {
	int res = 0;
	int mode;
    size_t lmsg, lresult;
    rsa_context rsa;
    char *message = (char*)luaL_checklstring(L, 1, &lmsg); /* message */
    char result[KEY_SIZE];
char alt_result[KEY_SIZE];
    char* strMode=NULL;
    if(lua_type(L, 3)==LUA_TSTRING) {
        printf("Got parameter\n");
        strMode = (char*)lua_tostring(L, 3);
        printf("[%s]\n", strMode);
        mode = strncmp(strMode, "private", 7) ? RSA_PUBLIC : RSA_PRIVATE;
    }
    
    rsa_init( &rsa, RSA_PKCS_V15, 0, NULL, NULL ); 
    
    processKey(L, 2, &rsa); /* keytable */
    
    rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;
    
    memset(result, 0, KEY_SIZE);
    
// <test> by Jason
    printf("\nMode==%s\n", mode==RSA_PUBLIC ? "RSA_PUBLIC" : "RSA_PRIVATE" );
    printf("Size==%d\n", lmsg );
    printf("Crypt.Size==%d\n", rsa.len );
    
    printf("ver: %d\n", rsa.ver);
    printf("len: %d\n", rsa.len);
    printf("padding: %d\n", rsa.padding);
    printf("hash_id: %d\n", rsa.hash_id);
    
    mpi_print("N:%s\n", &rsa.N);
    mpi_print("E:%s\n", &rsa.E);
    
    if(mode!=RSA_PUBLIC) {
        //mpi_print("D:%s\n", &rsa.D);
        //mpi_print("P:%s\n", &rsa.P);
        //mpi_print("Q:%s\n", &rsa.Q);
        //mpi_print("DP:%s\n", &rsa.DP);
        //mpi_print("DQ:%s\n", &rsa.DQ);
        //mpi_print("QP:%s\n", &rsa.QP);

        //mpi_print("RN:%s\n", &rsa.RN);
        //mpi_print("RP:%s\n", &rsa.RP);
        //mpi_print("RQ:%s\n", &rsa.RQ);
    }
// </test> by Jason

    // pass rsa context and message to encryption engine
    res = rsa_pkcs1_encrypt(&rsa, RSA_PUBLIC, lmsg, message, result);
    
    if(res)
    	luaL_error(L, "Error during cipher (%d)", res);
/*    
    lmsg = 128;
    res = rsa_pkcs1_decrypt(&rsa, mode, &lmsg, result, alt_result);
    
    if(res)
    	luaL_error(L, "Error during decipher (%d)", res);
    
    printf("(%d)", lmsg);
*/
    push_private_key(L, &rsa);
    
    // push encrypted result buffer
    lua_pushlstring(L, result, rsa.len); /* ciphertext */

    rsa_free( &rsa );
    
    return 1;
}


/**
*  Decrypts a string and removes the padding using either private or public key. 
* (depending on mode).
*  @param ciphertext: binary string to be decrypted.
*  @param key: table containing either the public or the private key, as generated by gen_key.
*  @return  The original message (if everything works ok).
*  @see  rsa_genkey
*/
static int luarsa_pkcs1_decrypt (lua_State *L) {
	int res = 0;
	int mode;
    size_t lmsg, lresult;
    rsa_context rsa;
    char *message = (char*)luaL_checklstring(L, 1, &lmsg); /* ciphertext */
    char result[KEY_SIZE];
    
    rsa_init( &rsa, RSA_PKCS_V15, 0, NULL, NULL ); 
    

    mode = processKey(L, 2, &rsa); /* keytable */
    
    rsa.len = lmsg;

    memset(result, 0, KEY_SIZE);
    printf("\nMode==%s\n", mode==RSA_PUBLIC ? "RSA_PUBLIC" : "RSA_PRIVATE" );
    printf("Size==%d\n", lmsg );
    printf("Crypt.Size==%d\n", rsa.len );
    
    printf("ver: %d\n", rsa.ver);
    printf("len: %d\n", rsa.len);
    printf("padding: %d\n", rsa.padding);
    printf("hash_id: %d\n", rsa.hash_id);
    
    mpi_print("N:%s\n", &rsa.N);
    mpi_print("E:%s\n", &rsa.E);
    
    if(mode!=RSA_PUBLIC) {
        mpi_print("D:%s\n", &rsa.D);
        mpi_print("P:%s\n", &rsa.P);
        mpi_print("Q:%s\n", &rsa.Q);
        mpi_print("DP:%s\n", &rsa.DP);
        mpi_print("DQ:%s\n", &rsa.DQ);
        mpi_print("QP:%s\n", &rsa.QP);

        //mpi_print("RN:%s\n", &rsa.RN);
        //mpi_print("RP:%s\n", &rsa.RP);
        //mpi_print("RQ:%s\n", &rsa.RQ);
    }
    
    // pass rsa context and ciphertext to decryption engine
    res = rsa_pkcs1_decrypt(&rsa, RSA_PRIVATE, &lmsg, message, result);
    printf("Orig.Size==%d\n", lmsg );
    
    if(res) {
    	luaL_error(L, "Error during cipher (%d)", res);
    }
    
    // push encrypted result buffer
    lua_pushlstring(L, result, lmsg); /* ciphertext */

    rsa_free( &rsa );
    
    return 1;
}


/*
** Assumes the table is on top of the stack.
*/
static void set_info (lua_State *L) {
	lua_pushliteral (L, "_COPYRIGHT");
	lua_pushliteral (L, "Copyright (C) 2003-2007 Kepler Project");
	lua_settable (L, -3);
	lua_pushliteral (L, "_DESCRIPTION");
	lua_pushliteral (L, "Public Key cryptographic facilities using RSA algorithm");
	lua_settable (L, -3);
	lua_pushliteral (L, "_VERSION");
	lua_pushliteral (L, "RSA 0.1.1");
	lua_settable (L, -3);
}


static struct luaL_reg rsalib[] = {
	{"genkey", rsa_genkey},
	{"sum", sha1_sum},
	{"crypt", luarsa_pkcs1_encrypt},
	{"decrypt", luarsa_pkcs1_decrypt},
	{NULL, NULL}
};


int luaopen_rsa_core (lua_State *L) {
  luaL_openlib(L, "rsa", rsalib, 0);
  set_info (L);
  return 1;
}

