//========= Copyright © 1996-2005, Valve Corporation, All rights reserved. ============//
//
// Purpose: Standalone utility to encrypt files with ice encryption, that doesn't
//			 depend on Steam.
//
// Author: Valve Software and Scott Loyd (scottloyd@gmail.com).
//			Tested and proofread by Me2.
// Depends on: Just needs public/IceKey.cpp to be compiled/linked with it
// $NoKeywords: $
//
//=============================================================================//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include "osdir.h"
#include "IceKey.H"

// Globals
static bool g_Encrypt = true; //By default we encrypt

#define MAX_ICE_KEY 8
#define MAX_EXTENSION 16
static char g_ICEKey[MAX_ICE_KEY];
static char g_Extension[MAX_EXTENSION];

#ifdef WIN32
#define STRING_CMP stricmp
#else
#define STRING_CMP strcasecmp
#undef NULL
#define NULL 0
#endif

bool DEncrypt(const char* filename);

//----- Helpers -----
void Usage( void )
{
	printf( "Usage: ice <-d> <-x ext> [-k IceKey(8 byte)] [file]\n" );
	printf( "Default action: Encrypt. \n" );
	printf( "-d : Decrypt a file. \n" );
	printf( "-x : Extension to use as output. \n" );
	printf( "-k : You need to specify your 8 byte Ice Encryption Key. \n" );
	printf( "-h : Print the help menu, and stop.\n" );
}

void Exit(const char *msg)
{
	fprintf( stderr, msg );
	exit( 1 );
}

void SetExtension(char *dest, size_t length, const char *ext)
{
	//Start at the end till we hit a .
	//if we reach 0 without a .  just append the extension; one must not have existed.
	size_t mover = length;

	while( (*(dest + mover) != '.') && (mover > 0))
		mover--;

	if(mover == 0)
		strcat(dest,ext);
	else
	{
		strcpy(dest + mover,ext);
	}
}

/*
The entry point, see usage for I/O
*/
int main(int argc, char* argv[])
{
	if(argc < 2)
	{
		Usage();
		exit( 0 );
	}
	
	//By default we output .ctx
	strncpy( g_Extension, ".ctx",MAX_EXTENSION );
	memset(g_ICEKey,0,MAX_ICE_KEY);

	int i = 1;
	while( i < argc )
	{
		if( STRING_CMP( argv[i], "-h" ) == 0 )
		{
			Usage();
			exit( 0 );
		} 
		else if( STRING_CMP( argv[i], "-d" ) == 0 )
		{
			g_Encrypt = false;
		} 
		else if( STRING_CMP( argv[i], "-x" ) == 0 )
		{
			//Extension
			i++;

			if ( strlen( argv[i] ) > MAX_EXTENSION )
			{
				Exit("Your Extension is too big.\n");
			}

			strncpy( g_Extension, argv[i], MAX_EXTENSION );
		}
		else if( STRING_CMP( argv[i], "-k" ) == 0 )
		{
			//Key
			i++;

			if ( strlen( argv[i] ) != MAX_ICE_KEY )
			{
				Exit("Your ICE key needs to be 8 characters long.\n");
			}

			strncpy( g_ICEKey, argv[i], MAX_ICE_KEY );
		}
		else 
		{
			break;
		}
		i++;
	}

	if(g_ICEKey[0] == '\0') {
		Exit("You need to specify a key.\n");
	}
	//Parse files starting from current arg position
	if(argv[i] == NULL && (strlen(argv[i]) < 1))
		Exit("Was not about to find a file to parse\n");


	//Directory enumeration by Red Comet
	//Thanks Google and bvh for directory class
	if( strstr(argv[i],"*") != NULL ){
		oslink::directory dir("."); //Create list of files inside current directory
		char* pch = strstr(argv[i],"."); //Get pointer to the '.' in the file extension we want
		char sExt[5] = "";

		strncpy(sExt,pch,4);
				
		while (dir){
			
			//Check each file to see if it matches wildcard
			std::string nFile;
			nFile = dir.next();
			
			if( strstr(nFile.c_str(),sExt) != NULL ){
				
				if(DEncrypt(nFile.c_str()))
					std::cout << "Handled file: " << nFile << " successfully." << std::endl;
			}

		}
	}else{
		if(DEncrypt(argv[i]))
			std::cout << "Handled file: " << argv[i] << " successfully." << std::endl;
	}
	//End Red Comet code
}


bool DEncrypt(const char* filename)
{
		//Open allocate/read a file into memory
	FILE *pFile;
	pFile = fopen (filename, "rb");
	if(! pFile)
		Exit("Failed to open input file\n");

	long lFileSize; //Size of input file
	unsigned char *pBuff; //Holds the input file contents
	unsigned char *pOutBuff; //Holds the output goodies

	// obtain file size.
	fseek (pFile , 0 , SEEK_END);
	lFileSize= ftell (pFile);
	rewind (pFile);

	// allocate memory to contain the whole file.
	pBuff = (unsigned char*) malloc (lFileSize);
	pOutBuff = (unsigned char*) malloc (lFileSize);

	if (pBuff == NULL || pOutBuff == NULL)
	{
		fclose(pFile);
		std::cout << "Could not allocate buffer" << std::endl;
                return false;
	}

	// copy the file into the buffer.
	fread (pBuff,1,lFileSize,pFile);
	
	//clean the output buffer
	memset(pOutBuff,NULL,lFileSize);

	fclose(pFile);

	//Lets start the ice goodies!
	IceKey ice( 0 ); // level 0 = 64bit key
	ice.set( (unsigned char*) g_ICEKey ); // set key

	int blockSize = ice.blockSize();

	unsigned char *p1 = pBuff;
	unsigned char *p2 = pOutBuff;

	// encrypt data in 8 byte blocks
	int bytesLeft = lFileSize;

	while ( bytesLeft >= blockSize )
	{
		if ( g_Encrypt )
			ice.encrypt( p1, p2 );
		else
			ice.decrypt( p1, p2 );

		bytesLeft -= blockSize;
		p1+=blockSize;
		p2+=blockSize;
	}

	//The end chunk doesn't get an encryption?  that sux...
	memcpy( p2, p1, bytesLeft );

	size_t outLength = strlen(filename) + MAX_EXTENSION + 1;
	char *pOutPath = (char *)malloc(outLength);
	strncpy(pOutPath,filename,outLength);

	SetExtension(pOutPath, outLength, g_Extension);

	pFile = fopen (pOutPath , "wb");
	if(pFile == NULL)
	{
		fprintf( stderr, "Was not able to open output file for writing.\n" );
		free(pBuff);
		free(pOutBuff);
		free(pOutPath);
		return false;
	}

	fwrite (pOutBuff , 1 , lFileSize , pFile);
	fclose (pFile);

	free(pBuff);
	free(pOutBuff);
	free(pOutPath);

	return true;
}
