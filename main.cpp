/*
 * hrepsh - 
 * Copyright (C) 2013  Guy Rutenberg
 * http://www.guyrutenberg.com
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <error.h>

#include <boost/format.hpp>

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "cryptopp/filters.h"
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::HashFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "cryptopp/hmac.h"
using CryptoPP::HMAC;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

using namespace std;

/**
 * Get the path to the executable of the parent process.
 */
string get_parent_process_path()
{
	pid_t ppid = getppid();
	boost::format proc_path("/proc/%d/exe");
	char *path = realpath(boost::str(proc_path % ppid).c_str(), NULL);
	if (!path) {
		error(1, errno, NULL);
	}
	string  parent_path(path);
	free(path);
	return parent_path;
}

string get_key()
{
	// the following shall be replaced by a real secret key...
	string secret_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	uid_t user = getuid();
	string salt = ((boost::format("%d") % user).str() + 
		string("\x00", 1) + 
		get_parent_process_path());
	string final_key;

	try {
		HMAC< SHA256 > hmac((const byte*)secret_key.data(), secret_key.size());

		StringSource(salt, true, 
				new HashFilter(hmac,
					new StringSink(final_key)
					) // HashFilter      
			    ); // StringSource
	} catch(const CryptoPP::Exception& e) {
		cerr << e.what() << endl;
		exit(1);
	}

	return final_key;
}


int main(int argc, char **argv)
{
	cout << "Hello world" << endl;
	cout << get_parent_process_path() << endl;

	AutoSeededRandomPool prng;
	byte iv[ AES::BLOCKSIZE ];
	prng.GenerateBlock( iv, sizeof(iv) );    

	string plain = "Test Vector";
	string cipher;

	GCM<AES>::Encryption e;
	string key = get_key();
	e.SetKeyWithIV((const byte*)key.data(), key.size(), iv, sizeof(iv));

	string encoded;
	encoded.clear();
	StringSource(key, true,
			new HexEncoder(
				new StringSink(encoded)
				) // HexEncoder
		    ); // StringSource

	cout << "key: " << encoded << endl;

	StringSource( plain, true,
		new AuthenticatedEncryptionFilter( e,
			new StringSink( cipher )
			) // AuthenticatedEncryptionFilter
		); // StringSource
	cout << "plain len: " << plain.size() << endl;
	cout << "cipher len: " << cipher.size() << endl;
	
	string rpdata;
	try {
		GCM< AES >::Decryption d;
			d.SetKeyWithIV( (const byte*)key.data(), key.size(), iv, sizeof(iv) );
			// d.SpecifyDataLengths( 0, cipher.size()-TAG_SIZE, 0 );
			
			AuthenticatedDecryptionFilter df( d,
					new StringSink( rpdata ),
					AuthenticatedDecryptionFilter::DEFAULT_FLAGS
					); // AuthenticatedDecryptionFilter
		
			// The StringSource dtor will be called immediately
			//  after construction below. This will cause the
			//  destruction of objects it owns. To stop the
			//  behavior so we can get the decoding result from
			//  the DecryptionFilter, we must use a redirector
			//  or manually Put(...) into the filter without
			//  using a StringSource.
			StringSource( cipher, true,
					new Redirector( df /*, PASS_EVERYTHING */ )
				    ); // StringSource
		
			// If the object does not throw, here's the only
			//  opportunity to check the data's integrity
			bool b = df.GetLastResult();
			assert( true == b );
			
			cout << "recovered text: " << rpdata << endl;
	} catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e ) {
		cerr << "Caught HashVerificationFailed..." << endl;
			cerr << e.what() << endl;
			cerr << endl;
	} catch( CryptoPP::InvalidArgument& e ) {
		cerr << "Caught InvalidArgument..." << endl;
			cerr << e.what() << endl;
			cerr << endl;
	} catch( CryptoPP::Exception& e ) {
		cerr << "Caught Exception..." << endl;
			cerr << e.what() << endl;
			cerr << endl;
	}
	

	return 0;
}
