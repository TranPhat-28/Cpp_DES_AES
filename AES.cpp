#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cerr;
using std::cout;
using std::cin;
using std::endl;
using std::wcin;
using std::wcout;

#include <fstream>

// Convert wstring to string;
#include <string>
#include <string.h>
using std::string;
using std::wstring;
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

using CryptoPP::byte;
#include <cstdlib>
using std::exit;

#include "include/cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "include/cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "include/cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "include/cryptopp/aes.h"
using CryptoPP::AES;

#include "include/cryptopp/modes.h"
using CryptoPP::ECB_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CBC_CTS_Mode;
using CryptoPP::CTR_Mode;

#include "include/cryptopp/xts.h"
using CryptoPP::XTS;

#include "include/cryptopp/ccm.h"
using CryptoPP::CCM;

#include "include/cryptopp/eax.h"
#include "include/cryptopp/filters.h"
using CryptoPP::EAX;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "include/cryptopp/gcm.h"
using CryptoPP::GCM;

#include "include/cryptopp/secblock.h"
using CryptoPP::SecByteBlock;
using CryptoPP::Redirector;

// Support Vietnamese
// Set _setmode()
#include <io.h>
#include <fcntl.h>

//--------------------------------------------------
//-----Include tất cả các thư viện------------------
//--------------------------------------------------

//Mảng lưu tên các Mode
string ModeList[] = {"ECB", "CBC", "OFB", "CFB", "CTR", "XTS", "CCM", "GCM"};

//--------------------------------------------------
//---------Khai báo hàm-----------------------------
//--------------------------------------------------
void Func_ECB(wstring wplain, SecByteBlock key);
void Func_CBC(wstring wplain, SecByteBlock key, byte* iv);
void Func_OFB(wstring wplain, SecByteBlock key, byte* iv);
void Func_CFB(wstring wplain, SecByteBlock key, byte* iv);
void Func_CTR(wstring wplain, SecByteBlock key, byte* iv);
void Func_XTS(wstring wplain, SecByteBlock key, byte* iv);
void Func_CCM(wstring wplain, SecByteBlock key, byte* iv);
void Func_GCM(wstring wplain, SecByteBlock key, byte* iv);
// Hàm in menu chọn Mode
void printMenu();
// Hàm chuyển đổi string
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);
wstring utf8_to_wstring (const std::string& str);
string wstring_to_utf8 (const std::wstring& str);



//--------------------------------------------------
//-------------Hàm main()---------------------------
//--------------------------------------------------
int main()
{
	// Support tiếng việt
 	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);

	
	// --------Lựa chọn MODE---------
	printMenu();
	int input_mode;
	do
	{
		wcin >> input_mode;
	} while (input_mode < 1 || input_mode > 8);
	system("cls");

	// Input plaintext dạng wstring
	wcout << "Input plaintext: ";
	wstring input;
	fflush(stdin);
	//wcin.ignore();
	getline(wcin, input);
	//wcin >> input;

	// --------------------------
	// -------Key và IV----------
	// --------------------------
	AutoSeededRandomPool prng;

	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	byte iv[ AES::BLOCKSIZE ];
	// Key 32 for XTS
	SecByteBlock key32(AES::DEFAULT_KEYLENGTH * 2);
	byte iv32[ AES::BLOCKSIZE * 2];

	// In các lựa chọn ra màn hình
	wcout << "Secret key and IV option: " << endl;
	wcout << "1. Random. " << endl;
	wcout << "2. Input from screen. " << endl;
	wcout << "3. Input from file. " << endl;
	// Người dùng input lựa chọn
	wcin.ignore();
	int input2;
	do
	{
		wcin >> input2;
	} while (input2 < 1 || input2 > 3);
	
	// Thực hiện lựa chọn của người dùng

	// Case 1: Random key và iv
	if (input2 == 1)
	{
		prng.GenerateBlock( key, key.size() );
		prng.GenerateBlock( iv, sizeof(iv) );
		prng.GenerateBlock( key32, key32.size() );
		prng.GenerateBlock( iv32, sizeof(iv32) );
	}
	// Case 2: Nhập key và iv từ màn hình
	else if (input2 == 2)
	{
		// Input KEY from terminal
		wstring skey1;
		wcout << "Please input key (16 bytes; 32 bytes for XTS): " << endl;
		
		wcin.ignore();
		wcin >> skey1;

		string skey = wstring_to_string(skey1);

		// Reading key from input screen
		StringSource ss1(skey, false);

		// Create byte array space for key
		CryptoPP::ArraySink copykey(key, sizeof(key));
		// Key32 for XTS
		CryptoPP::ArraySink copykey32(key32, sizeof(key32));

		// Copy data to key
		ss1.Detach(new Redirector(copykey));
		ss1.Pump(16);  // Pump first 16 bytes
		ss1.Detach(new Redirector(copykey32));
		ss1.Pump(32);  // Pump first 32 bytes for XTS

		// Input IV from terminal
		wstring siv1;
		wcout << "Please input IV (16 bytes): " << endl;
		
		wcin.ignore();
		wcin >> siv1;

		string siv = wstring_to_string(siv1);

		// Reading IV from input screen
		StringSource ss2(siv, false);

		// Create byte array space for IV
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));

		// Copy data to IV
		ss2.Detach(new Redirector(copyiv));
		ss2.Pump(16);  // Pump first 16 bytes
		
	}
	// Case 3: Input từ file
	else
	{
		wcout << "Input Key and IV from file [input.txt]: " << endl;
		string skey, siv;
		std::ifstream myfile ("input.txt");
		if (myfile.is_open())
		{
			getline (myfile, skey);
			// Reading key from input screen
			StringSource ss1(skey, false);

			// Create byte array space for key
			CryptoPP::ArraySink copykey(key, sizeof(key));
			// Key32 for XTS
			CryptoPP::ArraySink copykey32(key, sizeof(key32));

			// Copy data to key
			ss1.Detach(new Redirector(copykey));
			ss1.Pump(16);  // Pump first 16 bytes
			ss1.Detach(new Redirector(copykey32));
			ss1.Pump(32);  // Pump first 32 bytes

			getline (myfile, siv);
			// Reading iv from input screen
			StringSource ss2(siv, false);

			// Create byte array space for iv
			CryptoPP::ArraySink copyIV(iv, sizeof(iv));

			// Copy data to iv
			ss2.Detach(new Redirector(copyIV));
			ss2.Pump(16);  // Pump first 16 bytes
			myfile.close();
		}
		else cout << "Unable to open file"; 
	}
	
	// Gọi hàm theo input
	switch (input_mode)
	{
	case 1:
		wcout << "ECB Mode - IV is not needed: " << endl;
		Func_ECB(input, key);
		break;
	case 2:
		wcout << "CBC Mode: " << endl;
		Func_CBC(input, key, iv);
		break;
	case 3:
		wcout << "OFB Mode: " << endl;
		Func_OFB(input, key, iv);
		break;
	case 4:
		wcout << "CFB Mode: " << endl;
		Func_CFB(input, key, iv);
		break;
	case 5:
		wcout << "CTR Mode: " << endl;
		Func_CTR(input, key, iv);
		break;
	case 6:
		wcout << "XTS Mode - Plaintext at least 16 bytes: " << endl;
		Func_XTS(input, key32, iv32);
		break;
	case 7:
		wcout << "CCM Mode: " << endl;
		Func_CCM(input, key, iv);
		break;				
	case 8:
		wcout << "GCM Mode: " << endl;
		Func_GCM(input, key, iv);
		break;
	}
}
//................................
//........Định nghĩa hàm..........
//................................

//ECB không dùng IV
//ECB có yêu cầu Padding
void Func_ECB(wstring wplain, SecByteBlock key)
{
	// Chuyển chuỗi plaintext về utf8
	string plain;
	plain = wstring_to_utf8(wplain);     
	string cipher, encoded, recovered;

	// In Key ra màn hình
	encoded.clear();
	StringSource(key, 16, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder 
	); // StringSource

	// Chuyển string encoded sang wstring wencoded_key
	wstring wencoded_key(encoded.begin(), encoded.end()); 
	wcout << L"Key: " << wencoded_key << endl;

	// Biến đo performance
	int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;

	wcout << "Plain text: " << wplain <<endl;

//---------MÃ HOÁ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			cipher = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			ECB_Mode< AES >::Encryption e;
			e.SetKey(key, 16);

			// The StreamTransformationFilter adds padding
			//  as required. ECB and CBC Mode must be padded
			//  to the block size of the cipher.
			StringSource(plain, true, 
				new StreamTransformationFilter(e,
					new StringSink(cipher)
				) // StreamTransformationFilter      
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	// Chuyển string encoded sang wstring wencoded_cipher
	wstring wencoded_cipher(encoded.begin(), encoded.end()); 
	wcout << L"Cipher text: " << wencoded_cipher << endl; 
	// Xuất thời gian mã hóa đo được
	wcout << L"Encyption excution time: " << exec_time / 10000 << " ms" << endl;

	// Reset biến đo performance
	exec_time = 0;

//---------GIẢI MÃ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			recovered = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			ECB_Mode< AES >::Decryption d;
			d.SetKey(key, 16);

			// The StreamTransformationFilter removes
			//  padding as required.
			StringSource s(cipher, true, 
				new StreamTransformationFilter(d,
					new StringSink(recovered)
				) // StreamTransformationFilter
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}

		// Chuyển chuỗi utf8-recovered thành wstring-recov
		wstring recov = utf8_to_wstring(recovered);
		// In ra màn hình
		wcout<< L"Recovered text: "<< recov<<endl;
		// In thời gian giải mã đo được
		wcout << L"Decyption excution time: " << exec_time / 10000 << " ms" << endl;
	}
	//Báo lỗi
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}


//CBC có dùng IV
//CBC có yêu cầu Padding
void Func_CBC(wstring wplain, SecByteBlock key, byte* iv)
{
	// Chuyển chuỗi plaintext về utf8
	string plain;
	plain = wstring_to_utf8(wplain);     
	string cipher, encoded, recovered;

	// In Key ra màn hình
	encoded.clear();
	StringSource(key, 16, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder 
	); // StringSource

	// Chuyển string encoded sang wstring wencoded_key
	wstring wencoded_key(encoded.begin(), encoded.end()); 
	wcout << L"Key: " << wencoded_key << endl;

	// In iv ra màn hình
	encoded.clear();
	StringSource(iv, 16, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource

	// Chuyển string encoded sang wstring wencoded_iv
    wstring wencoded_iv(encoded.begin(), encoded.end()); 
	wcout << L"IV: " << wencoded_iv << endl;

	// Biến đo performance
	int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;

	wcout << "Plain text: " << wplain <<endl;

//---------MÃ HOÁ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			cipher = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			CBC_Mode< AES >::Encryption e;
			e.SetKeyWithIV(key, 16, iv);

			// The StreamTransformationFilter adds padding
			//  as required. ECB and CBC Mode must be padded
			//  to the block size of the cipher.
			StringSource(plain, true, 
				new StreamTransformationFilter(e,
					new StringSink(cipher)
				) // StreamTransformationFilter      
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	// Chuyển string encoded sang wstring wencoded_cipher
	wstring wencoded_cipher(encoded.begin(), encoded.end()); 
	wcout << L"Cipher text: " << wencoded_cipher << endl; 
	// Xuất thời gian mã hóa đo được
	wcout << L"Encyption excution time: " << exec_time / 10000 << " ms" << endl;

	// Reset biến đo performance
	exec_time = 0;

//---------GIẢI MÃ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			recovered = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			CBC_Mode< AES >::Decryption d;
			d.SetKeyWithIV(key, 16, iv);

			// The StreamTransformationFilter removes
			//  padding as required.
			StringSource s(cipher, true, 
				new StreamTransformationFilter(d,
					new StringSink(recovered)
				) // StreamTransformationFilter
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}

		// Chuyển chuỗi utf8-recovered thành wstring-recov
		wstring recov = utf8_to_wstring(recovered);
		// In ra màn hình
		wcout<< L"Recovered text: "<< recov<<endl;
		// In thời gian giải mã đo được
		wcout << L"Decyption excution time: " << exec_time / 10000 << " ms" << endl;
	}
	//Báo lỗi
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}


//OFB có dùng IV
//OFB không yêu cầu plaintext phải được Padding cho đủ size Block
void Func_OFB(wstring wplain, SecByteBlock key, byte* iv)
{
	// Chuyển chuỗi plaintext về utf8
	string plain;
	plain = wstring_to_utf8(wplain);     
	string cipher, encoded, recovered;

	// In Key ra màn hình
	encoded.clear();
	StringSource(key, 16, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder 
	); // StringSource

	// Chuyển string encoded sang wstring wencoded_key
	wstring wencoded_key(encoded.begin(), encoded.end()); 
	wcout << L"Key: " << wencoded_key << endl;

	// In iv ra màn hình
	encoded.clear();
	StringSource(iv, 16, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource

	// Chuyển string encoded sang wstring wencoded_iv
    wstring wencoded_iv(encoded.begin(), encoded.end()); 
	wcout << L"IV: " << wencoded_iv << endl;

	// Biến đo performance
	int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;

	wcout << "Plain text: " << wplain <<endl;

//---------MÃ HOÁ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			cipher = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			OFB_Mode< AES >::Encryption e;
			e.SetKeyWithIV(key, 16, iv);

			// The StreamTransformationFilter adds padding
			//  as required. ECB and CBC Mode must be padded
			//  to the block size of the cipher.
			StringSource(plain, true, 
				new StreamTransformationFilter(e,
					new StringSink(cipher)
				) // StreamTransformationFilter      
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	// Chuyển string encoded sang wstring wencoded_cipher
	wstring wencoded_cipher(encoded.begin(), encoded.end()); 
	wcout << L"Cipher text: " << wencoded_cipher << endl; 
	// Xuất thời gian mã hóa đo được
	wcout << L"Encyption excution time: " << exec_time / 10000 << " ms" << endl;

	// Reset biến đo performance
	exec_time = 0;

//---------GIẢI MÃ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			recovered = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			OFB_Mode< AES >::Decryption d;
			d.SetKeyWithIV(key, 16, iv);

			// The StreamTransformationFilter removes
			//  padding as required.
			StringSource s(cipher, true, 
				new StreamTransformationFilter(d,
					new StringSink(recovered)
				) // StreamTransformationFilter
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}

		// Chuyển chuỗi utf8-recovered thành wstring-recov
		wstring recov = utf8_to_wstring(recovered);
		// In ra màn hình
		wcout<< L"Recovered text: "<< recov<<endl;
		// In thời gian giải mã đo được
		wcout << L"Decyption excution time: " << exec_time / 10000 << " ms" << endl;
	}
	//Báo lỗi
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}


//CFB có dùng IV
//CFB không yêu cầu plaintext phải được Padding cho đủ size Block
void Func_CFB(wstring wplain, SecByteBlock key, byte* iv)
{
	// Chuyển chuỗi plaintext về utf8
	string plain;
	plain = wstring_to_utf8(wplain);     
	string cipher, encoded, recovered;

	// In Key ra màn hình
	encoded.clear();
	StringSource(key, 16, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder 
	); // StringSource

	// Chuyển string encoded sang wstring wencoded_key
	wstring wencoded_key(encoded.begin(), encoded.end()); 
	wcout << L"Key: " << wencoded_key << endl;

	// In iv ra màn hình
	encoded.clear();
	StringSource(iv, 16, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource

	// Chuyển string encoded sang wstring wencoded_iv
    wstring wencoded_iv(encoded.begin(), encoded.end()); 
	wcout << L"IV: " << wencoded_iv << endl;

	// Biến đo performance
	int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;

	wcout << "Plain text: " << wplain <<endl;

//---------MÃ HOÁ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			cipher = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			CFB_Mode< AES >::Encryption e;
			e.SetKeyWithIV(key, 16, iv);

			// The StreamTransformationFilter adds padding
			//  as required. ECB and CBC Mode must be padded
			//  to the block size of the cipher.
			StringSource(plain, true, 
				new StreamTransformationFilter(e,
					new StringSink(cipher)
				) // StreamTransformationFilter      
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	// Chuyển string encoded sang wstring wencoded_cipher
	wstring wencoded_cipher(encoded.begin(), encoded.end()); 
	wcout << L"Cipher text: " << wencoded_cipher << endl; 
	// Xuất thời gian mã hóa đo được
	wcout << L"Encyption excution time: " << exec_time / 10000 << " ms" << endl;

	// Reset biến đo performance
	exec_time = 0;

//---------GIẢI MÃ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			recovered = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			CFB_Mode< AES >::Decryption d;
			d.SetKeyWithIV(key, 16, iv);

			// The StreamTransformationFilter removes
			//  padding as required.
			StringSource s(cipher, true, 
				new StreamTransformationFilter(d,
					new StringSink(recovered)
				) // StreamTransformationFilter
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}

		// Chuyển chuỗi utf8-recovered thành wstring-recov
		wstring recov = utf8_to_wstring(recovered);
		// In ra màn hình
		wcout<< L"Recovered text: "<< recov<<endl;
		// In thời gian giải mã đo được
		wcout << L"Decyption excution time: " << exec_time / 10000 << " ms" << endl;
	}
	//Báo lỗi
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}


//CTR không yêu cầu Padding
void Func_CTR(wstring wplain, SecByteBlock key, byte* iv)
{
	// Chuyển chuỗi plaintext về utf8
	string plain;
	plain = wstring_to_utf8(wplain);     
	string cipher, encoded, recovered;

	// In Key ra màn hình
	encoded.clear();
	StringSource(key, 16, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder 
	); // StringSource

	// Chuyển string encoded sang wstring wencoded_key
	wstring wencoded_key(encoded.begin(), encoded.end()); 
	wcout << L"Key: " << wencoded_key << endl;

	// In iv ra màn hình
	encoded.clear();
	StringSource(iv, 16, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource

	// Chuyển string encoded sang wstring wencoded_iv
    wstring wencoded_iv(encoded.begin(), encoded.end()); 
	wcout << L"IV: " << wencoded_iv << endl;

	// Biến đo performance
	int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;

	wcout << "Plain text: " << wplain <<endl;

//---------MÃ HOÁ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			cipher = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			CTR_Mode< AES >::Encryption e;
			e.SetKeyWithIV(key, 16, iv);

			// The StreamTransformationFilter adds padding
			//  as required. ECB and CBC Mode must be padded
			//  to the block size of the cipher.
			StringSource(plain, true, 
				new StreamTransformationFilter(e,
					new StringSink(cipher)
				) // StreamTransformationFilter      
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	// Chuyển string encoded sang wstring wencoded_cipher
	wstring wencoded_cipher(encoded.begin(), encoded.end()); 
	wcout << L"Cipher text: " << wencoded_cipher << endl; 
	// Xuất thời gian mã hóa đo được
	wcout << L"Encyption excution time: " << exec_time / 10000 << " ms" << endl;

	// Reset biến đo performance
	exec_time = 0;

//---------GIẢI MÃ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			recovered = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			CTR_Mode< AES >::Decryption d;
			d.SetKeyWithIV(key, 16, iv);

			// The StreamTransformationFilter removes
			//  padding as required.
			StringSource s(cipher, true, 
				new StreamTransformationFilter(d,
					new StringSink(recovered)
				) // StreamTransformationFilter
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}

		// Chuyển chuỗi utf8-recovered thành wstring-recov
		wstring recov = utf8_to_wstring(recovered);
		// In ra màn hình
		wcout<< L"Recovered text: "<< recov<<endl;
		// In thời gian giải mã đo được
		wcout << L"Decyption excution time: " << exec_time / 10000 << " ms" << endl;
	}
	//Báo lỗi
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

//XTS có dùng iv
//XTS không yêu cầu Padding
//NOTE: XTS yêu cầu plaintext tối thiểu 16 bytes
void Func_XTS(wstring wplain, SecByteBlock key, byte* iv)
{
	// Chuyển chuỗi plaintext về utf8
	string plain;
	plain = wstring_to_utf8(wplain);     
	string cipher, encoded, recovered;

	// In Key ra màn hình
	encoded.clear();
	StringSource(key, 32, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder 
	); // StringSource

	// Chuyển string encoded sang wstring wencoded_key
	wstring wencoded_key(encoded.begin(), encoded.end()); 
	wcout << L"Key: " << wencoded_key << endl;

	// In iv ra màn hình
	encoded.clear();
	StringSource(iv, 32, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource

	// Chuyển string encoded sang wstring wencoded_iv
    wstring wencoded_iv(encoded.begin(), encoded.end()); 
	wcout << L"IV: " << wencoded_iv << endl;

	// Biến đo performance
	int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;

	wcout << "Plain text: " << wplain <<endl;

//---------MÃ HOÁ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			cipher = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			XTS_Mode< AES >::Encryption e;
			e.SetKeyWithIV(key, 32, iv);

			// The StreamTransformationFilter adds padding
			//  as required. ECB and CBC Mode must be padded
			//  to the block size of the cipher.
			StringSource(plain, true, 
				new StreamTransformationFilter(e,
					new StringSink(cipher)
				) // StreamTransformationFilter      
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	// Chuyển string encoded sang wstring wencoded_cipher
	wstring wencoded_cipher(encoded.begin(), encoded.end()); 
	wcout << L"Cipher text: " << wencoded_cipher << endl; 
	// Xuất thời gian mã hóa đo được
	wcout << L"Encyption excution time: " << exec_time / 10000 << " ms" << endl;

	// Reset biến đo performance
	exec_time = 0;

//---------GIẢI MÃ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			recovered = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			XTS_Mode< AES >::Decryption d;
			d.SetKeyWithIV(key, 32, iv);

			// The StreamTransformationFilter removes
			//  padding as required.
			StringSource s(cipher, true, 
				new StreamTransformationFilter(d,
					new StringSink(recovered)
				) // StreamTransformationFilter
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}

		// Chuyển chuỗi utf8-recovered thành wstring-recov
		wstring recov = utf8_to_wstring(recovered);
		// In ra màn hình
		wcout<< L"Recovered text: "<< recov<<endl;
		// In thời gian giải mã đo được
		wcout << L"Decyption excution time: " << exec_time / 10000 << " ms" << endl;
	}
	//Báo lỗi
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

//CCM có dùng iv
//iv phải có độ dài bằng { 7, 8, 9, 10, 11, 12, 13 }
//CCM có hỗ trợ kiểm tra toàn vẹn dữ liệu
void Func_CCM(wstring wplain, SecByteBlock key, byte* iv)
{
	// Chuyển chuỗi plaintext về utf8
	string plain;
	plain = wstring_to_utf8(wplain);     
	string cipher, encoded, recovered;

	// In Key ra màn hình
	encoded.clear();
	StringSource(key, 16, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder 
	); // StringSource

	// Chuyển string encoded sang wstring wencoded_key
	wstring wencoded_key(encoded.begin(), encoded.end()); 
	wcout << L"Key: " << wencoded_key << endl;

	// In iv ra màn hình
	encoded.clear();
	StringSource(iv, 16, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource

	// Chuyển string encoded sang wstring wencoded_iv
    wstring wencoded_iv(encoded.begin(), encoded.end()); 
	wcout << L"IV: " << wencoded_iv << endl;

	// Biến đo performance
	int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;

	wcout << "Plain text: " << wplain <<endl;

//---------MÃ HOÁ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			cipher = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			CCM< AES >::Encryption e;
			e.SetKeyWithIV(key, 16, iv);

			// The StreamTransformationFilter adds padding
			//  as required. ECB and CBC Mode must be padded
			//  to the block size of the cipher.
			StringSource(plain, true, 
				new CryptoPP::AuthenticatedEncryptionFilter(e,
					new StringSink(cipher)
				) // StreamTransformationFilter      
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	// Chuyển string encoded sang wstring wencoded_cipher
	wstring wencoded_cipher(encoded.begin(), encoded.end()); 
	wcout << L"Cipher text: " << wencoded_cipher << endl; 
	// Xuất thời gian mã hóa đo được
	wcout << L"Encyption excution time: " << exec_time / 10000 << " ms" << endl;

	// Reset biến đo performance
	exec_time = 0;

//---------GIẢI MÃ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			recovered = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			CCM< AES >::Decryption d;
			d.SetKeyWithIV(key, 16, iv);

			// The StreamTransformationFilter removes
			//  padding as required.
			StringSource s(cipher, true, 
				new CryptoPP::AuthenticatedDecryptionFilter(d,
					new StringSink(recovered)
				) // StreamTransformationFilter
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}

		// Chuyển chuỗi utf8-recovered thành wstring-recov
		wstring recov = utf8_to_wstring(recovered);
		// In ra màn hình
		wcout<< L"Recovered text: "<< recov<<endl;
		// In thời gian giải mã đo được
		wcout << L"Decyption excution time: " << exec_time / 10000 << " ms" << endl;
	}
	//Báo lỗi
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}


//GCM có hỗ trợ kiểm tra toàn vẹn dữ liệu
void Func_GCM(wstring wplain, SecByteBlock key, byte* iv)
{
	// Chuyển chuỗi plaintext về utf8
	string plain;
	plain = wstring_to_utf8(wplain);     
	string cipher, encoded, recovered;

	// In Key ra màn hình
	encoded.clear();
	StringSource(key, 16, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder 
	); // StringSource

	// Chuyển string encoded sang wstring wencoded_key
	wstring wencoded_key(encoded.begin(), encoded.end()); 
	wcout << L"Key: " << wencoded_key << endl;

	// In iv ra màn hình
	encoded.clear();
	StringSource(iv, 16, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource

	// Chuyển string encoded sang wstring wencoded_iv
    wstring wencoded_iv(encoded.begin(), encoded.end()); 
	wcout << L"IV: " << wencoded_iv << endl;

	// Biến đo performance
	int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;

	wcout << "Plain text: " << wplain <<endl;

//---------MÃ HOÁ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			cipher = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			GCM< AES >::Encryption e;
			e.SetKeyWithIV(key, 16, iv);

			// The StreamTransformationFilter adds padding
			//  as required. ECB and CBC Mode must be padded
			//  to the block size of the cipher.
			StringSource(plain, true, 
				new CryptoPP::AuthenticatedEncryptionFilter(e,
					new StringSink(cipher)
				) // StreamTransformationFilter      
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	// Chuyển string encoded sang wstring wencoded_cipher
	wstring wencoded_cipher(encoded.begin(), encoded.end()); 
	wcout << L"Cipher text: " << wencoded_cipher << endl; 
	// Xuất thời gian mã hóa đo được
	wcout << L"Encyption excution time: " << exec_time / 10000 << " ms" << endl;

	// Reset biến đo performance
	exec_time = 0;

//---------GIẢI MÃ----------
	try
	{
		for (int count = 1; count <= 10000; count++)
		{
			recovered = "";
			// Bắt đầu tính thời gian
			start_time = clock();
			GCM< AES >::Decryption d;
			d.SetKeyWithIV(key, 16, iv);

			// The StreamTransformationFilter removes
			//  padding as required.
			StringSource s(cipher, true, 
				new CryptoPP::AuthenticatedDecryptionFilter(d,
					new StringSink(recovered)
				) // StreamTransformationFilter
			); // StringSource
			// Kết thúc tính thời gian
			stop_time = clock();
			exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
		}

		// Chuyển chuỗi utf8-recovered thành wstring-recov
		wstring recov = utf8_to_wstring(recovered);
		// In ra màn hình
		wcout<< L"Recovered text: "<< recov<<endl;
		// In thời gian giải mã đo được
		wcout << L"Decyption excution time: " << exec_time / 10000 << " ms" << endl;
	}
	//Báo lỗi
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}


//Hàm in ra màn hình danh sách các MODE để chọn
void printMenu()
{
    wcout << "ENCRYPT and DECRYPT using AES: " << endl;
    wcout << "Select MODE: " << endl;
    wcout << "1. ECB" << endl;
    wcout << "2. CBC" << endl;
    wcout << "3. OFB" << endl;
    wcout << "4. CFB" << endl;
    wcout << "5. CTR" << endl;
    wcout << "6. XTS (Plaintext must be at least 1 block [16 bytes] )" << endl;
    wcout << "7. CCM" << endl;
    wcout << "8. GCM" << endl;
}

// Convert string to wstring
wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

// Convert wstring to string
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

// Convert UTF-8 string to wstring
wstring utf8_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> myconv;
    return myconv.from_bytes(str);
}

// Convert wstring to UTF-8 string
string wstring_to_utf8 (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> myconv;
    return myconv.to_bytes(str);
}

