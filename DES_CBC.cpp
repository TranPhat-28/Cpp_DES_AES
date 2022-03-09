#include <iostream>
#include <string>
#include <cmath>
#include <bitset>
#include <sstream>
#include <vector>
//Support Vietnamese
#include <io.h>
#include <fcntl.h>
#include <string>
using std::string;
using std::wstring;
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;
using namespace std;

// Chuỗi lưu 16 key cho 16 vòng mã hoá
string round_keys[16];

// Biến lưu lại độ dài padding của block cuối để xoá padding sau này
int pad_length;

// Chuỗi plaintext
// Vì là biến toàn cục nên trước khi thực hiện mã / giải mã cần chú ý cập nhật biến này lại
string plain;

// Hàm chuyển từ thập phân sang chuỗi nhị phân
// Dùng để tìm đúng S-box theo index khi mã hoá
string convertDecimalToBinary(int decimal)
{
	string binary;
    while(decimal != 0) 
	{
		binary = (decimal % 2 == 0 ? "0" : "1") + binary; 
		decimal = decimal/2;
	}

	while(binary.length() < 4)
	{
		binary = "0" + binary;
	}
    return binary;
}

// Hàm chuyển từ nhị phân sang thập phân
// Dùng để tìm đúng S-box theo index khi mã hoá
int convertBinaryToDecimal(string binary)
{
    int decimal = 0;
	int counter = 0;
	int size = binary.length();
	for(int i = size-1; i >= 0; i--)
	{
    	if(binary[i] == '1')
		{
        	decimal += pow(2, counter);
    	}
    	counter++;
	}
	return decimal;
}

// Hàm thực hiện shift trái 1 bit
string shift_left_once(string key_chunk)
{ 
    string shifted = "";  
    for(int i = 1; i < 28; i++)
	{ 
        shifted += key_chunk[i]; 
    } 
    shifted += key_chunk[0];   
    return shifted; 
} 

// Hàm thực hiện shift trái 2 bit
string shift_left_twice(string key_chunk)
{ 
    string shifted=""; 
    for(int i = 0; i < 2; i++)
	{ 
        for(int j = 1; j < 28; j++)
		{ 
            shifted += key_chunk[j]; 
        } 
        shifted += key_chunk[0]; 
        key_chunk= shifted; 
        shifted =""; 
    } 
    return key_chunk; 
}

// Hàm thực hiện XOR 2 chuỗi đầu vào
string Xor(string a, string b)
{ 
	string result = ""; 
	int size = b.size();
	for(int i = 0; i < size; i++)
	{ 
		if(a[i] != b[i])
		{ 
			result += "1"; 
		}
		else
		{ 
			result += "0"; 
		} 
	} 
	return result; 
} 

// Hàm tạo ngẫu nhiên 16 key cho 16 round
// Từ một key được input ban đầu
void generate_keys(string key)
{
	// Bảng PC1 (Permutation compression)
	int pc1[56] = {
	57,49,41,33,25,17,9, 
	1,58,50,42,34,26,18, 
	10,2,59,51,43,35,27, 
	19,11,3,60,52,44,36,		 
	63,55,47,39,31,23,15, 
	7,62,54,46,38,30,22, 
	14,6,61,53,45,37,29, 
	21,13,5,28,20,12,4 
	};

	// Bảng PC2 (Permutation compression)
	int pc2[48] = { 
	14,17,11,24,1,5, 
	3,28,15,6,21,10, 
	23,19,12,4,26,8, 
	16,7,27,20,13,2, 
	41,52,31,37,47,55, 
	30,40,51,45,33,48, 
	44,49,39,56,34,53, 
	46,42,50,36,29,32 
	}; 

	// B1. Nén key với bảng PC1
	// Key sẽ từ 64 bits -> 56 bits
	string perm_key = ""; 
	for(int i = 0; i < 56; i++)
	{ 
		perm_key+= key[pc1[i]-1]; 
	} 

	// B2. Chia key thành 2 nửa trái và phải
	string left= perm_key.substr(0, 28); 
	string right= perm_key.substr(28, 28); 

	// Vòng lặp 16 lần để tạo 16 key
	for (int i = 0; i < 16; i++)
	{ 
		// B3.1. Đối với rounds 1, 2, 9, 16 thì key sẽ được shift trái 1 bit
		if(i == 0 || i == 1 || i==8 || i==15 )
		{
			// Shift cả 2 nửa trái và phải
			left= shift_left_once(left); 
			right= shift_left_once(right);
		} 
		// B3.2. Đối với các round còn lại thì key được shift 2 bit
		else
		{
			// Shift cả 2 nửa trái và phải
			left= shift_left_twice(left); 
			right= shift_left_twice(right);
		}
		// Ghép 2 nửa lại với nhau
		string combined_key = left + right;
		string round_key = ""; 
		// Dùng bảng PC2 để biến đổi key
		// Key sẽ giảm từ 56 xuống còn 48 bits
		for(int i = 0; i < 48; i++)
		{ 
			round_key += combined_key[pc2[i]-1]; 
		}   
		// Hoàn thành một key, lưu lại vào mảng
		round_keys[i] = round_key; 
		// Kết thúc một vòng tạo key
	} 
}



// ------------------------------------------
// --------------Mã hoá DES------------------
// ------------------------------------------

string DES()
{ 
	// Bảng IP dùng cho bước hoán vị ban đầu (Initial Permutation)
	int initial_permutation[64] = { 
	58,50,42,34,26,18,10,2, 
	60,52,44,36,28,20,12,4, 
	62,54,46,38,30,22,14,6, 
	64,56,48,40,32,24,16,8, 
	57,49,41,33,25,17,9,1, 
	59,51,43,35,27,19,11,3, 
	61,53,45,37,29,21,13,5, 
	63,55,47,39,31,23,15,7 
	}; 

	// Bảng Expansion table
	int expansion_table[48] = { 
	32,1,2,3,4,5,4,5, 
	6,7,8,9,8,9,10,11, 
	12,13,12,13,14,15,16,17, 
	16,17,18,19,20,21,20,21, 
	22,23,24,25,24,25,26,27, 
	28,29,28,29,30,31,32,1 
	}; 

	// S-Box (Substition box)
	int substition_boxes[8][4][16]=  
	{{ 
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8, 
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 
    }, 
    { 
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5, 
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 
    }, 
    { 
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1, 
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 
    }, 
    { 
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9, 
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 
    }, 
    { 
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6, 
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 
    }, 
    { 
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8, 
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 
    }, 
    { 
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6, 
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 
    }, 
    { 
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2, 
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 
    }};
	// Bảng permutation ( P-Box )
	int permutation_tab[32] = { 
	16,7,20,21,29,12,28,17, 
	1,15,23,26,5,18,31,10, 
	2,8,24,14,32,27,3,9,
	19,13,30,6,22,11,4,25 
	}; 
	// Bảng permutation ngược ( P^(-1) )
	int inverse_permutation[64]= { 
	40,8,48,16,56,24,64,32, 
	39,7,47,15,55,23,63,31, 
	38,6,46,14,54,22,62,30, 
	37,5,45,13,53,21,61,29, 
	36,4,44,12,52,20,60,28, 
	35,3,43,11,51,19,59,27, 
	34,2,42,10,50,18,58,26, 
	33,1,41,9,49,17,57,25 
	};

	// B1. Thực hiện Initial Permutation
  	string perm = ""; 
	for(int i = 0; i < 64; i++)
	{ 
		perm += plain[initial_permutation[i]-1]; 
	}  

	// B2. Sau khi IP, chia plaintext thành 2 nửa trái và phải bằng nhau, mỗi phần 32 bit
	string left = perm.substr(0, 32); 
	string right = perm.substr(32, 32);

	// Thực hiện 16 vòng mã hoá (vòng lặp for 16 lần)
	for (int i = 0; i < 16; i++) 
	{ 
    	string right_expanded = ""; 
		// 3.1. Nửa phải sẽ được mở rộng (expand) sử dụng expansion table
		// Sẽ tăng từ 32 lên 48 bit sau bước này
    	for(int i = 0; i < 48; i++) 
		{ 
      		right_expanded += right[expansion_table[i]-1]; 
    	}

		// 3.3. Sau đó nửa phải (đã được mở rộng lên 48 bits) sẽ được XOR với key (key 48 bits)
		string xored = Xor(round_keys[i], right_expanded);  

		string res = ""; 
		// 3.4. Kết quả sẽ được chia thành 8 phần bằng nhau, mỗi phần 6 bits, và thực 
		// hiện substition với 8 S-box. Sau bước này mỗi phần đều sẽ giảm từ 
		// 6 bit xuống 4 bit.
		for(int i = 0; i < 8; i++)
		{ 
			// Tìm S-box theo index
      		string row1= xored.substr(i*6,1) + xored.substr(i*6 + 5,1);
      		int row = convertBinaryToDecimal(row1);
      		string col1 = xored.substr(i*6 + 1,1) + xored.substr(i*6 + 2,1) + xored.substr(i*6 + 3,1) + xored.substr(i*6 + 4,1);;
			int col = convertBinaryToDecimal(col1);
			int val = substition_boxes[i][row][col];
			res += convertDecimalToBinary(val);  
		} 

		// 3.5. Hoán vị - Permutation
		// Sử dụng Permutation box
		string perm2 =""; 
		for(int i = 0; i < 32; i++)
		{ 
			perm2 += res[permutation_tab[i]-1]; 
		}

		// 3.6. Kết quả sẽ được đem XOR với nửa trái
		xored = Xor(perm2, left);
		// 3.7. Sau đó nửa trái và nửa phải sẽ được đảo vị trí
		left = xored; 
		if(i < 15)
		{ 
			string temp = right;
			right = xored;
			left = temp;
		} 
		// Kết thúc round
	} 
	
	// 4. Hai nửa trái phải sẽ được ghép lại
	string combined_text = left + right;   
	string ciphertext = "";

	// Thực hiện IP ngược với bảng Inversed Permutation
	for(int i = 0; i < 64; i++)
	{ 
		ciphertext+= combined_text[inverse_permutation[i]-1]; 
	}

	// Kết quả
	return ciphertext; 
}

// Hàm chuyển String sang chuỗi bin
string TextToBinaryString(string text) 
{
    string binaryString = "";
    for (char& _char : text) {
        binaryString +=bitset<8>(_char).to_string();
    }
    return binaryString;
}

// Hàm chuyển chuỗi bin sang String
string BinaryStringToText(string bin) 
{
    string text = "";
    stringstream sstream(bin);
    while(sstream.good())
    {
        std::bitset<8> bits;
        sstream >> bits;
        char c = char(bits.to_ulong());
        text += c;
    }
    return text;
}

// Hàm tách chuỗi input thành từng block 8 bytes, lưu lại vào mảng
vector<string> split_input_to_block(string input)
{
	string tmp = input;
	vector<string> ans;
	while (tmp.length() != 0)
	{
		if (tmp.length() < 8)
		{
			break;
		}
		string block = tmp.substr(0, 8);
		ans.push_back(block);
		tmp = tmp.substr(8);
	}
	// Block cuối cùng
	ans.push_back(tmp);
	return ans;
}

/* convert string to wstring */
wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert ưstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}


int main()
{ 
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);

	// Nhập plaintext (dạng string)
	wcout << L"Input plaintext: ";
	wstring wplain;
	getline(wcin, wplain);

	plain = wstring_to_string (wplain);	

	// Gọi hàm để tách string input thành mảng các string, mỗi phần tử là 1 block (8 byte)
	vector<string> plaintext_block = split_input_to_block(plain);

	// Chuyển mảng input từ kiểu string sang binary và padding vào block cuối cùng
	vector<string> plaintext_bin_block;
	for (int i = 0; i < plaintext_block.size(); i++)
	{
		// Chuyển sang nhị phân
		if (i != (plaintext_block.size() - 1))
		{
			plaintext_bin_block.push_back(TextToBinaryString(plaintext_block[i]));
		}
		// Block cuối sẽ được padding
		else
		{
			// Padding theo độ dài của block cuối cùng
			// Padding như sau: block cuối nếu thiếu n byte (để đủ 8 byte)
			// Thì sẽ padding thêm vào 0n0n...(HEX) cho đến đủ
			string pad;
			switch (plaintext_block[i].length())
			{
			case 1:
				pad_length = 7;
				pad = "00000111000001110000011100000111000001110000011100000111";
				break;
			case 2:
				pad_length = 6;
				pad = "000001100000011000000110000001100000011000000110";
				break;
			case 3:
				pad_length = 5;
				pad = "0000010100000101000001010000010100000101";
				break;
			case 4:
				pad_length = 4;
				pad = "00000100000001000000010000000100";
				break;
			case 5:
				pad_length = 3;
				pad = "000000110000001100000011";
				break;
			case 6:
				pad_length = 2;
				pad = "0000001000000010";
				break;
			case 7:
				pad_length = 1;
				pad = "00000001";
				break;
			}
			// Lưu block đã chuyển sang kiểu nhị phân lại vào mảng
			plaintext_bin_block.push_back(TextToBinaryString(plaintext_block[i]) + pad);
		}
	}

/*
	// In ra màn hình từng block ban đầu (string)
	for (int i = 0; i < plaintext_block.size(); i++)
	{
		cout << plaintext_block[i] << endl;
	}
	// In ra màn hình từng block kiểu binary và đã padding
	for (int i = 0; i < plaintext_bin_block.size(); i++)
	{
		cout << plaintext_bin_block[i] << endl;
	}
*/

	//------------KEY-------------------
	// Input key từ màn hình
	// Và kiểm tra điều kiện (key = 8 byte)
	wcout << "Input key (8 bytes): ";
	wstring wkey_input;
	do
	{
		wcin >> wkey_input;
		if (wkey_input.length() != 8)
		{
			wcout << "Invalid key length." << endl;
		}
	} while (wkey_input.length() != 8);
	string key_input = wstring_to_string (wkey_input);
	
	// Chuyển key từ string sang binary
	string bin_key = TextToBinaryString(key_input);
	

	//------------Initialize Vector-----------------
	// Input IV từ màn hình
	// Và kiểm tra điều kiện (IV = 8 byte)
	wcout << "Input IV (8 bytes) : ";
	wstring wiv_input;
	do
	{
		wcin >> wiv_input;
		if (wiv_input.length() != 8)
		{
			wcout << "Invalid IV length." << endl;
		}
	} while (wiv_input.length() != 8);
	
	string iv_input = wstring_to_string(wiv_input);
	// Chuyển iv từ string sang binary
	string bin_iv = TextToBinaryString(iv_input);


	// In ra plaintext, key, iv người dùng đã nhập
    wcout << "Plaintext: " << wplain << endl; 
	wcout << "Key: " << string_to_wstring(key_input) << endl;
	wcout << "IV : " << string_to_wstring(iv_input) << endl;

	// Bắt đầu mã hoá
	// Tạo 16 key
  	generate_keys(bin_key); 


	// Mã hoá từng block
	// Sau đó mỗi block đã được mã hoá sẽ được lưu vào mảng
	// MODE CBC: Block plaintext đầu tiên sẽ được XOR với IV
	// Block plaintext thứ i sẽ được XOR với cipher thứ i - 1 trước khi mã hoá
	vector<string> cipher_block;
	for (int i = 0; i < plaintext_bin_block.size(); i++)
	{
		// Nếu là block đầu tiên thì đem XOR với iv
		if (i == 0)
		{
			plain = Xor(plaintext_bin_block[i], bin_iv);
		}
		// Nếu không thì đem XOR với cipher thứ i - 1
		else
		{
			plain = Xor(plaintext_bin_block[i], cipher_block[i - 1]);
		}
		string cipher = DES();
		cipher_block.push_back(cipher);
	}
    
	// Xuất ciphertext ra màn hình
	wcout << "Ciphertext: ";
	for (int i = 0; i < cipher_block.size(); i++)
	{
		wcout << string_to_wstring(cipher_block[i]);
	}
	wcout << endl;

	// Để giải mã, áp dụng DES với key được đảo ngược
	int i = 15;
	int j = 0;
	// Đảo ngược chuỗi 16 key
	while(i > j)
	{
		string temp = round_keys[i];
		round_keys[i] = round_keys[j];
		round_keys[j] = temp;
		i--;
		j++;
	}

	// Giải mã từng block
	// Sau đó mỗi block đã được giải mã sẽ được lưu vào mảng
	// MODE CBC: Block recovered đầu tiên sẽ được XOR với IV sau khi đã giải mã
	// Block recovered thứ i sẽ được XOR với block cipher thứ i - 1 sau khi được giải mã
	vector<string> recovered_block;
	for (int i = 0; i < cipher_block.size(); i++)
	{
		// Đưa nội dung cipher block vào plain để thực hiện
		plain = cipher_block[i];
		string recovered = DES();
		// Nếu là block đầu tiên thì đem XOR với iv
		if (i == 0)
		{
			recovered = Xor(recovered, bin_iv);
		}
		// Nếu không thì đem XOR với cipher thứ i - 1
		else
		{
			recovered = Xor(recovered, cipher_block[i - 1]);
		}
		recovered_block.push_back(recovered);
	}


	// Xuất recovered ra màn hình
	wcout << "Recovered: ";
	for (int i = 0; i < recovered_block.size(); i++)
	{
		// Nếu là block cuối cùng thì xoá đi phần padding
		if (i == recovered_block.size() - 1)
		{
			string last = BinaryStringToText(recovered_block[i]).substr(0, 8 - pad_length);
			wcout << string_to_wstring(last); 
			break;
		}
		wcout << string_to_wstring(BinaryStringToText(recovered_block[i]));
	}
	return 0;
} 