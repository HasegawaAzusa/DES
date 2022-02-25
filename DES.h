#pragma once
#include <string>
#include <bitset>
using std::string;
using std::bitset;

class DES
{
public:
	/**
	 * 接收一个32位输入Ri与子密钥ki，获取32位输出
	 */
	static bitset<32> feistel(const bitset<32>& Ri, const bitset<48>& ki)
	{
		bitset<48> expandRi;
		// 第一步：E盒扩展置换，32位的Ri映射为48位
		for (int i = 0; i < 48; ++i)
			expandRi[i] = Ri[DES::E[i] - 1];

		// 第二步：异或
		expandRi = expandRi ^ ki;

		// 第三步：S盒置换，48位的输入映射为32位输出
		bitset<32> mappingRi;
		for (int i = 0, j = 0; i < 48; i += 6)
		{
			int row = (expandRi[i] << 1) | expandRi[i + 5];
			int col = (expandRi[i + 1] << 3) | (expandRi[i + 2] << 2) | (expandRi[i + 3] << 1) | expandRi[i + 4];
			int num = S_BOX[i / 6][row][col];
			mappingRi[j++] = num & 1;
			mappingRi[j++] = num & 2;
			mappingRi[j++] = num & 4;
			mappingRi[j++] = num & 8;
		}

		// 第四步：P盒置换，32位的输入映射为32位输出
		bitset<32> output = mappingRi;
		for (int i = 0; i < 32; ++i)
			output[i] = mappingRi[DES::P[i] - 1];
		return output;
	}


	/**
	 * 对子密钥的28位输入循环左移shift
	 */
	static bitset<28> leftShift(const bitset<28>& ki, int shift)
	{
		bitset<28> output((ki << shift) | (ki >> (28 - shift)));
		return output;
	}

	/**
	 * 生成16个48位子密钥
	 */
	void generateKeys(const bitset<64>& key)
	{
		bitset<56> realKey;
		bitset<28> Li;
		bitset<28> Ri;
		// 去掉奇偶标记位，将64位密钥变成56位
		for (int i = 0; i < 56; ++i)
			realKey[i] = key[PC_1[i] - 1];
		// 生成子密钥，保存在 subKeys[16] 中
		for (int round = 0; round < 16; ++round)
		{
			Li = realKey.to_ullong() >> 28;
			Ri = realKey.to_ullong() & 0X0FFFFFFF;
			Li = DES::leftShift(Li, shiftBits[round]);
			Ri = DES::leftShift(Ri, shiftBits[round]);
			realKey = (Li.to_ullong() << 28) | Ri.to_ullong();
			for (int i = 0; i < 48; ++i)
			{
				subKeys[round][i] = realKey[PC_2[i] - 1];
			}
		}
	}

	// 将8个字节转换为 bitset<64>
	static bitset<64> toUllong(const string& str)
	{
		unsigned long long bits = 0;
		for (int i = 0; i < 8; ++i)
		{
			bits = (bits << 8) | str[i];
		}
		return bits;
	}
	
	// 将 bitset<64> 转换为8个字节
	static string toString(const bitset<64>& bits)
	{
		return DES::toString(bits.to_ullong());
	}

	// 将 unsigned long long 转换为8个字节
	static string toString(unsigned long long bits)
	{
		string str(9, 0);
		for (int i = 0; i < 8; ++i)
		{
			str[8 - i] = bits & 0xFF;
			bits >>= 8;
		}
		return str;
	}

	void generateKeys(const string& key)
	{
		this->generateKeys(DES::toUllong(key));
	}

	/**
	 * 一次 DES 加密64位数据
	 */
	bitset<64> encode(const bitset<64>& plain)
	{
		bitset<64> code;
		bitset<64> IPoutput;
		bitset<32> Li;
		bitset<32> Ri;
		bitset<32> newLi;
		// 第一步：初始置换IP
		for (int i = 0; i < 64; ++i)
			IPoutput[i] = plain[IP[i] - 1];

		// 第二步：获取 L0 和 R0
		Li = IPoutput.to_ullong() >> 32;
		Ri = IPoutput.to_ullong() & 0xFFFFFFFF;

		// 第三步：共16轮迭代
		for (int round = 0; round < 16; ++round)
		{
			newLi = Ri;
			Ri = Li ^ DES::feistel(Ri, subKeys[round]);
			Li = newLi;
		}

		// 第四步：合并L16和R16，注意合并为 R16L16
		IPoutput = (Ri.to_ullong() << 32) | (Li.to_ullong());

		// 第五步：逆初始置换 IP^(-1)
		for (int i = 0; i < 64; ++i)
			code[i] = IPoutput[IP_1[i] - 1];

		// 返回密文
		return code;
	}
	
	/**
	 * 一次 DES 解密64位数据
	 */
	bitset<64> decode(const bitset<64>& code)
	{
		bitset<64> plain;
		bitset<64> IPoutput;
		bitset<32> Li;
		bitset<32> Ri;
		bitset<32> newLi;

		// 第一步：初始置换IP
		for (int i = 0; i < 64; ++i)
			IPoutput[i] = code[IP[i] - 1];

		// 第二步：获取 L16 和 R16
		Li = IPoutput.to_ullong() >> 32;
		Ri = IPoutput.to_ullong() & 0xFFFFFFFF;

		// 第三步：共16轮迭代（子密钥逆序应用）
		for (int round = 0; round < 16; ++round)
		{
			newLi = Ri;
			Ri = Li ^ DES::feistel(Ri, subKeys[15 - round]);
			Li = newLi;
		}

		// 第四步：合并L16和R16，注意合并为 R16L16
		IPoutput = (Ri.to_ullong() << 32) | (Li.to_ullong());

		// 第五步：逆初始置换 IP^(-1)
		for (int i = 0; i < 64; ++i)
			plain[i] = IPoutput[IP_1[i] - 1];

		// 返回明文
		return plain;
	}

private:
	// 子密钥 (轮密钥 ki)
	bitset<48> subKeys[16];
	// 初始置换表 IP
	static const int IP[64];
	// 逆初始置换表 IP^(-1)
	static const int IP_1[64];
	// 密钥置换表，将64位密钥压缩为56位
	static const int PC_1[56];
	// 压缩置换，将56位密钥压缩为48位子密钥
	static const int PC_2[48];
	// 每轮左移的位数
	static const int shiftBits[16];
	// E盒扩展置换表，将32位输入扩展至48位输出
	static const int E[48];
	// S盒置换表，每个S盒是4x16的置换表，6位输入映射为4位输出
	static const int S_BOX[8][4][16];
	// P盒置换表，32位输入映射为32位输出
	static const int P[32];
};

const int DES::IP[64] = {
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9,  1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

const int DES::IP_1[64] = {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41,  9, 49, 17, 57, 25
};

const int DES::PC_1[56] = {
	57, 49, 41, 33, 25, 17, 9,
	 1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27,
	19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	 7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29,
	21, 13,  5, 28, 20, 12,  4
};

const int DES::PC_2[48] = {
	14, 17, 11, 24,  1,  5,
	 3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8,
	16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

const int DES::shiftBits[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

const int DES::E[48] = {
	32,  1,  2,  3,  4,  5,
	 4,  5,  6,  7,  8,  9,
	 8,  9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32,  1
};

const int DES::S_BOX[8][4][16] = {
		{
			{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
			{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
			{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
			{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
		},
		{
			{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
			{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
			{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
			{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
		},
		{
			{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
			{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
			{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
			{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
		},
		{
			{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
			{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
			{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
			{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
		},
		{
			{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
			{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
			{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
			{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
		},
		{
			{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
			{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
			{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
			{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
		},
		{
			{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
			{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
			{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
			{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
		},
		{
			{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
			{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
			{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
			{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
		}
};

const int DES::P[32] = {
	16,  7, 20, 21,
	29, 12, 28, 17,
	 1, 15, 23, 26,
	 5, 18, 31, 10,
	 2,  8, 24, 14,
	32, 27,  3,  9,
	19, 13, 30,  6,
	22, 11,  4, 25
};
