#include <iostream>
#include "src/AES.h"
#include "gtest/gtest.h"

TEST(AESFixture, RotWord_1)
{
	AES a = AES();
	unsigned int w = 0x11223344;
	const unsigned int ans = 0x22334411;
	const unsigned int v = a.RotWord(w);
	ASSERT_EQ(v, ans);
}

TEST(AESFixture, RotWord_2)
{
	AES a = AES();
	unsigned int w = 0x00AABBCC;
	const unsigned int ans = 0xAABBCC00;
	const unsigned int v = a.RotWord(w);
	ASSERT_EQ(v, ans);
}

TEST(AESFixture, RotWord_3)
{
	AES a = AES();
	unsigned int w = 0x83ced71b;
	const unsigned int ans = 0xced71b83;
	const unsigned int v = a.RotWord(w);
	ASSERT_EQ(v, ans);
}

TEST(AESFixture, SubWord_1)
{
	AES a = AES();
	unsigned int w = 0x11223344;
	const unsigned int ans = 0x8293c31b;
	const unsigned int v = a.SubWord(w);
	ASSERT_EQ(v, ans);
}

TEST(AESFixture, SubWord_2)
{
	AES a = AES();
	unsigned int w = 0x925cef3d;
	const unsigned int ans = 0x4f4adf27;
	const unsigned int v = a.SubWord(w);
	ASSERT_EQ(v, ans);
}

TEST(AESFixture, SubWord_3)
{
	AES a = AES();
	unsigned int w = 0x83ced71b;
	const unsigned int ans = 0xec8b0eaf;
	const unsigned int v = a.SubWord(w);
	ASSERT_EQ(v, ans);
}

TEST(AESFixture, init_state_1)
{
	AES a = AES();
	std::string s = "00 44 88 cc \n11 55 99 dd \n22 66 aa ee \n33 77 bb ff \n";
	std::string in = "00112233445566778899AABBCCDDEEFF";
	a.init_state(in);
	std::ostringstream o;
	a.print_state(o);
	ASSERT_EQ(o.str(), s); 
}
