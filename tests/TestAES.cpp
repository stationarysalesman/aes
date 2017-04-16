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

