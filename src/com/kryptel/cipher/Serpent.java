/*******************************************************************************

  Product:       Kryptel/Java
  File:          Serpent.java
  Description:   https://www.kryptel.com/articles/developers/java/cipher.php

  Copyright (c) 2017 Inv Softworks LLC,    http://www.kryptel.com

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*******************************************************************************/


package com.kryptel.cipher;


import static com.kryptel.Guids.CID_CIPHER_SERPENT;
import static com.kryptel.bslx.Conversions.FromBytes;
import static com.kryptel.bslx.Conversions.ToBytes;

import java.util.UUID;


final class Serpent extends BlockCipherBase {
	Serpent(long capabilities) {
		super(capabilities);

  	DEFAULT_KEY_SIZE = 32;
  	DEFAULT_BLOCK_SIZE = 16;
  	DEFAULT_ROUNDS = 32;
  	DEFAULT_SCHEME = 1;

  	cipherInfo = new CipherInfo(
  			new int[] { 16, 24, 32 },				// Key sizes
  			new int[] { 16 },								// Block sizes
  			new int[] { 32 },								// Rounds
  			new String[] { "Standard" });

		cipherKeySize = DEFAULT_KEY_SIZE;
	  cipherBlockSize = DEFAULT_BLOCK_SIZE;
	  cipherRounds = DEFAULT_ROUNDS;
	  cipherScheme = DEFAULT_SCHEME;
	}

	
	//
	// IKryptelComponent
	//

	public UUID ComponentID() { return componentID; }
	public String ComponentName() { return "Serpent"; }

	
  //
  // Private data and methods
  //

  static UUID componentID = CID_CIPHER_SERPENT;


  private static final int PHI = 0x9e3779b9;    // Constant used in the key schedule

  private int[][] Subkeys = new int [33][4];

  
  private static int ROL(int x, int n) {
    return (x << n) | (x >>> (32 - n));
  }
  private static int ROR(int x, int n) {
    return (x >>> n) | (x << (32 - n));
  }
  
  
  private class RefInt { public int v; }

  private static void RND00(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t05, t06, t07, t08, t09, t11, t12, t13, t14, t15, t17, t01;
    t01 = b   ^ c  ;
    t02 = a   | d  ;
    t03 = a   ^ b  ;
    z.v = t02 ^ t01;
    t05 = c   | z.v;
    t06 = a   ^ d  ;
    t07 = b   | c  ;
    t08 = d   & t05;
    t09 = t03 & t07;
    y.v = t09 ^ t08;
    t11 = t09 & y.v;
    t12 = c   ^ d  ;
    t13 = t07 ^ t11;
    t14 = b   & t06;
    t15 = t06 ^ t13;
    w.v =     ~ t15;
    t17 = w.v ^ t14;
    x.v = t12 ^ t17;
  }
  private static void RND01(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t04, t05, t06, t07, t08, t10, t11, t12, t13, t16, t17, t01;
    t01 = a   | d  ;
    t02 = c   ^ d  ;
    t03 =     ~ b  ;
    t04 = a   ^ c  ;
    t05 = a   | t03;
    t06 = d   & t04;
    t07 = t01 & t02;
    t08 = b   | t06;
    y.v = t02 ^ t05;
    t10 = t07 ^ t08;
    t11 = t01 ^ t10;
    t12 = y.v ^ t11;
    t13 = b   & d  ;
    z.v =     ~ t10;
    x.v = t13 ^ t12;
    t16 = t10 | x.v;
    t17 = t05 & t16;
    w.v = c   ^ t17;
  }
  private static void RND02(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t05, t06, t07, t08, t09, t10, t12, t13, t14, t01;
    t01 = a   | c  ;
    t02 = a   ^ b  ;
    t03 = d   ^ t01;
    w.v = t02 ^ t03;
    t05 = c   ^ w.v;
    t06 = b   ^ t05;
    t07 = b   | t05;
    t08 = t01 & t06;
    t09 = t03 ^ t07;
    t10 = t02 | t09;
    x.v = t10 ^ t08;
    t12 = a   | d  ;
    t13 = t09 ^ x.v;
    t14 = b   ^ t13;
    z.v =     ~ t09;
    y.v = t12 ^ t14;
  }
  private static void RND03(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t13, t14, t15, t01;
    t01 = a   ^ c  ;
    t02 = a   | d  ;
    t03 = a   & d  ;
    t04 = t01 & t02;
    t05 = b   | t03;
    t06 = a   & b  ;
    t07 = d   ^ t04;
    t08 = c   | t06;
    t09 = b   ^ t07;
    t10 = d   & t05;
    t11 = t02 ^ t10;
    z.v = t08 ^ t09;
    t13 = d   | z.v;
    t14 = a   | t07;
    t15 = b   & t13;
    y.v = t08 ^ t11;
    w.v = t14 ^ t15;
    x.v = t05 ^ t04;
  }
  private static void RND04(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t04, t05, t06, t08, t09, t10, t11, t12, t13, t14, t15, t16, t01;
    t01 = a   | b  ;
    t02 = b   | c  ;
    t03 = a   ^ t02;
    t04 = b   ^ d  ;
    t05 = d   | t03;
    t06 = d   & t01;
    z.v = t03 ^ t06;
    t08 = z.v & t04;
    t09 = t04 & t05;
    t10 = c   ^ t06;
    t11 = b   & c  ;
    t12 = t04 ^ t08;
    t13 = t11 | t03;
    t14 = t10 ^ t09;
    t15 = a   & t05;
    t16 = t11 | t12;
    y.v = t13 ^ t08;
    x.v = t15 ^ t16;
    w.v =     ~ t14;
  }
  private static void RND05(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t04, t05, t07, t08, t09, t10, t11, t12, t13, t14, t01;
    t01 = b   ^ d  ;
    t02 = b   | d  ;
    t03 = a   & t01;
    t04 = c   ^ t02;
    t05 = t03 ^ t04;
    w.v =     ~ t05;
    t07 = a   ^ t01;
    t08 = d   | w.v;
    t09 = b   | t05;
    t10 = d   ^ t08;
    t11 = b   | t07;
    t12 = t03 | w.v;
    t13 = t07 | t10;
    t14 = t01 ^ t11;
    y.v = t09 ^ t13;
    x.v = t07 ^ t08;
    z.v = t12 ^ t14;
  }
  private static void RND06(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t04, t05, t07, t08, t09, t10, t11, t12, t13, t15, t17, t18, t01;
    t01 = a   & d  ;
    t02 = b   ^ c  ;
    t03 = a   ^ d  ;
    t04 = t01 ^ t02;
    t05 = b   | c  ;
    x.v =     ~ t04;
    t07 = t03 & t05;
    t08 = b   & x.v;
    t09 = a   | c  ;
    t10 = t07 ^ t08;
    t11 = b   | d  ;
    t12 = c   ^ t11;
    t13 = t09 ^ t10;
    y.v =     ~ t13;
    t15 = x.v & t03;
    z.v = t12 ^ t07;
    t17 = a   ^ b  ;
    t18 = y.v ^ t15;
    w.v = t17 ^ t18;
  }
  private static void RND07(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t04, t05, t06, t08, t09, t10, t11, t13, t14, t15, t16, t17, t01;
    t01 = a   & c  ;
    t02 =     ~ d  ;
    t03 = a   & t02;
    t04 = b   | t01;
    t05 = a   & b  ;
    t06 = c   ^ t04;
    z.v = t03 ^ t06;
    t08 = c   | z.v;
    t09 = d   | t05;
    t10 = a   ^ t08;
    t11 = t04 & z.v;
    x.v = t09 ^ t10;
    t13 = b   ^ x.v;
    t14 = t01 ^ x.v;
    t15 = c   ^ t05;
    t16 = t11 | t13;
    t17 = t02 | t14;
    w.v = t15 ^ t17;
    y.v = a   ^ t16;
  }

  private static void InvRND00(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t04, t05, t06, t08, t09, t10, t12, t13, t14, t15, t17, t18, t01;
    t01 = c   ^ d  ;
    t02 = a   | b  ;
    t03 = b   | c  ;
    t04 = c   & t01;
    t05 = t02 ^ t01;
    t06 = a   | t04;
    y.v =     ~ t05;
    t08 = b   ^ d  ;
    t09 = t03 & t08;
    t10 = d   | y.v;
    x.v = t09 ^ t06;
    t12 = a   | t05;
    t13 = x.v ^ t12;
    t14 = t03 ^ t10;
    t15 = a   ^ c  ;
    z.v = t14 ^ t13;
    t17 = t05 & t13;
    t18 = t14 | t17;
    w.v = t15 ^ t18;
  }
  private static void InvRND01(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t14, t15, t17, t01;
    t01 = a   ^ b  ;
    t02 = b   | d  ;
    t03 = a   & c  ;
    t04 = c   ^ t02;
    t05 = a   | t04;
    t06 = t01 & t05;
    t07 = d   | t03;
    t08 = b   ^ t06;
    t09 = t07 ^ t06;
    t10 = t04 | t03;
    t11 = d   & t08;
    y.v =     ~ t09;
    x.v = t10 ^ t11;
    t14 = a   | y.v;
    t15 = t06 ^ x.v;
    z.v = t01 ^ t04;
    t17 = c   ^ t15;
    w.v = t14 ^ t17;
  }
  private static void InvRND02(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t04, t06, t07, t08, t09, t10, t11, t12, t15, t16, t17, t01;
    t01 = a   ^ d  ;
    t02 = c   ^ d  ;
    t03 = a   & c  ;
    t04 = b   | t02;
    w.v = t01 ^ t04;
    t06 = a   | c  ;
    t07 = d   | w.v;
    t08 =     ~ d  ;
    t09 = b   & t06;
    t10 = t08 | t03;
    t11 = b   & t07;
    t12 = t06 & t02;
    z.v = t09 ^ t10;
    x.v = t12 ^ t11;
    t15 = c   & z.v;
    t16 = w.v ^ x.v;
    t17 = t10 ^ t15;
    y.v = t16 ^ t17;
  }
  private static void InvRND03(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t04, t05, t06, t07, t09, t11, t12, t13, t14, t16, t01;
    t01 = c   | d  ;
    t02 = a   | d  ;
    t03 = c   ^ t02;
    t04 = b   ^ t02;
    t05 = a   ^ d  ;
    t06 = t04 & t03;
    t07 = b   & t01;
    y.v = t05 ^ t06;
    t09 = a   ^ t03;
    w.v = t07 ^ t03;
    t11 = w.v | t05;
    t12 = t09 & t11;
    t13 = a   & y.v;
    t14 = t01 ^ t05;
    x.v = b   ^ t12;
    t16 = b   | t13;
    z.v = t14 ^ t16;
  }
  private static void InvRND04(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t04, t05, t06, t07, t09, t10, t11, t12, t13, t15, t01;
    t01 = b   | d  ;
    t02 = c   | d  ;
    t03 = a   & t01;
    t04 = b   ^ t02;
    t05 = c   ^ d  ;
    t06 =     ~ t03;
    t07 = a   & t04;
    x.v = t05 ^ t07;
    t09 = x.v | t06;
    t10 = a   ^ t07;
    t11 = t01 ^ t09;
    t12 = d   ^ t04;
    t13 = c   | t10;
    z.v = t03 ^ t12;
    t15 = a   ^ t04;
    y.v = t11 ^ t13;
    w.v = t15 ^ t09;
  }
  private static void InvRND05(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t04, t05, t07, t08, t09, t10, t12, t13, t15, t16, t01;
    t01 = a   & d  ;
    t02 = c   ^ t01;
    t03 = a   ^ d  ;
    t04 = b   & t02;
    t05 = a   & c  ;
    w.v = t03 ^ t04;
    t07 = a   & w.v;
    t08 = t01 ^ w.v;
    t09 = b   | t05;
    t10 =     ~ b  ;
    x.v = t08 ^ t09;
    t12 = t10 | t07;
    t13 = w.v | x.v;
    z.v = t02 ^ t12;
    t15 = t02 ^ t13;
    t16 = b   ^ d  ;
    y.v = t16 ^ t15;
  }
  private static void InvRND06(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t04, t05, t06, t07, t08, t09, t12, t13, t14, t15, t16, t17, t01;
    t01 = a   ^ c  ;
    t02 =     ~ c  ;
    t03 = b   & t01;
    t04 = b   | t02;
    t05 = d   | t03;
    t06 = b   ^ d  ;
    t07 = a   & t04;
    t08 = a   | t02;
    t09 = t07 ^ t05;
    x.v = t06 ^ t08;
    w.v =     ~ t09;
    t12 = b   & w.v;
    t13 = t01 & t05;
    t14 = t01 ^ t12;
    t15 = t07 ^ t13;
    t16 = d   | t02;
    t17 = a   ^ x.v;
    z.v = t17 ^ t15;
    y.v = t16 ^ t14;
  }
  private static void InvRND07(int a, int b, int c, int d, RefInt w, RefInt x, RefInt y, RefInt z) {
    int t02, t03, t04, t06, t07, t08, t09, t10, t11, t13, t14, t15, t16, t01;
    t01 = a   & b  ;
    t02 = a   | b  ;
    t03 = c   | t01;
    t04 = d   & t02;
    z.v = t03 ^ t04;
    t06 = b   ^ t04;
    t07 = d   ^ z.v;
    t08 =     ~ t07;
    t09 = t06 | t08;
    t10 = b   ^ d  ;
    t11 = a   | d  ;
    x.v = a   ^ t09;
    t13 = c   ^ t06;
    t14 = c   & t11;
    t15 = d   | x.v;
    t16 = t01 | t10;
    w.v = t13 ^ t15;
    y.v = t14 ^ t16;
  }

  private static void transform(int x0, int x1, int x2, int x3, RefInt y0, RefInt y1, RefInt y2, RefInt y3) {
    y0.v = ROL(x0, 13);
    y2.v = ROL(x2, 3);
    y1.v = x1 ^ y0.v ^ y2.v;
    y3.v = x3 ^ y2.v ^ (y0.v << 3);
    y1.v = ROL(y1.v, 1);
    y3.v = ROL(y3.v, 7);
    y0.v = y0.v ^ y1.v ^ y3.v;
    y2.v = y2.v ^ y3.v ^ (y1.v << 7);
    y0.v = ROL(y0.v, 5);
    y2.v = ROL(y2.v, 22);
  }
  private static void inv_transform(int x0, int x1, int x2, int x3, RefInt y0, RefInt y1, RefInt y2, RefInt y3) {
    y2.v = ROR(x2, 22);
    y0.v = ROR(x0, 5);
    y2.v = y2.v ^ x3 ^ (x1 << 7);
    y0.v = y0.v ^ x1 ^ x3;
    y3.v = ROR(x3, 7);
    y1.v = ROR(x1, 1);
    y3.v = y3.v ^ y2.v ^ (y0.v << 3);
    y1.v = y1.v ^ y0.v ^ y2.v;
    y2.v = ROR(y2.v, 3);
    y0.v = ROR(y0.v, 13);
  }

  private void keying(RefInt x0, RefInt x1, RefInt x2, RefInt x3, int idx) {
    x0.v ^= Subkeys[idx][0];
    x1.v ^= Subkeys[idx][1];
    x2.v ^= Subkeys[idx][2];
    x3.v ^= Subkeys[idx][3];
  }


  //
  // The following functions define the cipher implementation
  //

  protected void ExpandKey() {
    int[] w = new int [132];
    RefInt[] k = new RefInt [132];
    int keyLen = cipherKeySize * 8;
    int i, j;
    
    for (i = 0; i < k.length; i++) k[i] = new RefInt();

    FromBytes(w, 0, cipherKey, 0, cipherKeySize);
    i = cipherKeySize / 4;
    if (keyLen < 256) w[i] = (int)((cipherKey[i] & ((1 << ((keyLen & 31))) - 1)) | (1 << ((keyLen & 31))));
    for (i++; i < 8; i++) w[i] = 0;
    for (i = 8; i < 16; i++) w[i] = ROL(w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ (i - 8), 11);
    for (i = 0; i < 8; i++) w[i] = w[i + 8];
    for (i = 8; i < 132; i++) w[i] = ROL(w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ i, 11);

    RND03(w[  0], w[  1], w[  2], w[  3], k[  0], k[  1], k[  2], k[  3]);
    RND02(w[  4], w[  5], w[  6], w[  7], k[  4], k[  5], k[  6], k[  7]);
    RND01(w[  8], w[  9], w[ 10], w[ 11], k[  8], k[  9], k[ 10], k[ 11]);
    RND00(w[ 12], w[ 13], w[ 14], w[ 15], k[ 12], k[ 13], k[ 14], k[ 15]);
    RND07(w[ 16], w[ 17], w[ 18], w[ 19], k[ 16], k[ 17], k[ 18], k[ 19]);
    RND06(w[ 20], w[ 21], w[ 22], w[ 23], k[ 20], k[ 21], k[ 22], k[ 23]);
    RND05(w[ 24], w[ 25], w[ 26], w[ 27], k[ 24], k[ 25], k[ 26], k[ 27]);
    RND04(w[ 28], w[ 29], w[ 30], w[ 31], k[ 28], k[ 29], k[ 30], k[ 31]);
    RND03(w[ 32], w[ 33], w[ 34], w[ 35], k[ 32], k[ 33], k[ 34], k[ 35]);
    RND02(w[ 36], w[ 37], w[ 38], w[ 39], k[ 36], k[ 37], k[ 38], k[ 39]);
    RND01(w[ 40], w[ 41], w[ 42], w[ 43], k[ 40], k[ 41], k[ 42], k[ 43]);
    RND00(w[ 44], w[ 45], w[ 46], w[ 47], k[ 44], k[ 45], k[ 46], k[ 47]);
    RND07(w[ 48], w[ 49], w[ 50], w[ 51], k[ 48], k[ 49], k[ 50], k[ 51]);
    RND06(w[ 52], w[ 53], w[ 54], w[ 55], k[ 52], k[ 53], k[ 54], k[ 55]);
    RND05(w[ 56], w[ 57], w[ 58], w[ 59], k[ 56], k[ 57], k[ 58], k[ 59]);
    RND04(w[ 60], w[ 61], w[ 62], w[ 63], k[ 60], k[ 61], k[ 62], k[ 63]);
    RND03(w[ 64], w[ 65], w[ 66], w[ 67], k[ 64], k[ 65], k[ 66], k[ 67]);
    RND02(w[ 68], w[ 69], w[ 70], w[ 71], k[ 68], k[ 69], k[ 70], k[ 71]);
    RND01(w[ 72], w[ 73], w[ 74], w[ 75], k[ 72], k[ 73], k[ 74], k[ 75]);
    RND00(w[ 76], w[ 77], w[ 78], w[ 79], k[ 76], k[ 77], k[ 78], k[ 79]);
    RND07(w[ 80], w[ 81], w[ 82], w[ 83], k[ 80], k[ 81], k[ 82], k[ 83]);
    RND06(w[ 84], w[ 85], w[ 86], w[ 87], k[ 84], k[ 85], k[ 86], k[ 87]);
    RND05(w[ 88], w[ 89], w[ 90], w[ 91], k[ 88], k[ 89], k[ 90], k[ 91]);
    RND04(w[ 92], w[ 93], w[ 94], w[ 95], k[ 92], k[ 93], k[ 94], k[ 95]);
    RND03(w[ 96], w[ 97], w[ 98], w[ 99], k[ 96], k[ 97], k[ 98], k[ 99]);
    RND02(w[100], w[101], w[102], w[103], k[100], k[101], k[102], k[103]);
    RND01(w[104], w[105], w[106], w[107], k[104], k[105], k[106], k[107]);
    RND00(w[108], w[109], w[110], w[111], k[108], k[109], k[110], k[111]);
    RND07(w[112], w[113], w[114], w[115], k[112], k[113], k[114], k[115]);
    RND06(w[116], w[117], w[118], w[119], k[116], k[117], k[118], k[119]);
    RND05(w[120], w[121], w[122], w[123], k[120], k[121], k[122], k[123]);
    RND04(w[124], w[125], w[126], w[127], k[124], k[125], k[126], k[127]);
    RND03(w[128], w[129], w[130], w[131], k[128], k[129], k[130], k[131]);

    for (i = 0; i <= 32; i++)
      for (j = 0; j < 4; j++)
        Subkeys[i][j] = k[4 * i + j].v;
  }

  protected void EncryptBasicBlock(byte[] dst, int to, byte[] src, int from) {
    int[] x0 = new int [4];
    RefInt[] x = new RefInt [4];
    RefInt y0 = new RefInt();
    RefInt y1 = new RefInt();
    RefInt y2 = new RefInt();
    RefInt y3 = new RefInt();

    FromBytes(x0, 0, src, from, 16);
    for (int i = 0; i < 4; i++) {
    	x[i] = new RefInt();
    	x[i].v = x0[i]; 
    }

    keying(x[0], x[1], x[2], x[3], 0);
    RND00(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 1);
    RND01(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 2);
    RND02(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 3);
    RND03(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 4);
    RND04(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 5);
    RND05(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 6);
    RND06(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 7);
    RND07(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 8);
    RND00(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 9);
    RND01(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 10);
    RND02(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 11);
    RND03(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 12);
    RND04(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 13);
    RND05(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 14);
    RND06(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 15);
    RND07(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 16);
    RND00(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 17);
    RND01(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 18);
    RND02(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 19);
    RND03(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 20);
    RND04(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 21);
    RND05(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 22);
    RND06(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 23);
    RND07(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 24);
    RND00(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 25);
    RND01(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 26);
    RND02(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 27);
    RND03(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 28);
    RND04(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 29);
    RND05(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 30);
    RND06(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    keying(x[0], x[1], x[2], x[3], 31);
    RND07(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    x[0] = y0; x[1] = y1; x[2] = y2; x[3] = y3;
    keying(x[0], x[1], x[2], x[3], 32);

    for (int i = 0; i < 4; i++) x0[i] = x[i].v; 
    ToBytes(dst, to, x0, 0, 16);
  }

  protected void DecryptBasicBlock(byte[] dst, int to, byte[] src, int from) {
    int[] x0 = new int [4];
    RefInt[] x = new RefInt [4];
    RefInt y0 = new RefInt();
    RefInt y1 = new RefInt();
    RefInt y2 = new RefInt();
    RefInt y3 = new RefInt();

    FromBytes(x0, 0, src, from, 16);
    for (int i = 0; i < 4; i++) {
    	x[i] = new RefInt();
    	x[i].v = x0[i]; 
    }

    /* Start to decrypt the ciphertext x */
    keying(x[0], x[1], x[2], x[3], 32);
    InvRND07(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 31);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND06(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 30);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND05(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 29);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND04(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 28);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND03(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 27);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND02(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 26);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND01(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 25);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND00(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 24);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND07(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 23);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND06(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 22);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND05(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 21);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND04(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 20);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND03(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 19);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND02(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 18);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND01(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 17);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND00(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 16);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND07(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 15);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND06(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 14);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND05(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 13);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND04(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 12);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND03(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 11);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND02(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 10);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND01(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 9);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND00(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 8);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND07(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 7);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND06(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 6);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND05(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 5);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND04(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 4);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND03(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 3);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND02(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 2);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND01(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    keying(y0, y1, y2, y3, 1);
    inv_transform(y0.v, y1.v, y2.v, y3.v, x[0], x[1], x[2], x[3]);
    InvRND00(x[0].v, x[1].v, x[2].v, x[3].v, y0, y1, y2, y3);
    x[0] = y0; x[1] = y1; x[2] = y2; x[3] = y3;
    keying(x[0], x[1], x[2], x[3], 0);

    for (int i = 0; i < 4; i++) x0[i] = x[i].v; 
    ToBytes(dst, to, x0, 0, 16);
  }
}
