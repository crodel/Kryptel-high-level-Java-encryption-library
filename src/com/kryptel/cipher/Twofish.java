/*******************************************************************************

  Product:       Kryptel/Java
  File:          Twofish.java
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


import static com.kryptel.Guids.CID_CIPHER_TWOFISH;
import static com.kryptel.bslx.Conversions.FromBytes;
import static com.kryptel.bslx.Conversions.ToBytes;

import java.util.UUID;


final class Twofish extends BlockCipherBase {
	Twofish(long capabilities) {
		super(capabilities);

  	DEFAULT_KEY_SIZE = 32;
  	DEFAULT_BLOCK_SIZE = BLOCK_SIZE;
  	DEFAULT_ROUNDS = MAX_ROUNDS;
  	DEFAULT_SCHEME = 1;

  	cipherInfo = new CipherInfo(
  			new int[] { 16, 24, 32 },			// Key sizes
  			new int[] { BLOCK_SIZE },			// Block sizes
  			new int[] { MAX_ROUNDS },			// Rounds
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
	public String ComponentName() { return "Twofish"; }

	
  //
  // Private data and methods
  //

  static UUID componentID = CID_CIPHER_TWOFISH;

  private static final int MAX_KEY_SIZE = 32;
  private static final int MAX_ROUNDS = 16;
  private static final int BLOCK_SIZE = 16;


  private static int[][] MDS = {
   {0xBCBC3275, 0xECEC21F3, 0x202043C6, 0xB3B3C9F4, 0xDADA03DB, 0x02028B7B, 0xE2E22BFB, 0x9E9EFAC8,
    0xC9C9EC4A, 0xD4D409D3, 0x18186BE6, 0x1E1E9F6B, 0x98980E45, 0xB2B2387D, 0xA6A6D2E8, 0x2626B74B,
    0x3C3C57D6, 0x93938A32, 0x8282EED8, 0x525298FD, 0x7B7BD437, 0xBBBB3771, 0x5B5B97F1, 0x474783E1,
    0x24243C30, 0x5151E20F, 0xBABAC6F8, 0x4A4AF31B, 0xBFBF4887, 0x0D0D70FA, 0xB0B0B306, 0x7575DE3F,
    0xD2D2FD5E, 0x7D7D20BA, 0x666631AE, 0x3A3AA35B, 0x59591C8A, 0x00000000, 0xCDCD93BC, 0x1A1AE09D,
    0xAEAE2C6D, 0x7F7FABC1, 0x2B2BC7B1, 0xBEBEB90E, 0xE0E0A080, 0x8A8A105D, 0x3B3B52D2, 0x6464BAD5,
    0xD8D888A0, 0xE7E7A584, 0x5F5FE807, 0x1B1B1114, 0x2C2CC2B5, 0xFCFCB490, 0x3131272C, 0x808065A3,
    0x73732AB2, 0x0C0C8173, 0x79795F4C, 0x6B6B4154, 0x4B4B0292, 0x53536974, 0x94948F36, 0x83831F51,
    0x2A2A3638, 0xC4C49CB0, 0x2222C8BD, 0xD5D5F85A, 0xBDBDC3FC, 0x48487860, 0xFFFFCE62, 0x4C4C0796,
    0x4141776C, 0xC7C7E642, 0xEBEB24F7, 0x1C1C1410, 0x5D5D637C, 0x36362228, 0x6767C027, 0xE9E9AF8C,
    0x4444F913, 0x1414EA95, 0xF5F5BB9C, 0xCFCF18C7, 0x3F3F2D24, 0xC0C0E346, 0x7272DB3B, 0x54546C70,
    0x29294CCA, 0xF0F035E3, 0x0808FE85, 0xC6C617CB, 0xF3F34F11, 0x8C8CE4D0, 0xA4A45993, 0xCACA96B8,
    0x68683BA6, 0xB8B84D83, 0x38382820, 0xE5E52EFF, 0xADAD569F, 0x0B0B8477, 0xC8C81DC3, 0x9999FFCC,
    0x5858ED03, 0x19199A6F, 0x0E0E0A08, 0x95957EBF, 0x70705040, 0xF7F730E7, 0x6E6ECF2B, 0x1F1F6EE2,
    0xB5B53D79, 0x09090F0C, 0x616134AA, 0x57571682, 0x9F9F0B41, 0x9D9D803A, 0x111164EA, 0x2525CDB9,
    0xAFAFDDE4, 0x4545089A, 0xDFDF8DA4, 0xA3A35C97, 0xEAEAD57E, 0x353558DA, 0xEDEDD07A, 0x4343FC17,
    0xF8F8CB66, 0xFBFBB194, 0x3737D3A1, 0xFAFA401D, 0xC2C2683D, 0xB4B4CCF0, 0x32325DDE, 0x9C9C71B3,
    0x5656E70B, 0xE3E3DA72, 0x878760A7, 0x15151B1C, 0xF9F93AEF, 0x6363BFD1, 0x3434A953, 0x9A9A853E,
    0xB1B1428F, 0x7C7CD133, 0x88889B26, 0x3D3DA65F, 0xA1A1D7EC, 0xE4E4DF76, 0x8181942A, 0x91910149,
    0x0F0FFB81, 0xEEEEAA88, 0x161661EE, 0xD7D77321, 0x9797F5C4, 0xA5A5A81A, 0xFEFE3FEB, 0x6D6DB5D9,
    0x7878AEC5, 0xC5C56D39, 0x1D1DE599, 0x7676A4CD, 0x3E3EDCAD, 0xCBCB6731, 0xB6B6478B, 0xEFEF5B01,
    0x12121E18, 0x6060C523, 0x6A6AB0DD, 0x4D4DF61F, 0xCECEE94E, 0xDEDE7C2D, 0x55559DF9, 0x7E7E5A48,
    0x2121B24F, 0x03037AF2, 0xA0A02665, 0x5E5E198E, 0x5A5A6678, 0x65654B5C, 0x62624E58, 0xFDFD4519,
    0x0606F48D, 0x404086E5, 0xF2F2BE98, 0x3333AC57, 0x17179067, 0x05058E7F, 0xE8E85E05, 0x4F4F7D64,
    0x89896AAF, 0x10109563, 0x74742FB6, 0x0A0A75FE, 0x5C5C92F5, 0x9B9B74B7, 0x2D2D333C, 0x3030D6A5,
    0x2E2E49CE, 0x494989E9, 0x46467268, 0x77775544, 0xA8A8D8E0, 0x9696044D, 0x2828BD43, 0xA9A92969,
    0xD9D97929, 0x8686912E, 0xD1D187AC, 0xF4F44A15, 0x8D8D1559, 0xD6D682A8, 0xB9B9BC0A, 0x42420D9E,
    0xF6F6C16E, 0x2F2FB847, 0xDDDD06DF, 0x23233934, 0xCCCC6235, 0xF1F1C46A, 0xC1C112CF, 0x8585EBDC,
    0x8F8F9E22, 0x7171A1C9, 0x9090F0C0, 0xAAAA539B, 0x0101F189, 0x8B8BE1D4, 0x4E4E8CED, 0x8E8E6FAB,
    0xABABA212, 0x6F6F3EA2, 0xE6E6540D, 0xDBDBF252, 0x92927BBB, 0xB7B7B602, 0x6969CA2F, 0x3939D9A9,
    0xD3D30CD7, 0xA7A72361, 0xA2A2AD1E, 0xC3C399B4, 0x6C6C4450, 0x07070504, 0x04047FF6, 0x272746C2,
    0xACACA716, 0xD0D07625, 0x50501386, 0xDCDCF756, 0x84841A55, 0xE1E15109, 0x7A7A25BE, 0x1313EF91},

   {0xA9D93939, 0x67901717, 0xB3719C9C, 0xE8D2A6A6, 0x04050707, 0xFD985252, 0xA3658080, 0x76DFE4E4,
    0x9A084545, 0x92024B4B, 0x80A0E0E0, 0x78665A5A, 0xE4DDAFAF, 0xDDB06A6A, 0xD1BF6363, 0x38362A2A,
    0x0D54E6E6, 0xC6432020, 0x3562CCCC, 0x98BEF2F2, 0x181E1212, 0xF724EBEB, 0xECD7A1A1, 0x6C774141,
    0x43BD2828, 0x7532BCBC, 0x37D47B7B, 0x269B8888, 0xFA700D0D, 0x13F94444, 0x94B1FBFB, 0x485A7E7E,
    0xF27A0303, 0xD0E48C8C, 0x8B47B6B6, 0x303C2424, 0x84A5E7E7, 0x54416B6B, 0xDF06DDDD, 0x23C56060,
    0x1945FDFD, 0x5BA33A3A, 0x3D68C2C2, 0x59158D8D, 0xF321ECEC, 0xAE316666, 0xA23E6F6F, 0x82165757,
    0x63951010, 0x015BEFEF, 0x834DB8B8, 0x2E918686, 0xD9B56D6D, 0x511F8383, 0x9B53AAAA, 0x7C635D5D,
    0xA63B6868, 0xEB3FFEFE, 0xA5D63030, 0xBE257A7A, 0x16A7ACAC, 0x0C0F0909, 0xE335F0F0, 0x6123A7A7,
    0xC0F09090, 0x8CAFE9E9, 0x3A809D9D, 0xF5925C5C, 0x73810C0C, 0x2C273131, 0x2576D0D0, 0x0BE75656,
    0xBB7B9292, 0x4EE9CECE, 0x89F10101, 0x6B9F1E1E, 0x53A93434, 0x6AC4F1F1, 0xB499C3C3, 0xF1975B5B,
    0xE1834747, 0xE66B1818, 0xBDC82222, 0x450E9898, 0xE26E1F1F, 0xF4C9B3B3, 0xB62F7474, 0x66CBF8F8,
    0xCCFF9999, 0x95EA1414, 0x03ED5858, 0x56F7DCDC, 0xD4E18B8B, 0x1C1B1515, 0x1EADA2A2, 0xD70CD3D3,
    0xFB2BE2E2, 0xC31DC8C8, 0x8E195E5E, 0xB5C22C2C, 0xE9894949, 0xCF12C1C1, 0xBF7E9595, 0xBA207D7D,
    0xEA641111, 0x77840B0B, 0x396DC5C5, 0xAF6A8989, 0x33D17C7C, 0xC9A17171, 0x62CEFFFF, 0x7137BBBB,
    0x81FB0F0F, 0x793DB5B5, 0x0951E1E1, 0xADDC3E3E, 0x242D3F3F, 0xCDA47676, 0xF99D5555, 0xD8EE8282,
    0xE5864040, 0xC5AE7878, 0xB9CD2525, 0x4D049696, 0x44557777, 0x080A0E0E, 0x86135050, 0xE730F7F7,
    0xA1D33737, 0x1D40FAFA, 0xAA346161, 0xED8C4E4E, 0x06B3B0B0, 0x706C5454, 0xB22A7373, 0xD2523B3B,
    0x410B9F9F, 0x7B8B0202, 0xA088D8D8, 0x114FF3F3, 0x3167CBCB, 0xC2462727, 0x27C06767, 0x90B4FCFC,
    0x20283838, 0xF67F0404, 0x60784848, 0xFF2EE5E5, 0x96074C4C, 0x5C4B6565, 0xB1C72B2B, 0xAB6F8E8E,
    0x9E0D4242, 0x9CBBF5F5, 0x52F2DBDB, 0x1BF34A4A, 0x5FA63D3D, 0x9359A4A4, 0x0ABCB9B9, 0xEF3AF9F9,
    0x91EF1313, 0x85FE0808, 0x49019191, 0xEE611616, 0x2D7CDEDE, 0x4FB22121, 0x8F42B1B1, 0x3BDB7272,
    0x47B82F2F, 0x8748BFBF, 0x6D2CAEAE, 0x46E3C0C0, 0xD6573C3C, 0x3E859A9A, 0x6929A9A9, 0x647D4F4F,
    0x2A948181, 0xCE492E2E, 0xCB17C6C6, 0x2FCA6969, 0xFCC3BDBD, 0x975CA3A3, 0x055EE8E8, 0x7AD0EDED,
    0xAC87D1D1, 0x7F8E0505, 0xD5BA6464, 0x1AA8A5A5, 0x4BB72626, 0x0EB9BEBE, 0xA7608787, 0x5AF8D5D5,
    0x28223636, 0x14111B1B, 0x3FDE7575, 0x2979D9D9, 0x88AAEEEE, 0x3C332D2D, 0x4C5F7979, 0x02B6B7B7,
    0xB896CACA, 0xDA583535, 0xB09CC4C4, 0x17FC4343, 0x551A8484, 0x1FF64D4D, 0x8A1C5959, 0x7D38B2B2,
    0x57AC3333, 0xC718CFCF, 0x8DF40606, 0x74695353, 0xB7749B9B, 0xC4F59797, 0x9F56ADAD, 0x72DAE3E3,
    0x7ED5EAEA, 0x154AF4F4, 0x229E8F8F, 0x12A2ABAB, 0x584E6262, 0x07E85F5F, 0x99E51D1D, 0x34392323,
    0x6EC1F6F6, 0x50446C6C, 0xDE5D3232, 0x68724646, 0x6526A0A0, 0xBC93CDCD, 0xDB03DADA, 0xF8C6BABA,
    0xC8FA9E9E, 0xA882D6D6, 0x2BCF6E6E, 0x40507070, 0xDCEB8585, 0xFE750A0A, 0x328A9393, 0xA48DDFDF,
    0xCA4C2929, 0x10141C1C, 0x2173D7D7, 0xF0CCB4B4, 0xD309D4D4, 0x5D108A8A, 0x0FE25151, 0x00000000,
    0x6F9A1919, 0x9DE01A1A, 0x368F9494, 0x42E6C7C7, 0x4AECC9C9, 0x5EFDD2D2, 0xC1AB7F7F, 0xE0D8A8A8},

   {0xBC75BC32, 0xECF3EC21, 0x20C62043, 0xB3F4B3C9, 0xDADBDA03, 0x027B028B, 0xE2FBE22B, 0x9EC89EFA,
    0xC94AC9EC, 0xD4D3D409, 0x18E6186B, 0x1E6B1E9F, 0x9845980E, 0xB27DB238, 0xA6E8A6D2, 0x264B26B7,
    0x3CD63C57, 0x9332938A, 0x82D882EE, 0x52FD5298, 0x7B377BD4, 0xBB71BB37, 0x5BF15B97, 0x47E14783,
    0x2430243C, 0x510F51E2, 0xBAF8BAC6, 0x4A1B4AF3, 0xBF87BF48, 0x0DFA0D70, 0xB006B0B3, 0x753F75DE,
    0xD25ED2FD, 0x7DBA7D20, 0x66AE6631, 0x3A5B3AA3, 0x598A591C, 0x00000000, 0xCDBCCD93, 0x1A9D1AE0,
    0xAE6DAE2C, 0x7FC17FAB, 0x2BB12BC7, 0xBE0EBEB9, 0xE080E0A0, 0x8A5D8A10, 0x3BD23B52, 0x64D564BA,
    0xD8A0D888, 0xE784E7A5, 0x5F075FE8, 0x1B141B11, 0x2CB52CC2, 0xFC90FCB4, 0x312C3127, 0x80A38065,
    0x73B2732A, 0x0C730C81, 0x794C795F, 0x6B546B41, 0x4B924B02, 0x53745369, 0x9436948F, 0x8351831F,
    0x2A382A36, 0xC4B0C49C, 0x22BD22C8, 0xD55AD5F8, 0xBDFCBDC3, 0x48604878, 0xFF62FFCE, 0x4C964C07,
    0x416C4177, 0xC742C7E6, 0xEBF7EB24, 0x1C101C14, 0x5D7C5D63, 0x36283622, 0x672767C0, 0xE98CE9AF,
    0x441344F9, 0x149514EA, 0xF59CF5BB, 0xCFC7CF18, 0x3F243F2D, 0xC046C0E3, 0x723B72DB, 0x5470546C,
    0x29CA294C, 0xF0E3F035, 0x088508FE, 0xC6CBC617, 0xF311F34F, 0x8CD08CE4, 0xA493A459, 0xCAB8CA96,
    0x68A6683B, 0xB883B84D, 0x38203828, 0xE5FFE52E, 0xAD9FAD56, 0x0B770B84, 0xC8C3C81D, 0x99CC99FF,
    0x580358ED, 0x196F199A, 0x0E080E0A, 0x95BF957E, 0x70407050, 0xF7E7F730, 0x6E2B6ECF, 0x1FE21F6E,
    0xB579B53D, 0x090C090F, 0x61AA6134, 0x57825716, 0x9F419F0B, 0x9D3A9D80, 0x11EA1164, 0x25B925CD,
    0xAFE4AFDD, 0x459A4508, 0xDFA4DF8D, 0xA397A35C, 0xEA7EEAD5, 0x35DA3558, 0xED7AEDD0, 0x431743FC,
    0xF866F8CB, 0xFB94FBB1, 0x37A137D3, 0xFA1DFA40, 0xC23DC268, 0xB4F0B4CC, 0x32DE325D, 0x9CB39C71,
    0x560B56E7, 0xE372E3DA, 0x87A78760, 0x151C151B, 0xF9EFF93A, 0x63D163BF, 0x345334A9, 0x9A3E9A85,
    0xB18FB142, 0x7C337CD1, 0x8826889B, 0x3D5F3DA6, 0xA1ECA1D7, 0xE476E4DF, 0x812A8194, 0x91499101,
    0x0F810FFB, 0xEE88EEAA, 0x16EE1661, 0xD721D773, 0x97C497F5, 0xA51AA5A8, 0xFEEBFE3F, 0x6DD96DB5,
    0x78C578AE, 0xC539C56D, 0x1D991DE5, 0x76CD76A4, 0x3EAD3EDC, 0xCB31CB67, 0xB68BB647, 0xEF01EF5B,
    0x1218121E, 0x602360C5, 0x6ADD6AB0, 0x4D1F4DF6, 0xCE4ECEE9, 0xDE2DDE7C, 0x55F9559D, 0x7E487E5A,
    0x214F21B2, 0x03F2037A, 0xA065A026, 0x5E8E5E19, 0x5A785A66, 0x655C654B, 0x6258624E, 0xFD19FD45,
    0x068D06F4, 0x40E54086, 0xF298F2BE, 0x335733AC, 0x17671790, 0x057F058E, 0xE805E85E, 0x4F644F7D,
    0x89AF896A, 0x10631095, 0x74B6742F, 0x0AFE0A75, 0x5CF55C92, 0x9BB79B74, 0x2D3C2D33, 0x30A530D6,
    0x2ECE2E49, 0x49E94989, 0x46684672, 0x77447755, 0xA8E0A8D8, 0x964D9604, 0x284328BD, 0xA969A929,
    0xD929D979, 0x862E8691, 0xD1ACD187, 0xF415F44A, 0x8D598D15, 0xD6A8D682, 0xB90AB9BC, 0x429E420D,
    0xF66EF6C1, 0x2F472FB8, 0xDDDFDD06, 0x23342339, 0xCC35CC62, 0xF16AF1C4, 0xC1CFC112, 0x85DC85EB,
    0x8F228F9E, 0x71C971A1, 0x90C090F0, 0xAA9BAA53, 0x018901F1, 0x8BD48BE1, 0x4EED4E8C, 0x8EAB8E6F,
    0xAB12ABA2, 0x6FA26F3E, 0xE60DE654, 0xDB52DBF2, 0x92BB927B, 0xB702B7B6, 0x692F69CA, 0x39A939D9,
    0xD3D7D30C, 0xA761A723, 0xA21EA2AD, 0xC3B4C399, 0x6C506C44, 0x07040705, 0x04F6047F, 0x27C22746,
    0xAC16ACA7, 0xD025D076, 0x50865013, 0xDC56DCF7, 0x8455841A, 0xE109E151, 0x7ABE7A25, 0x139113EF},

   {0xD939A9D9, 0x90176790, 0x719CB371, 0xD2A6E8D2, 0x05070405, 0x9852FD98, 0x6580A365, 0xDFE476DF,
    0x08459A08, 0x024B9202, 0xA0E080A0, 0x665A7866, 0xDDAFE4DD, 0xB06ADDB0, 0xBF63D1BF, 0x362A3836,
    0x54E60D54, 0x4320C643, 0x62CC3562, 0xBEF298BE, 0x1E12181E, 0x24EBF724, 0xD7A1ECD7, 0x77416C77,
    0xBD2843BD, 0x32BC7532, 0xD47B37D4, 0x9B88269B, 0x700DFA70, 0xF94413F9, 0xB1FB94B1, 0x5A7E485A,
    0x7A03F27A, 0xE48CD0E4, 0x47B68B47, 0x3C24303C, 0xA5E784A5, 0x416B5441, 0x06DDDF06, 0xC56023C5,
    0x45FD1945, 0xA33A5BA3, 0x68C23D68, 0x158D5915, 0x21ECF321, 0x3166AE31, 0x3E6FA23E, 0x16578216,
    0x95106395, 0x5BEF015B, 0x4DB8834D, 0x91862E91, 0xB56DD9B5, 0x1F83511F, 0x53AA9B53, 0x635D7C63,
    0x3B68A63B, 0x3FFEEB3F, 0xD630A5D6, 0x257ABE25, 0xA7AC16A7, 0x0F090C0F, 0x35F0E335, 0x23A76123,
    0xF090C0F0, 0xAFE98CAF, 0x809D3A80, 0x925CF592, 0x810C7381, 0x27312C27, 0x76D02576, 0xE7560BE7,
    0x7B92BB7B, 0xE9CE4EE9, 0xF10189F1, 0x9F1E6B9F, 0xA93453A9, 0xC4F16AC4, 0x99C3B499, 0x975BF197,
    0x8347E183, 0x6B18E66B, 0xC822BDC8, 0x0E98450E, 0x6E1FE26E, 0xC9B3F4C9, 0x2F74B62F, 0xCBF866CB,
    0xFF99CCFF, 0xEA1495EA, 0xED5803ED, 0xF7DC56F7, 0xE18BD4E1, 0x1B151C1B, 0xADA21EAD, 0x0CD3D70C,
    0x2BE2FB2B, 0x1DC8C31D, 0x195E8E19, 0xC22CB5C2, 0x8949E989, 0x12C1CF12, 0x7E95BF7E, 0x207DBA20,
    0x6411EA64, 0x840B7784, 0x6DC5396D, 0x6A89AF6A, 0xD17C33D1, 0xA171C9A1, 0xCEFF62CE, 0x37BB7137,
    0xFB0F81FB, 0x3DB5793D, 0x51E10951, 0xDC3EADDC, 0x2D3F242D, 0xA476CDA4, 0x9D55F99D, 0xEE82D8EE,
    0x8640E586, 0xAE78C5AE, 0xCD25B9CD, 0x04964D04, 0x55774455, 0x0A0E080A, 0x13508613, 0x30F7E730,
    0xD337A1D3, 0x40FA1D40, 0x3461AA34, 0x8C4EED8C, 0xB3B006B3, 0x6C54706C, 0x2A73B22A, 0x523BD252,
    0x0B9F410B, 0x8B027B8B, 0x88D8A088, 0x4FF3114F, 0x67CB3167, 0x4627C246, 0xC06727C0, 0xB4FC90B4,
    0x28382028, 0x7F04F67F, 0x78486078, 0x2EE5FF2E, 0x074C9607, 0x4B655C4B, 0xC72BB1C7, 0x6F8EAB6F,
    0x0D429E0D, 0xBBF59CBB, 0xF2DB52F2, 0xF34A1BF3, 0xA63D5FA6, 0x59A49359, 0xBCB90ABC, 0x3AF9EF3A,
    0xEF1391EF, 0xFE0885FE, 0x01914901, 0x6116EE61, 0x7CDE2D7C, 0xB2214FB2, 0x42B18F42, 0xDB723BDB,
    0xB82F47B8, 0x48BF8748, 0x2CAE6D2C, 0xE3C046E3, 0x573CD657, 0x859A3E85, 0x29A96929, 0x7D4F647D,
    0x94812A94, 0x492ECE49, 0x17C6CB17, 0xCA692FCA, 0xC3BDFCC3, 0x5CA3975C, 0x5EE8055E, 0xD0ED7AD0,
    0x87D1AC87, 0x8E057F8E, 0xBA64D5BA, 0xA8A51AA8, 0xB7264BB7, 0xB9BE0EB9, 0x6087A760, 0xF8D55AF8,
    0x22362822, 0x111B1411, 0xDE753FDE, 0x79D92979, 0xAAEE88AA, 0x332D3C33, 0x5F794C5F, 0xB6B702B6,
    0x96CAB896, 0x5835DA58, 0x9CC4B09C, 0xFC4317FC, 0x1A84551A, 0xF64D1FF6, 0x1C598A1C, 0x38B27D38,
    0xAC3357AC, 0x18CFC718, 0xF4068DF4, 0x69537469, 0x749BB774, 0xF597C4F5, 0x56AD9F56, 0xDAE372DA,
    0xD5EA7ED5, 0x4AF4154A, 0x9E8F229E, 0xA2AB12A2, 0x4E62584E, 0xE85F07E8, 0xE51D99E5, 0x39233439,
    0xC1F66EC1, 0x446C5044, 0x5D32DE5D, 0x72466872, 0x26A06526, 0x93CDBC93, 0x03DADB03, 0xC6BAF8C6,
    0xFA9EC8FA, 0x82D6A882, 0xCF6E2BCF, 0x50704050, 0xEB85DCEB, 0x750AFE75, 0x8A93328A, 0x8DDFA48D,
    0x4C29CA4C, 0x141C1014, 0x73D72173, 0xCCB4F0CC, 0x09D4D309, 0x108A5D10, 0xE2510FE2, 0x00000000,
    0x9A196F9A, 0xE01A9DE0, 0x8F94368F, 0xE6C742E6, 0xECC94AEC, 0xFDD25EFD, 0xAB7FC1AB, 0xD8A8E0D8}};

  private static byte[][] P8x8 = {
   {(byte)0xA9, (byte)0x67, (byte)0xB3, (byte)0xE8, (byte)0x04, (byte)0xFD, (byte)0xA3, (byte)0x76, 
    (byte)0x9A, (byte)0x92, (byte)0x80, (byte)0x78, (byte)0xE4, (byte)0xDD, (byte)0xD1, (byte)0x38, 
    (byte)0x0D, (byte)0xC6, (byte)0x35, (byte)0x98, (byte)0x18, (byte)0xF7, (byte)0xEC, (byte)0x6C, 
    (byte)0x43, (byte)0x75, (byte)0x37, (byte)0x26, (byte)0xFA, (byte)0x13, (byte)0x94, (byte)0x48, 
    (byte)0xF2, (byte)0xD0, (byte)0x8B, (byte)0x30, (byte)0x84, (byte)0x54, (byte)0xDF, (byte)0x23, 
    (byte)0x19, (byte)0x5B, (byte)0x3D, (byte)0x59, (byte)0xF3, (byte)0xAE, (byte)0xA2, (byte)0x82, 
    (byte)0x63, (byte)0x01, (byte)0x83, (byte)0x2E, (byte)0xD9, (byte)0x51, (byte)0x9B, (byte)0x7C, 
    (byte)0xA6, (byte)0xEB, (byte)0xA5, (byte)0xBE, (byte)0x16, (byte)0x0C, (byte)0xE3, (byte)0x61, 
    (byte)0xC0, (byte)0x8C, (byte)0x3A, (byte)0xF5, (byte)0x73, (byte)0x2C, (byte)0x25, (byte)0x0B, 
    (byte)0xBB, (byte)0x4E, (byte)0x89, (byte)0x6B, (byte)0x53, (byte)0x6A, (byte)0xB4, (byte)0xF1, 
    (byte)0xE1, (byte)0xE6, (byte)0xBD, (byte)0x45, (byte)0xE2, (byte)0xF4, (byte)0xB6, (byte)0x66, 
    (byte)0xCC, (byte)0x95, (byte)0x03, (byte)0x56, (byte)0xD4, (byte)0x1C, (byte)0x1E, (byte)0xD7, 
    (byte)0xFB, (byte)0xC3, (byte)0x8E, (byte)0xB5, (byte)0xE9, (byte)0xCF, (byte)0xBF, (byte)0xBA, 
    (byte)0xEA, (byte)0x77, (byte)0x39, (byte)0xAF, (byte)0x33, (byte)0xC9, (byte)0x62, (byte)0x71, 
    (byte)0x81, (byte)0x79, (byte)0x09, (byte)0xAD, (byte)0x24, (byte)0xCD, (byte)0xF9, (byte)0xD8, 
    (byte)0xE5, (byte)0xC5, (byte)0xB9, (byte)0x4D, (byte)0x44, (byte)0x08, (byte)0x86, (byte)0xE7, 
    (byte)0xA1, (byte)0x1D, (byte)0xAA, (byte)0xED, (byte)0x06, (byte)0x70, (byte)0xB2, (byte)0xD2, 
    (byte)0x41, (byte)0x7B, (byte)0xA0, (byte)0x11, (byte)0x31, (byte)0xC2, (byte)0x27, (byte)0x90, 
    (byte)0x20, (byte)0xF6, (byte)0x60, (byte)0xFF, (byte)0x96, (byte)0x5C, (byte)0xB1, (byte)0xAB, 
    (byte)0x9E, (byte)0x9C, (byte)0x52, (byte)0x1B, (byte)0x5F, (byte)0x93, (byte)0x0A, (byte)0xEF, 
    (byte)0x91, (byte)0x85, (byte)0x49, (byte)0xEE, (byte)0x2D, (byte)0x4F, (byte)0x8F, (byte)0x3B, 
    (byte)0x47, (byte)0x87, (byte)0x6D, (byte)0x46, (byte)0xD6, (byte)0x3E, (byte)0x69, (byte)0x64, 
    (byte)0x2A, (byte)0xCE, (byte)0xCB, (byte)0x2F, (byte)0xFC, (byte)0x97, (byte)0x05, (byte)0x7A, 
    (byte)0xAC, (byte)0x7F, (byte)0xD5, (byte)0x1A, (byte)0x4B, (byte)0x0E, (byte)0xA7, (byte)0x5A, 
    (byte)0x28, (byte)0x14, (byte)0x3F, (byte)0x29, (byte)0x88, (byte)0x3C, (byte)0x4C, (byte)0x02, 
    (byte)0xB8, (byte)0xDA, (byte)0xB0, (byte)0x17, (byte)0x55, (byte)0x1F, (byte)0x8A, (byte)0x7D, 
    (byte)0x57, (byte)0xC7, (byte)0x8D, (byte)0x74, (byte)0xB7, (byte)0xC4, (byte)0x9F, (byte)0x72, 
    (byte)0x7E, (byte)0x15, (byte)0x22, (byte)0x12, (byte)0x58, (byte)0x07, (byte)0x99, (byte)0x34, 
    (byte)0x6E, (byte)0x50, (byte)0xDE, (byte)0x68, (byte)0x65, (byte)0xBC, (byte)0xDB, (byte)0xF8, 
    (byte)0xC8, (byte)0xA8, (byte)0x2B, (byte)0x40, (byte)0xDC, (byte)0xFE, (byte)0x32, (byte)0xA4, 
    (byte)0xCA, (byte)0x10, (byte)0x21, (byte)0xF0, (byte)0xD3, (byte)0x5D, (byte)0x0F, (byte)0x00, 
    (byte)0x6F, (byte)0x9D, (byte)0x36, (byte)0x42, (byte)0x4A, (byte)0x5E, (byte)0xC1, (byte)0xE0},

   {(byte)0x75, (byte)0xF3, (byte)0xC6, (byte)0xF4, (byte)0xDB, (byte)0x7B, (byte)0xFB, (byte)0xC8, 
    (byte)0x4A, (byte)0xD3, (byte)0xE6, (byte)0x6B, (byte)0x45, (byte)0x7D, (byte)0xE8, (byte)0x4B, 
    (byte)0xD6, (byte)0x32, (byte)0xD8, (byte)0xFD, (byte)0x37, (byte)0x71, (byte)0xF1, (byte)0xE1, 
    (byte)0x30, (byte)0x0F, (byte)0xF8, (byte)0x1B, (byte)0x87, (byte)0xFA, (byte)0x06, (byte)0x3F, 
    (byte)0x5E, (byte)0xBA, (byte)0xAE, (byte)0x5B, (byte)0x8A, (byte)0x00, (byte)0xBC, (byte)0x9D, 
    (byte)0x6D, (byte)0xC1, (byte)0xB1, (byte)0x0E, (byte)0x80, (byte)0x5D, (byte)0xD2, (byte)0xD5, 
    (byte)0xA0, (byte)0x84, (byte)0x07, (byte)0x14, (byte)0xB5, (byte)0x90, (byte)0x2C, (byte)0xA3, 
    (byte)0xB2, (byte)0x73, (byte)0x4C, (byte)0x54, (byte)0x92, (byte)0x74, (byte)0x36, (byte)0x51, 
    (byte)0x38, (byte)0xB0, (byte)0xBD, (byte)0x5A, (byte)0xFC, (byte)0x60, (byte)0x62, (byte)0x96, 
    (byte)0x6C, (byte)0x42, (byte)0xF7, (byte)0x10, (byte)0x7C, (byte)0x28, (byte)0x27, (byte)0x8C, 
    (byte)0x13, (byte)0x95, (byte)0x9C, (byte)0xC7, (byte)0x24, (byte)0x46, (byte)0x3B, (byte)0x70, 
    (byte)0xCA, (byte)0xE3, (byte)0x85, (byte)0xCB, (byte)0x11, (byte)0xD0, (byte)0x93, (byte)0xB8, 
    (byte)0xA6, (byte)0x83, (byte)0x20, (byte)0xFF, (byte)0x9F, (byte)0x77, (byte)0xC3, (byte)0xCC, 
    (byte)0x03, (byte)0x6F, (byte)0x08, (byte)0xBF, (byte)0x40, (byte)0xE7, (byte)0x2B, (byte)0xE2, 
    (byte)0x79, (byte)0x0C, (byte)0xAA, (byte)0x82, (byte)0x41, (byte)0x3A, (byte)0xEA, (byte)0xB9, 
    (byte)0xE4, (byte)0x9A, (byte)0xA4, (byte)0x97, (byte)0x7E, (byte)0xDA, (byte)0x7A, (byte)0x17, 
    (byte)0x66, (byte)0x94, (byte)0xA1, (byte)0x1D, (byte)0x3D, (byte)0xF0, (byte)0xDE, (byte)0xB3, 
    (byte)0x0B, (byte)0x72, (byte)0xA7, (byte)0x1C, (byte)0xEF, (byte)0xD1, (byte)0x53, (byte)0x3E, 
    (byte)0x8F, (byte)0x33, (byte)0x26, (byte)0x5F, (byte)0xEC, (byte)0x76, (byte)0x2A, (byte)0x49, 
    (byte)0x81, (byte)0x88, (byte)0xEE, (byte)0x21, (byte)0xC4, (byte)0x1A, (byte)0xEB, (byte)0xD9, 
    (byte)0xC5, (byte)0x39, (byte)0x99, (byte)0xCD, (byte)0xAD, (byte)0x31, (byte)0x8B, (byte)0x01, 
    (byte)0x18, (byte)0x23, (byte)0xDD, (byte)0x1F, (byte)0x4E, (byte)0x2D, (byte)0xF9, (byte)0x48, 
    (byte)0x4F, (byte)0xF2, (byte)0x65, (byte)0x8E, (byte)0x78, (byte)0x5C, (byte)0x58, (byte)0x19, 
    (byte)0x8D, (byte)0xE5, (byte)0x98, (byte)0x57, (byte)0x67, (byte)0x7F, (byte)0x05, (byte)0x64, 
    (byte)0xAF, (byte)0x63, (byte)0xB6, (byte)0xFE, (byte)0xF5, (byte)0xB7, (byte)0x3C, (byte)0xA5, 
    (byte)0xCE, (byte)0xE9, (byte)0x68, (byte)0x44, (byte)0xE0, (byte)0x4D, (byte)0x43, (byte)0x69, 
    (byte)0x29, (byte)0x2E, (byte)0xAC, (byte)0x15, (byte)0x59, (byte)0xA8, (byte)0x0A, (byte)0x9E, 
    (byte)0x6E, (byte)0x47, (byte)0xDF, (byte)0x34, (byte)0x35, (byte)0x6A, (byte)0xCF, (byte)0xDC, 
    (byte)0x22, (byte)0xC9, (byte)0xC0, (byte)0x9B, (byte)0x89, (byte)0xD4, (byte)0xED, (byte)0xAB, 
    (byte)0x12, (byte)0xA2, (byte)0x0D, (byte)0x52, (byte)0xBB, (byte)0x02, (byte)0x2F, (byte)0xA9, 
    (byte)0xD7, (byte)0x61, (byte)0x1E, (byte)0xB4, (byte)0x50, (byte)0x04, (byte)0xF6, (byte)0xC2, 
    (byte)0x16, (byte)0x25, (byte)0x86, (byte)0x56, (byte)0x55, (byte)0x09, (byte)0xBE, (byte)0x91}};

  
  // Constants for subkeys computing
  private static final int SK_STEP = 0x02020202;
  private static final int SK_BUMP = 0x01010101;
  private static final int SK_ROTL = 9;

  private int[] whiten = new int[2 * BLOCK_SIZE / 4];
  private int[] encrSubKeys = new int[2 * MAX_ROUNDS];
  private int[] decrSubKeys = new int[2 * MAX_ROUNDS];
  private int[] sbk = new int[MAX_KEY_SIZE / 8];
  private int[] sBox = new int[1024];

  private static int ROL(int x, int n) {
    return (x << n) | (x >>> (32 - n));
  }
  private static int ROR(int x, int n) {
    return (x >>> n) | (x << (32 - n));
  }

  private static final int RS_GF_FDBK = 0x14D;		/* field generator */
  private static int RS_rem(int x) {
    byte b = (byte)(x >>> 24);
    int g2 = (int)(((b << 1) ^ (((b & 0x80) != 0) ? RS_GF_FDBK : 0)) & 0xFF);
    int g3 = (int)(((b >>> 1) & 0x7F) ^ (((b & 1) != 0) ? RS_GF_FDBK >>> 1 : 0) ^ g2);
    return (x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ (b & 0xFF);
  }
  private static int RS_MDS_Encode(int k0, int k1) {
    int i, j;
    int r;

    for (i = r = 0; i < 2; i++) {
      r ^= (i != 0) ? k0 : k1;   /* merge in 32 more key bits */
      for (j = 0; j < 4; j++)    /* shift one byte at a time */
      	r = RS_rem(r);
    }
    return r;
  }

  private int F32(int x, int[] k32) {
    switch (cipherKeySize) {
      case 32:
        x = (x & 0xFFFFFF00) | (((P8x8[1][(x & 0xFF)] & 0xFF) ^ (k32[3] & 0xFF)) & 0xFF);
        x = (x & 0xFFFF00FF) | ((((P8x8[0][((x >>> 8) & 0xFF)] & 0xFF) ^ ((k32[3] >>> 8) & 0xFF)) << 8) & 0x0000FF00);
        x = (x & 0xFF00FFFF) | ((((P8x8[0][((x >>> 16) & 0xFF)] & 0xFF) ^ ((k32[3] >>> 16) & 0xFF)) << 16) & 0x00FF0000);
        x = (x & 0x00FFFFFF) | ((((P8x8[1][((x >>> 24) & 0xFF)] & 0xFF) ^ ((k32[3] >>> 24) & 0xFF)) << 24) & 0xFF000000);

      case 24:
        x = (x & 0xFFFFFF00) | (((P8x8[1][(x & 0xFF)] & 0xFF) ^ (k32[2] & 0xFF)) & 0xFF);
        x = (x & 0xFFFF00FF) | ((((P8x8[1][((x >>> 8) & 0xFF)] & 0xFF) ^ ((k32[2] >>> 8) & 0xFF)) << 8) & 0x0000FF00);
        x = (x & 0xFF00FFFF) | ((((P8x8[0][((x >>> 16) & 0xFF)] & 0xFF) ^ ((k32[2] >>> 16) & 0xFF)) << 16) & 0x00FF0000);
        x = (x & 0x00FFFFFF) | ((((P8x8[0][((x >>> 24) & 0xFF)] & 0xFF) ^ ((k32[2] >>> 24) & 0xFF)) << 24) & 0xFF000000);

      case 16:
      default:    /* 128-bit keys (optimize for this case) */
        return MDS[0][(P8x8[0][(P8x8[0][(x & 0xFF)] & 0xFF) ^ (k32[1] & 0xFF)] & 0xFF) ^ (k32[0] & 0xFF)] ^
               MDS[1][(P8x8[0][(P8x8[1][((x >>> 8) & 0xFF)] & 0xFF) ^ ((k32[1] >>> 8) & 0xFF)] & 0xFF) ^ ((k32[0] >>> 8) & 0xFF)] ^
               MDS[2][(P8x8[1][(P8x8[0][((x >>> 16) & 0xFF)] & 0xFF) ^ ((k32[1] >>> 16) & 0xFF)] & 0xFF) ^ ((k32[0] >>> 16) & 0xFF)] ^
               MDS[3][(P8x8[1][(P8x8[1][((x >>> 24) & 0xFF)] & 0xFF) ^ ((k32[1] >>> 24) & 0xFF)] & 0xFF) ^ ((k32[0] >>> 24) & 0xFF)];
    }
  }

  //
  // The following functions define the cipher implementation
  //

  protected void ExpandKey() {
    int[] ke = new int[MAX_KEY_SIZE / 8];
    int[] ko = new int[MAX_KEY_SIZE / 8];
    int[] subkeys = new int[2 * (BLOCK_SIZE / 4 + cipherRounds)];
    int A, B;
    byte[] L0 = new byte[256];
    byte[] L1 = new byte[256];
    int i, j;

    int[] Key32 = new int[cipherKeySize / 4];
    FromBytes(Key32, 0, cipherKey, 0, cipherKeySize);

    i = cipherKeySize >>> 3;

    ke[0] = Key32[0];
    ko[0] = Key32[1];
    sbk[--i] = RS_MDS_Encode(ke[0], ko[0]);

    ke[1] = Key32[2];
    ko[1] = Key32[3];
    sbk[--i] = RS_MDS_Encode(ke[1], ko[1]);

    if (i > 0) {
      ke[2] = Key32[4];
      ko[2] = Key32[5];
      sbk[--i] = RS_MDS_Encode(ke[2], ko[2]);

      if (i > 0) {
        ke[3] = Key32[6];
        ko[3] = Key32[7];
        sbk[--i] = RS_MDS_Encode(ke[3], ko[3]);
      }
    }

    // Compute round subkeys for PHT
    for (i = j = 0; i < (BLOCK_SIZE / 4 + cipherRounds); i++, j += SK_STEP) {
      A = F32(j, ke);             // A uses even key dwords
      B = F32(j + SK_BUMP, ko);   // B uses odd  key dwords
      B = ROL(B, 8);
      subkeys[2 * i] = A + B;   	// combine with a PHT
      B = A + 2 * B;
      subkeys[2 * i + 1] = ROL(B, SK_ROTL);
    }

    
    System.arraycopy(subkeys, 0, whiten, 0, whiten.length);
    System.arraycopy(subkeys, whiten.length, decrSubKeys, 0, decrSubKeys.length);
    java.util.Arrays.fill(subkeys, 0);

    for (i = 0, j = 2 * cipherRounds - 2; i < 2 * cipherRounds; i += 2, j -= 2) {
      encrSubKeys[i] = decrSubKeys[j];
      encrSubKeys[i + 1] = decrSubKeys[j + 1];
    }

    int k0, k1;

    switch (cipherKeySize) {
      case 16:
        for (i = 0; i < 256; i++) L0[i] = (byte)(P8x8[0][i] ^ (sbk[1] & 0xFF));
        k0 = sbk[0] & 0xFF;
        for (i = 0; i < 256; i += 2) {
          sBox[2 * i] = MDS[0][(P8x8[0][L0[i] & 0xFF] & 0xFF) ^ k0];
          sBox[2 * i + 2] = MDS[0][(P8x8[0][L0[i + 1] & 0xFF] & 0xFF) ^ k0];
        }

        for (i = 0; i < 256; i++) L0[i] = (byte)(P8x8[1][i] ^ ((sbk[1] >>> 8) & 0xFF));
        k0 = (sbk[0] >>> 8) & 0xFF;
        for (i = 0; i < 256; i += 2) {
          sBox[2 * i + 1] = MDS[1][(P8x8[0][L0[i] & 0xFF] & 0xFF) ^ k0];
          sBox[2 * i + 3] = MDS[1][(P8x8[0][L0[i + 1] & 0xFF] & 0xFF) ^ k0];
        }

        for (i = 0; i < 256; i++) L0[i] = (byte)(P8x8[0][i] ^ ((sbk[1] >>> 16) & 0xFF));
        k0 = (sbk[0] >>> 16) & 0xFF;
        for (i = 0; i < 256; i += 2) {
          sBox[512 + 2 * i] = MDS[2][(P8x8[1][L0[i] & 0xFF] & 0xFF) ^ k0];
          sBox[512 + 2 * i + 2] = MDS[2][(P8x8[1][L0[i + 1] & 0xFF] & 0xFF) ^ k0];
        }

        for (i = 0; i < 256; i++) L0[i] = (byte)(P8x8[1][i] ^ ((sbk[1] >>> 24) & 0xFF));
        k0 = (sbk[0] >>> 24) & 0xFF;
        for (i = 0; i < 256; i += 2) {
          sBox[512 + 2 * i + 1] = MDS[3][(P8x8[1][L0[i] & 0xFF] & 0xFF) ^ k0];
          sBox[512 + 2 * i + 3] = MDS[3][(P8x8[1][L0[i + 1] & 0xFF] & 0xFF) ^ k0];
        }
        break;

      case 24:
        for (i = 0; i < 256; i++) L0[i] = (byte)(P8x8[1][i] ^ (sbk[2] & 0xFF));
        k0 = sbk[0] & 0xFF;
        k1 = sbk[1] & 0xFF;
        for (i = 0; i < 256; i += 2) {
          sBox[2 * i] = MDS[0][(P8x8[0][(P8x8[0][L0[i] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
          sBox[2 * i + 2] = MDS[0][(P8x8[0][(P8x8[0][L0[i + 1] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
        }

        for (i = 0; i < 256; i++) L0[i] = (byte)(P8x8[1][i] ^ ((sbk[2] >>> 8) & 0xFF));
        k0 = (sbk[0] >>> 8) & 0xFF;
        k1 = (sbk[1] >>> 8) & 0xFF;
        for (i = 0; i < 256; i += 2) {
          sBox[2 * i + 1] = MDS[1][(P8x8[0][(P8x8[1][L0[i] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
          sBox[2 * i + 3] = MDS[1][(P8x8[0][(P8x8[1][L0[i + 1] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
        }

        for (i = 0; i < 256; i++) L0[i] = (byte)(P8x8[0][i] ^ ((sbk[2] >>> 16) & 0xFF));
        k0 = (sbk[0] >>> 16) & 0xFF;
        k1 = (sbk[1] >>> 16) & 0xFF;
        for (i = 0; i < 256; i += 2) {
          sBox[512 + 2 * i] = MDS[2][(P8x8[1][(P8x8[0][L0[i] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
          sBox[512 + 2 * i + 2] = MDS[2][(P8x8[1][(P8x8[0][L0[i + 1] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
        }

        for (i = 0; i < 256; i++) L0[i] = (byte)(P8x8[0][i] ^ ((sbk[2] >>> 24) & 0xFF));
        k0 = (sbk[0] >>> 24) & 0xFF;
        k1 = (sbk[1] >>> 24) & 0xFF;
        for (i = 0; i < 256; i += 2) {
          sBox[512 + 2 * i + 1] = MDS[3][(P8x8[1][(P8x8[1][L0[i] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
          sBox[512 + 2 * i + 3] = MDS[3][(P8x8[1][(P8x8[1][L0[i + 1] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
        }
        break;

      case 32:
        for (i = 0; i < 256; i++) L1[i] = (byte)(P8x8[1][i] ^ (sbk[3] & 0xFF));
        for (i = 0; i < 256; i += 2) {
          L0[i] = P8x8[1][L1[i] & 0xFF];
          L0[i + 1] = P8x8[1][L1[i + 1] & 0xFF];
        }
        for (i = 0; i < 256; i++) L0[i] = (byte)(L0[i] ^ (sbk[2] & 0xFF));
        k0 = sbk[0] & 0xFF;
        k1 = sbk[1] & 0xFF;
        for (i = 0; i < 256; i += 2) {
          sBox[2 * i] = MDS[0][(P8x8[0][(P8x8[0][L0[i] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
          sBox[2 * i + 2] = MDS[0][(P8x8[0][(P8x8[0][L0[i + 1] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
        }

        for (i = 0; i < 256; i++) L1[i] = (byte)(P8x8[0][i] ^ ((sbk[3] >>> 8) & 0xFF));
        for (i = 0; i < 256; i += 2) {
          L0[i] = P8x8[1][L1[i] & 0xFF];
          L0[i + 1] = P8x8[1][L1[i + 1] & 0xFF];
        }
        for (i = 0; i < 256; i++) L0[i] = (byte)(L0[i] ^ ((sbk[2] >>> 8) & 0xFF));
        k0 = ((sbk[0] >>> 8) & 0xFF);
        k1 = ((sbk[1] >>> 8) & 0xFF);
        for (i = 0; i < 256; i += 2) {
          sBox[2 * i + 1] = MDS[1][(P8x8[0][(P8x8[1][L0[i] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
          sBox[2 * i + 3] = MDS[1][(P8x8[0][(P8x8[1][L0[i + 1] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
        }

        for (i = 0; i < 256; i++) L1[i] = (byte)(P8x8[0][i] ^ ((sbk[3] >>> 16) & 0xFF));
        for (i = 0; i < 256; i += 2) {
          L0[i] = P8x8[0][L1[i] & 0xFF];
          L0[i + 1] = P8x8[0][L1[i + 1] & 0xFF];
        }
        for (i = 0; i < 256; i++) L0[i] = (byte)(L0[i] ^ ((sbk[2] >>> 16) & 0xFF));
        k0 = ((sbk[0] >>> 16) & 0xFF);
        k1 = ((sbk[1] >>> 16) & 0xFF);
        for (i = 0; i < 256; i += 2) {
          sBox[512 + 2 * i] = MDS[2][(P8x8[1][(P8x8[0][L0[i] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
          sBox[512 + 2 * i + 2] = MDS[2][(P8x8[1][(P8x8[0][L0[i + 1] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
        }

        for (i = 0; i < 256; i++) L1[i] = (byte)(P8x8[1][i] ^ ((sbk[3] >>> 24) & 0xFF));
        for (i = 0; i < 256; i += 2) {
          L0[i] = P8x8[0][L1[i] & 0xFF];
          L0[i + 1] = P8x8[0][L1[i + 1] & 0xFF];
        }
        for (i = 0; i < 256; i++) L0[i] = (byte)(L0[i] ^ ((sbk[2] >>> 24) & 0xFF));
        k0 = ((sbk[0] >>> 24) & 0xFF);
        k1 = ((sbk[1] >>> 24) & 0xFF);
        for (i = 0; i < 256; i += 2) {
          sBox[512 + 2 * i + 1] = MDS[3][(P8x8[1][(P8x8[1][L0[i] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
          sBox[512 + 2 * i + 3] = MDS[3][(P8x8[1][(P8x8[1][L0[i + 1] & 0xFF] & 0xFF) ^ k1] & 0xFF) ^ k0];
        }
        break;
    }
  }

  protected void EncryptBasicBlock(byte[] dst, int to, byte[] src, int from) {
    int t0, t1;
    int[] x = new int[BLOCK_SIZE / 4];

    FromBytes(x, 0, src, from, BLOCK_SIZE);
    for (int i = 0; i < x.length; i++) x[i] ^= whiten[i];

    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[0] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[1] >>> 16) & 0xFF) + 1]);
    x[3] = ROL(x[3], 1);
    x[2] ^= t0 + t1 + encrSubKeys[30];
    x[3] ^= t0 + 2 * t1 + encrSubKeys[31];
    x[2] = ROR(x[2], 1);

    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[2] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[3] >>> 16) & 0xFF) + 1]);
    x[1] = ROL(x[1], 1);
    x[0] ^= t0 + t1 + encrSubKeys[28];
    x[1] ^= t0 + 2 * t1 + encrSubKeys[29];
    x[0] = ROR(x[0], 1);

    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[0] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[1] >>> 16) & 0xFF) + 1]);
    x[3] = ROL(x[3], 1);
    x[2] ^= t0 + t1 + encrSubKeys[26];
    x[3] ^= t0 + 2 * t1 + encrSubKeys[27];
    x[2] = ROR(x[2], 1);

    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[2] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[3] >>> 16) & 0xFF) + 1]);
    x[1] = ROL(x[1], 1);
    x[0] ^= t0 + t1 + encrSubKeys[24];
    x[1] ^= t0 + 2 * t1 + encrSubKeys[25];
    x[0] = ROR(x[0], 1);

    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[0] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[1] >>> 16) & 0xFF) + 1]);
    x[3] = ROL(x[3], 1);
    x[2] ^= t0 + t1 + encrSubKeys[22];
    x[3] ^= t0 + 2 * t1 + encrSubKeys[23];
    x[2] = ROR(x[2], 1);

    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[2] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[3] >>> 16) & 0xFF) + 1]);
    x[1] = ROL(x[1], 1);
    x[0] ^= t0 + t1 + encrSubKeys[20];
    x[1] ^= t0 + 2 * t1 + encrSubKeys[21];
    x[0] = ROR(x[0], 1);

    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[0] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[1] >>> 16) & 0xFF) + 1]);
    x[3] = ROL(x[3], 1);
    x[2] ^= t0 + t1 + encrSubKeys[18];
    x[3] ^= t0 + 2 * t1 + encrSubKeys[19];
    x[2] = ROR(x[2], 1);

    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[2] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[3] >>> 16) & 0xFF) + 1]);
    x[1] = ROL(x[1], 1);
    x[0] ^= t0 + t1 + encrSubKeys[16];
    x[1] ^= t0 + 2 * t1 + encrSubKeys[17];
    x[0] = ROR(x[0], 1);

    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[0] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[1] >>> 16) & 0xFF) + 1]);
    x[3] = ROL(x[3], 1);
    x[2] ^= t0 + t1 + encrSubKeys[14];
    x[3] ^= t0 + 2 * t1 + encrSubKeys[15];
    x[2] = ROR(x[2], 1);

    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[2] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[3] >>> 16) & 0xFF) + 1]);
    x[1] = ROL(x[1], 1);
    x[0] ^= t0 + t1 + encrSubKeys[12];
    x[1] ^= t0 + 2 * t1 + encrSubKeys[13];
    x[0] = ROR(x[0], 1);

    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[0] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[1] >>> 16) & 0xFF) + 1]);
    x[3] = ROL(x[3], 1);
    x[2] ^= t0 + t1 + encrSubKeys[10];
    x[3] ^= t0 + 2 * t1 + encrSubKeys[11];
    x[2] = ROR(x[2], 1);

    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[2] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[3] >>> 16) & 0xFF) + 1]);
    x[1] = ROL(x[1], 1);
    x[0] ^= t0 + t1 + encrSubKeys[8];
    x[1] ^= t0 + 2 * t1 + encrSubKeys[9];
    x[0] = ROR(x[0], 1);

    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[0] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[1] >>> 16) & 0xFF) + 1]);
    x[3] = ROL(x[3], 1);
    x[2] ^= t0 + t1 + encrSubKeys[6];
    x[3] ^= t0 + 2 * t1 + encrSubKeys[7];
    x[2] = ROR(x[2], 1);

    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[2] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[3] >>> 16) & 0xFF) + 1]);
    x[1] = ROL(x[1], 1);
    x[0] ^= t0 + t1 + encrSubKeys[4];
    x[1] ^= t0 + 2 * t1 + encrSubKeys[5];
    x[0] = ROR(x[0], 1);

    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[0] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[1] >>> 16) & 0xFF) + 1]);
    x[3] = ROL(x[3], 1);
    x[2] ^= t0 + t1 + encrSubKeys[2];
    x[3] ^= t0 + 2 * t1 + encrSubKeys[3];
    x[2] = ROR(x[2], 1);

    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512 + 2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512 + 2 * ((x[2] >>> 24) & 0xFF) + 1]);
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512 + 2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512 + 2 * ((x[3] >>> 16) & 0xFF) + 1]);
    x[1] = ROL(x[1], 1);
    x[0] ^= t0 + t1 + encrSubKeys[0];
    x[1] ^= t0 + 2 * t1 + encrSubKeys[1];
    x[0] = ROR(x[0], 1);

    t0 = x[0]; x[0] = x[2]; x[2] = t0;
    t1 = x[1]; x[1] = x[3]; x[3] = t1;
    for (int i = 0; i < x.length; i++) x[i] ^= whiten[i + 4];
    ToBytes(dst, to, x, 0, BLOCK_SIZE);
  }

  protected void DecryptBasicBlock(byte[] dst, int to, byte[] src, int from) {
    int t0, t1;
    int[] x = new int[BLOCK_SIZE / 4];

    FromBytes(x, 0, src, from, BLOCK_SIZE);
    for (int i = 0; i < x.length; i++) x[i] ^= whiten[i + 4];
    t0 = x[0]; x[0] = x[2]; x[2] = t0;
    t1 = x[1]; x[1] = x[3]; x[3] = t1; 
    
    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[2] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512+2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[3] >>> 16) & 0xFF) + 1]); 
    x[0] = ROL(x[0], 1); 
    x[0] ^= t0 + t1 + decrSubKeys[30]; 
    x[1] ^= t0 + 2 * t1 + decrSubKeys[31]; 
    x[1] = ROR(x[1], 1); 
    
    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[0] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512+2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[1] >>> 16) & 0xFF) + 1]); 
    x[2] = ROL(x[2], 1); 
    x[2] ^= t0 + t1 + decrSubKeys[28]; 
    x[3] ^= t0 + 2 * t1 + decrSubKeys[29]; 
    x[3] = ROR(x[3], 1); 
    
    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[2] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512+2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[3] >>> 16) & 0xFF) + 1]); 
    x[0] = ROL(x[0], 1); 
    x[0] ^= t0 + t1 + decrSubKeys[26]; 
    x[1] ^= t0 + 2 * t1 + decrSubKeys[27]; 
    x[1] = ROR(x[1], 1);
    
    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[0] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512+2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[1] >>> 16) & 0xFF) + 1]); 
    x[2] = ROL(x[2], 1); 
    x[2] ^= t0 + t1 + decrSubKeys[24]; 
    x[3] ^= t0 + 2 * t1 + decrSubKeys[25]; 
    x[3] = ROR(x[3], 1);
    
    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[2] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512+2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[3] >>> 16) & 0xFF) + 1]); 
    x[0] = ROL(x[0], 1); 
    x[0] ^= t0 + t1 + decrSubKeys[22]; 
    x[1] ^= t0 + 2 * t1 + decrSubKeys[23]; 
    x[1] = ROR(x[1], 1);
    
    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[0] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512+2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[1] >>> 16) & 0xFF) + 1]); 
    x[2] = ROL(x[2], 1); 
    x[2] ^= t0 + t1 + decrSubKeys[20]; 
    x[3] ^= t0 + 2 * t1 + decrSubKeys[21]; 
    x[3] = ROR(x[3], 1);
    
    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[2] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512+2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[3] >>> 16) & 0xFF) + 1]); 
    x[0] = ROL(x[0], 1); 
    x[0] ^= t0 + t1 + decrSubKeys[18]; 
    x[1] ^= t0 + 2 * t1 + decrSubKeys[19]; 
    x[1] = ROR(x[1], 1);
    
    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[0] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512+2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[1] >>> 16) & 0xFF) + 1]); 
    x[2] = ROL(x[2], 1); 
    x[2] ^= t0 + t1 + decrSubKeys[16]; 
    x[3] ^= t0 + 2 * t1 + decrSubKeys[17]; 
    x[3] = ROR(x[3], 1);
    
    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[2] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512+2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[3] >>> 16) & 0xFF) + 1]); 
    x[0] = ROL(x[0], 1); 
    x[0] ^= t0 + t1 + decrSubKeys[14]; 
    x[1] ^= t0 + 2 * t1 + decrSubKeys[15]; 
    x[1] = ROR(x[1], 1); 
    
    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[0] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512+2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[1] >>> 16) & 0xFF) + 1]); 
    x[2] = ROL(x[2], 1); 
    x[2] ^= t0 + t1 + decrSubKeys[12]; 
    x[3] ^= t0 + 2 * t1 + decrSubKeys[13]; 
    x[3] = ROR(x[3], 1);
    
    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[2] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512+2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[3] >>> 16) & 0xFF) + 1]); 
    x[0] = ROL(x[0], 1); 
    x[0] ^= t0 + t1 + decrSubKeys[10]; 
    x[1] ^= t0 + 2 * t1 + decrSubKeys[11]; 
    x[1] = ROR(x[1], 1);
    
    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[0] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512+2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[1] >>> 16) & 0xFF) + 1]); 
    x[2] = ROL(x[2], 1); 
    x[2] ^= t0 + t1 + decrSubKeys[8]; 
    x[3] ^= t0 + 2 * t1 + decrSubKeys[9]; 
    x[3] = ROR(x[3], 1);
    
    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[2] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512+2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[3] >>> 16) & 0xFF) + 1]); 
    x[0] = ROL(x[0], 1); 
    x[0] ^= t0 + t1 + decrSubKeys[6]; 
    x[1] ^= t0 + 2 * t1 + decrSubKeys[7]; 
    x[1] = ROR(x[1], 1);
    
    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[0] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512+2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[1] >>> 16) & 0xFF) + 1]); 
    x[2] = ROL(x[2], 1); 
    x[2] ^= t0 + t1 + decrSubKeys[4]; 
    x[3] ^= t0 + 2 * t1 + decrSubKeys[5]; 
    x[3] = ROR(x[3], 1);
    
    t0 = (sBox[2 * (x[2] & 0xFF)] ^ sBox[2 * ((x[2] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[2] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[2] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[3] >>> 24) & 0xFF)] ^ sBox[2 * (x[3] & 0xFF) + 1] ^ sBox[512+2 * ((x[3] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[3] >>> 16) & 0xFF) + 1]); 
    x[0] = ROL(x[0], 1); 
    x[0] ^= t0 + t1 + decrSubKeys[2]; 
    x[1] ^= t0 + 2 * t1 + decrSubKeys[3]; 
    x[1] = ROR(x[1], 1);
    
    t0 = (sBox[2 * (x[0] & 0xFF)] ^ sBox[2 * ((x[0] >>> 8) & 0xFF) + 1] ^ sBox[512+2 * ((x[0] >>> 16) & 0xFF)] ^ sBox[512+2 * ((x[0] >>> 24) & 0xFF) + 1]); 
    t1 = (sBox[2 * ((x[1] >>> 24) & 0xFF)] ^ sBox[2 * (x[1] & 0xFF) + 1] ^ sBox[512+2 * ((x[1] >>> 8) & 0xFF)] ^ sBox[512+2 * ((x[1] >>> 16) & 0xFF) + 1]); 
    x[2] = ROL(x[2], 1); 
    x[2] ^= t0 + t1 + decrSubKeys[0]; 
    x[3] ^= t0 + 2 * t1 + decrSubKeys[1]; 
    x[3] = ROR(x[3], 1);

    for (int i = 0; i < x.length; i++) x[i] ^= whiten[i];
    ToBytes(dst, to, x, 0, BLOCK_SIZE);
  }
}
