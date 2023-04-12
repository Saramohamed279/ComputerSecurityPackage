using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        List<int> numShiftLeft = new List<int>() { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        List<int> PC1 = new List<int>()
        {
          57, 49, 41, 33, 25, 17,  9,
           1, 58, 50, 42, 34, 26, 18,
          10,  2, 59, 51, 43, 35, 27,
          19, 11,  3, 60, 52, 44, 36,
          63, 55, 47, 39, 31, 23, 15,
           7, 62, 54, 46, 38, 30, 22,
          14,  6, 61, 53, 45, 37, 29,
          21, 13,  5, 28, 20, 12,  4
        };

        List<int> PC2 = new List<int>()
        {
          14, 17, 11, 24,  1,  5,
           3, 28, 15,  6, 21, 10,
          23, 19, 12,  4, 26,  8,
          16,  7, 27, 20, 13,  2,
          41, 52, 31, 37, 47, 55,
          30, 40, 51, 45, 33, 48,
          44, 49, 39, 56, 34, 53,
          46, 42, 50, 36, 29, 32
        };

        List<int> IP = new List<int>()
        {
          58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17,  9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7
        };

        List<int> E = new List<int>()
        {
          32,  1,  2,  3,  4,  5,
           4,  5,  6,  7,  8,  9,
           8,  9, 10, 11, 12, 13,
          12, 13, 14, 15, 16, 17,
          16, 17, 18, 19, 20, 21,
          20, 21, 22, 23, 24, 25,
          24, 25, 26, 27, 28, 29,
          28, 29, 30, 31, 32,  1
        };

        List<int[,]> sBoxes = new List<int[,]>()
        {
            // s1
            new int[,]
            {
               { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
               {  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
               {  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
               { 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},
            },

            // s2
            new int[,]
            {
               { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
               {  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
               {  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
               { 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},
            },

            // s3
            new int[,]
            {
               { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
               { 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
               { 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
               {  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},
            },

            // s4
            new int[,]
            {
               {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
               { 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
               { 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
               {  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},
            },

            // s5
            new int[,]
            {
               {  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
               { 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
               {  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
               { 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},
            },

            // s6
            new int[,]
            {
               { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
               { 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
               {  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
               {  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},
            },

            // s7
            new int[,]
            {
               {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
               { 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
               {  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
               {  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},
            },

            // s8
            new int[,]
            {
               { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12, 7},
               {  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9, 2},
               {  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5, 8},
               {  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11},
            },

        };

        List<int> P = new List<int>()
        {
          16,  7, 20, 21,
          29, 12, 28, 17,
           1, 15, 23, 26,
           5, 18, 31, 10,
           2,  8, 24, 14,
          32, 27,  3,  9,
          19, 13, 30,  6,
          22, 11,  4, 25
        };

        List<int> IPinverse = new List<int>()
        {
          40,  8, 48, 16, 56, 24, 64, 32,
          39,  7, 47, 15, 55, 23, 63, 31,
          38,  6, 46, 14, 54, 22, 62, 30,
          37,  5, 45, 13, 53, 21, 61, 29,
          36,  4, 44, 12, 52, 20, 60, 28,
          35,  3, 43, 11, 51, 19, 59, 27,
          34,  2, 42, 10, 50, 18, 58, 26,
          33,  1, 41,  9, 49, 17, 57, 25
        };


        private string convertbinaryToDecimal(string binary)
        {
            int Dec = 0;
            char[] binarydig = binary.ToCharArray();
            Array.Reverse(binarydig);

            for (int i = 0; i < binarydig.Length; i++)
            {
                if (binarydig[i] == '1')
                {
                    if (i == 0)
                    {
                        Dec += 1;
                    }
                    else
                    {
                        Dec += (int)Math.Pow(2, i);
                    }
                }

            }
            return Dec.ToString();
        }
        private string convertDecimalTobinary(string dec)
        {
            string binary = string.Empty;
            int decNum = int.Parse(dec);
            int remain = 0;

            while (decNum > 0)
            {
                remain = decNum % 2;
                decNum /= 2;
                binary = remain.ToString() + binary;
            }
            return binary;
        }


        private string Sbox(string b, int i)
        {

            string B_of_row = String.Concat(b[0], b[b.Length - 1]); ///10
            string b_ofCol = b.Substring(1, 4);
            int row = int.Parse(convertbinaryToDecimal(B_of_row));
            int col = int.Parse(convertbinaryToDecimal(b_ofCol));
            int S_ofB = sBoxes[i][row, col];

            return convertDecimalTobinary(S_ofB.ToString());
        }
        

        private IEnumerable<string> keyGenerator(string baseKey)
        {

            string binaryBaseKey = convertHexaToBinary(baseKey);
            string permutatedBaseKey = Permutation(binaryBaseKey, PC1);

            string C = permutatedBaseKey.Substring(0, 28); ;
            string D = permutatedBaseKey.Substring(28, 28); ;

            for (int i = 0; i < 16; i++)
            {
                C = ShiftLeft(C, numShiftLeft[i]);
                D = ShiftLeft(D, numShiftLeft[i]);

                string thisRoundKey = "";

                thisRoundKey += C;
                thisRoundKey += D;

                thisRoundKey = Permutation(thisRoundKey, PC2);


                yield return thisRoundKey;
            }

        }
        public override string Encrypt(string plainText, string key)
        {
            // hexadecimal to binary
            string PTBinary = convertHexaToBinary(plainText);
            string PTPerm = Permutation(PTBinary, IP);
            List<string> rKey = new List<string>();
            int num = 32;
            string LeftPart = PTPerm.Substring(0, num);
            string RightPart = PTPerm.Substring(num, num);

            foreach (string roundKey in keyGenerator(key))
            {
                // use the key
                rKey.Add(roundKey);
            }
            int rr = 16;
            for (int r = 0; r < rr; r++)
            {
                string Expansion = Permutation(RightPart, E);

                string XoredResult = xoring(rKey[r], Expansion);//48
                string SBresult = "";

                int ss = 8;
                IEnumerable<string> Chunks = Split(XoredResult, 6);

                var item = Chunks.ElementAt(0);
                for (int s = 0; s < 8; s++)
                {

                    SBresult += Sbox(Chunks.ElementAt(s), s).PadLeft(4, '0');

                }

                string ExpandedPerm = Permutation(SBresult, P);

                LeftPart = xoring(LeftPart, ExpandedPerm);

                shuffle(ref LeftPart, ref RightPart);
            }

            shuffle(ref LeftPart, ref RightPart);
            plainText = LeftPart + RightPart;
            string final = Permutation(plainText, IPinverse);
            string encryptedtxt = "0x" + Convert.ToInt64(final, 2).ToString("x").PadLeft(16, '0');
            return encryptedtxt;

        }
     
        public override string Decrypt(string cipherText, string key)
        {

            // alternative way to create and use the key generation manually
            // method 2 is recommended
            //
            // create the generator
            //var generator = keyGenerator(key).GetEnumerator();
            //
            // move to the next item (first item)
            //generator.MoveNext();
            //
            // use the item
            //string currentKey = generator.Current;
            //
            // move to the next item
            //generator.MoveNext();


            // method 2
            // loop through all keys in the key generator one at a time
            //foreach (string roundKey in keyGenerator(key))
            //{
            //    // use the key
            //    Console.WriteLine(roundKey);
            //}

            // hexadecimal to binary
            string PTBinary = convertHexaToBinary(cipherText);
            string PTPerm = Permutation(PTBinary, IP);
            List<string> rKey = new List<string>();
            int num = 32;
            string LeftPart = PTPerm.Substring(0, num);
            string RightPart = PTPerm.Substring(num, num);

            foreach (string roundKey in keyGenerator(key))
            {
                // use the key
                rKey.Add(roundKey);
            }
            int rr = 16;
            for (int r = 15; r >= 0; r--)
            {
                string Expansion = Permutation(RightPart, E);

                string XoredResult = xoring(rKey[r], Expansion);//48
                string SBresult = "";

                int ss = 8;
                IEnumerable<string> Chunks = Split(XoredResult, 6);

                var item = Chunks.ElementAt(0);
                for (int s = 0; s < 8; s++)
                {

                    SBresult += Sbox(Chunks.ElementAt(s), s).PadLeft(4, '0');

                }

                string ExpandedPerm = Permutation(SBresult, P);

                LeftPart = xoring(LeftPart, ExpandedPerm);

                shuffle(ref LeftPart, ref RightPart);
            }

            shuffle(ref LeftPart, ref RightPart);
            cipherText = LeftPart + RightPart;
            string final = Permutation(cipherText, IPinverse);
            string plainText = "0x" + Convert.ToInt64(final, 2).ToString("x").PadLeft(16, '0');
            return plainText;
        }

        private string Permutation(string str, List<int> PC)
        {
            int n = PC.Count;
            string PermutationString = "";

            for (int i = 0; i < n; i++)
            {
                int new_index = PC[i] - 1;
                PermutationString += str[new_index];
            }

            return PermutationString;
        }
       
        public void shuffle(ref string x, ref string y)
        {

            string z;

            z = x;

            x = y;

            y = z;

        }
        private string ShiftLeft(string str, int ShiftingFactor)
        {
            int n = str.Length;
            string shifted_str = str;
            ShiftingFactor = ShiftingFactor % n;

            for (int i = 0; i < n; i++)
            {
                int new_index = ((i - ShiftingFactor) + n) % n;
                shifted_str = shifted_str.Remove(new_index, 1).Insert(new_index, str[i].ToString());
            }

            return shifted_str;
        }
        private string xoring(string x, string y)
        {
            string value = "";
            int len = x.Length;
            for (int i = 0; i <len ; i++)
            {
                
                if (x[i] == y[i])
                    value += "0";
                else
                    value += "1";
            }
            return value;
        }
        private IEnumerable<string> Split(string str, int chunkSize)
        {
            return Enumerable.Range(0, str.Length / chunkSize)
                .Select(i => str.Substring(i * chunkSize, chunkSize));
        }

        private string convertHexaToBinary(string hexa)
        {

            hexa = hexa.Substring(2, hexa.Length - 2);

            string binary = String.Join(String.Empty,
              hexa.Select(
                c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')
              )
            );

            return binary;
        }
    }
}
