using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.MD5
{
    public class MD5
    {

        /*
          steps

        1- convert input string to binary (done)
        2- split into 512 blocks as per the lab (semi done)
        3- pre algorithm preparation (done)
            - A, B, C, D
            - 4 functions
        4- function for a single step
        5- function for a block
        6- function for a round
         
         
         */
        private static string convertHexaToBinary(string hexa)
        {
            
            string binary = String.Join(String.Empty,
              hexa.Select(
                c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')
              )
            );
            
            return binary;
        }

        /*
        string A = convertHexaToBinary("67452301");
        string B = convertHexaToBinary("EFCDAB89");
        string C = convertHexaToBinary("98BADCFE");
        string D = convertHexaToBinary("10325478");
        */

        
        string A = convertHexaToBinary("01234567");
        string B = convertHexaToBinary("89abcdef");
        string C = convertHexaToBinary("fedcba98");
        string D = convertHexaToBinary("76543210");
        

        /*
        string A = convertHexaToBinary("76543210");
        string B = convertHexaToBinary("fedcba98");
        string C = convertHexaToBinary("89abcdef");
        string D = convertHexaToBinary("01234567");
        */

        public string GetHash(string text)
        {
            //text = "They are deterministic";
            text = convertStringToBinary(text);
            var splitText = splitInputInto512BitsBlock(text);


            foreach (var item in splitText)
            {

                string local_a = A;
                string local_b = B;
                string local_c = C;
                string local_d = D;

                for (int i = 0; i < 4; i++)
                {
                    singleBlock(i, item);
                }

                A = Add(A, local_a);
                B = Add(B, local_b);
                C = Add(C, local_c);
                D = Add(D, local_d);

            }

            string hash = A + B + C + D;
            hash = BinaryStringToHexString(hash);

            return hash; 

        }
        public static string BinaryStringToHexString(string binary)
        {
            if (string.IsNullOrEmpty(binary))
                return binary;

            StringBuilder result = new StringBuilder(binary.Length / 8 + 1);

            // TODO: check all 1's or 0's... throw otherwise

            int mod4Len = binary.Length % 8;
            if (mod4Len != 0)
            {
                // pad to length multiple of 8
                binary = binary.PadLeft(((binary.Length / 8) + 1) * 8, '0');
            }

            for (int i = 0; i < binary.Length; i += 8)
            {
                string eightBits = binary.Substring(i, 8);
                result.AppendFormat("{0:X2}", Convert.ToByte(eightBits, 2));
            }

            return result.ToString();
        }
        private void singleBlock(int blockNum, string input)
        {

            var inputChuncks = splitToChuncks(input, 32);
            var chunkList = inputChuncks.ToList();


            for(int i = 0; i<16; i++)
            {
                int k = -1;
                Func<string, string, string, string> fun;
                List<int> shiftArray;

                switch (blockNum)
                {
                    case 0:
                        k = i;
                        fun = F;
                        shiftArray = new List<int>() { 7, 12, 17, 22 };
                        break;
                    case 1:
                        k = (1 + 5 * i) % 16;
                        fun = G;
                        shiftArray = new List<int>() { 5, 9, 14, 20 };

                        break;
                    case 2:
                        k = (5 + 3 * i) % 16;
                        fun = H;
                        shiftArray = new List<int>() { 4, 11, 16, 23 };

                        break;
                    case 3:
                        k = (7 * i) % 16;
                        fun = I;
                        shiftArray = new List<int>() { 6, 10, 15, 21 };

                        break;
                    default:
                        fun = F;
                        shiftArray = new List<int>() { 7, 12, 17, 22 };
                        break;
                }

                singleStep(fun, chunkList[k], (i + (16 * blockNum) + 1), shiftArray[i % 4]);
            }
        }

        private void singleStep(Func<string, string, string, string> fun, string msg, int i, int shiftAmount)
        {
            string funcResult = fun(B,C,D);

            string result = Add(funcResult, A);

            result = Add(result, msg);

            result = Add(result, T(i));

            result = circularShiftLeft(result, shiftAmount);

            result = Add(result, B);

            A = D;
            B = result;
            C = B;
            D = C;
        }

        private string Add(string x, string y)
        {
            long mod = (long)Math.Pow(2, 32);

            long X = Convert.ToInt64(x , 2);
            long Y = Convert.ToInt64(y , 2);

            long result = (((X + Y) % mod) + mod) % mod;
            
            string ret = Convert.ToString(result, 2);

            return ret;
        }

        //private Func<string, string, string, string> RoundFunction

        static IEnumerable<string> splitToChuncks(string s, int chunckSize)
        {
            return Enumerable.Range(0, s.Length / chunckSize).Select(i => s.Substring(i * chunckSize, chunckSize));
        }

        private string circularShiftLeft(string s, int amount)
        {
            string shiftAmount = s.Substring(0, amount);

            s = s.Substring(amount);

            s += shiftAmount;

            return s;
        }

        private string T(int i)
        {
            long result = (long)(Math.Pow(2, 32) * Math.Abs(Math.Sin(i)));

            string stringResult = Convert.ToString(result, 16);

            string BinaryStringResult = convertHexaToBinary(stringResult);

            return BinaryStringResult;
        }

        private string F(string b, string c, string d)
        {
            return Or(And(b, c), And(Not(b), d));
        }
        private string G(string b, string c, string d)
        {
            return Or(And(b, d), And(c, Not(d)));
        }
        private string H(string b, string c, string d)
        {
            return Xor(b, Xor(c, d));
        }
        private string I(string b, string c, string d)
        {
            return Xor(c, Or(b, Not(d)));
        }

        private string Not(string x)
        {
            string value = "";
            for (int i = 0; i < x.Length; i++)
            {
                if (x[i] == '1')
                    value += "0";
                else
                    value += "1";
            }
            return value;
        }
        private string Or(string x, string y)
        {
            string value = "";
            for (int i = 0; i < x.Length; i++)
            {
                if (x[i] == '1' || y[i] == '1')
                    value += "1";
                else
                    value += "0";
            }
            return value;
        }
        private string And(string x, string y)
        {
            string value = "";
            for (int i = 0; i < x.Length; i++)
            {
                if (x[i] == '1' && y[i] == '1')
                    value += "1";
                else
                    value += "0";
            }
            return value;
        }
        private string Xor(string x, string y)
        {
            string value = "";
            for (int i = 0; i < x.Length; i++)
            {
                if (x[i] == y[i])
                    value += "0";
                else
                    value += "1";
            }
            return value;
        }

        private List<string> splitInputInto512BitsBlock(string input)
        {
            List<string> blocks = new List<string>();

            int iterations = (int)Math.Floor(input.Length / 512m);

            // takes full blocks of 512 bits 
            for(int i = 0; i<iterations; i++)
            {
                blocks.Add(input.Substring(i * 512, 512));
            }

            // addes the last block that is less than 512 bits
            // if the input wasn't divisible by 512
            if (input.Length % 512 != 0)
            {
                blocks.Add(input.Substring(iterations * 512));
            }
            else
            {
                blocks.Add(lengthBlock(input));
            }

            // append 1000... (length in bits) to the last block if it has space (more than 65 bits)
            if (blocks[blocks.Count - 1].Length <= (512 - 65))
            {
                // convert length of input into a string of bits
                var lengthInBits = Convert.ToString(input.Length, 2).PadLeft(64, '0');

                // add a single "1"
                blocks[blocks.Count - 1] += "1";


                // calculate number of "0" to add
                int lenZeros = 512 - 64 - blocks[blocks.Count - 1].Length;

                // add number of "0" 
                for(int i = 0;i < lenZeros; i++)
                {
                    blocks[blocks.Count - 1] += "0";
                }

                // add the length in bits 
                blocks[blocks.Count - 1] += lengthInBits;
            }
            else if(blocks[blocks.Count -1].Length < 512)
            {
                blocks[blocks.Count - 1] += "1";
                while(blocks[blocks.Count - 1].Length < 512)
                {
                    blocks[blocks.Count - 1] += "0";
                }

                blocks.Add(lengthBlock(input));

            }

            // if the last block is not full (512 bits) but doesn't have 65 or more bits
            // I have no idea what to do ... yet!

            return blocks;
        }


        private string lengthBlock(string input)
        {
            string lastBlock = "";
            var lengthInBits = Convert.ToString(input.Length, 2).PadLeft(64, '0');

            lastBlock += "1";

            for (int i = 0; i < 512 - 65; i++)
            {
                lastBlock += "0";

            }
            lastBlock += lengthInBits;

            return lastBlock;
        }
        private string convertStringToBinary(string s)
        {

            string binary = String.Join(String.Empty,
              s.Select(
                c => Convert.ToString(c, 2).PadLeft(8, '0')
              )
            );

            return binary;
        }


    }
}
