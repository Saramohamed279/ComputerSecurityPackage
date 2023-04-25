using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            return Encrypt(cipherText, key);
        }
            

        public override string Encrypt(string plainText, string key)
        {
            int[] sarray = new int[256];
            int[] tarray = new int[256];
            string HexaPT = "";
            int ptlen = plainText.Length;
            int hexaNum = 16;
            int c = 0;
            string HexaKey = "";
            int keylen = key.Length;
            bool Ishexa = false;
            if (plainText.Contains("0x") == true)
            { 
                Ishexa = true;
                for (int k = 2; k < ptlen - 1; k += 2)
                {

                    int Pthandling = Convert.ToInt32(plainText[k].ToString() + plainText[k + 1].ToString(), hexaNum);
                    HexaPT += (char)Pthandling;
                }
            }
            else
                HexaPT = plainText;


            if (key.Contains("0x") == true)
            {
                for (int v = 2; v < keylen - 1; v += 2)
                {

                    int keyhandling = Convert.ToInt32(key[v].ToString() + key[v + 1].ToString(), hexaNum);
                    HexaKey += (char)keyhandling;
                }
            }
            else
                HexaKey = key;
            //initial sarray and tarray
            int length = 256;
            int i = 0;
            for (i = 0; i < length; i++)
            {
                if (c == HexaKey.Length)
                    c = 0;
                sarray[i] = i;
                tarray[i] = HexaKey[c];
                c++;
            }

            //permutes by ksa
            int j = 0;

            for (i = 0; i < length; i++)
            {
               
                j = (j + sarray[i] + tarray[i]) % length;
                shuffle(ref sarray[i], ref sarray[j]);//s
               
            }
            //permutes by PRGA
           
            //xor between plaintext and s[t]
            i = 0; j = 0;
            c = 0;
            int t;
            char[] K = new char[HexaPT.Length];
            char[] CipherText = new char[HexaPT.Length];
           //key streams
            while (c < HexaPT.Length)
            {
                i = (i + 1) % length;
                j = (j + sarray[i]) % length;
                shuffle(ref sarray[i],ref sarray[j]);
                t = (sarray[i] + sarray[j]) % length;
                K[c]= (char)sarray[t];
                CipherText[c] = (char)(HexaPT[c] ^ K[c]);
                c++;
            }

            string Finalresult = new string(CipherText);
            if (Ishexa)
            {
                StringBuilder builder = new StringBuilder();
               foreach (dynamic f in Finalresult)
                {
                    builder.Append(Convert.ToInt32(f).ToString("X"));
                }
                Finalresult= builder.ToString();
                Finalresult = "0x" + Finalresult;
            }
            return Finalresult;
           
        }
        public void shuffle(ref int x, ref int y)
        {

            int z=0;

            z = x;

            x = y;

            y = z;

        }
       
    }
}
