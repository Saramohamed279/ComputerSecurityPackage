using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{


    /*
    Plain :  wearedisc overedsaveyourself
    Cipher : zicvtwqng kzeiigasxstslvvwla
    Key :    deciptive wearediscoveredsav


    Key :    deciptivezicvtwqngkzeiigasx
    Plain :  wearedisc
    {wearedisclrcnpkkfr}
     */

    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {

        string alphabet = "abcdefghijklmnopqrstuvwxyz";

        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();  
            var key = new StringBuilder();

            for(int i = 0; i < plainText.Length; i++)
            {
                int ctIndex = alphabet.IndexOf(cipherText[i]);
                int ptIndex = alphabet.IndexOf(plainText[i]);

                char letter;
                if(ctIndex - ptIndex  >= 0)
                {
                    letter = alphabet[(ctIndex - ptIndex)];
                }
                else
                {
                    letter = alphabet[(ctIndex - ptIndex + 26) % 26];
                }

                if (letter == plainText[0]) break;

                key.Append(letter);
            }

            return key.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();

            var actualKey = new StringBuilder(key);

            var plaintext = new StringBuilder();

            for (int i = 0; i < cipherText.Length; i++)
            {
                int ctIndex = alphabet.IndexOf(cipherText[i]);
                int keyIndex = alphabet.IndexOf(actualKey[i]);

                char letter = alphabet[(ctIndex - keyIndex + 26) % 26];

                plaintext.Append(letter);

                if(actualKey.Length < cipherText.Length)
                {
                    actualKey.Append(letter);
                }

            }

            return plaintext.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            int actualKeyLength = plainText.Length;

            var actualKey = new StringBuilder(key);

            int keyRange = actualKeyLength - key.Length; 

            for(int i = 0; i < keyRange; i++)
            {
                actualKey.Append(plainText[i]);
            }


            var cipherText = new StringBuilder();

            for(int i = 0; i < actualKeyLength; i++)
            {
                int ptIndex = alphabet.IndexOf(plainText[i]);
                int keyIndex = alphabet.IndexOf(actualKey[i]);

                char letter = alphabet[(ptIndex + keyIndex) % 26];

                cipherText.Append(letter);

            }

            return cipherText.ToString();

        }
    }
}
