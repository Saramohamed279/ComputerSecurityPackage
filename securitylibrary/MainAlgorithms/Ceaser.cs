using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        int z = Convert.ToInt32('z');
        int a = Convert.ToInt32('a');

        public string Encrypt(string plainText, int key)
        {
            var cipher = new StringBuilder();

            for (int i = 0; i < plainText.Length; i++)
            {

                int letter = Convert.ToInt32(Char.ToLower(plainText[i]));
                int letter_with_key = letter + key;

                char cipher_letter;

                if(letter_with_key > z)
                {
                    cipher_letter = Convert.ToChar((Convert.ToInt32(letter_with_key) + a) % (z + 1));
                }
                else
                {
                    cipher_letter = Convert.ToChar(letter_with_key);
                }

                cipher.Append(cipher_letter);
            }
            return cipher.ToString();
        }

        public string Decrypt(string cipherText, int key)
        {
            var text = new StringBuilder();

            for (int i = 0; i < cipherText.Length; i++)
            {

                int letter = Convert.ToInt32(Char.ToLower(cipherText[i]));
                int letter_with_key = letter - key;

                char text_letter;

                if (letter_with_key < a)
                {
                    text_letter = Convert.ToChar(Convert.ToInt32(letter_with_key) + z + 1 - a);
                }
                else
                {
                    text_letter = Convert.ToChar(letter_with_key);
                }

                text.Append(text_letter);
            }
            return text.ToString();
        }

        public int Analyse(string plainText, string cipherText)
        {
            for(int i = 0; i<26; i++) {

                string test_cipher = Encrypt(plainText, i);

                if (test_cipher.Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))
                {
                    return i;
                }
            }

            return 0;
        }
    }
}
