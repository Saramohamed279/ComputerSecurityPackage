using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {

            for (int i = 1; i <= 100; i++)
            {
                if (Encrypt(plainText, i).Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))
                {
                    return i;
                }
            }
            return 0;
        }

        public string Decrypt(string cipherText, int key)
        {
            int depth = key;
            int width = (int)Math.Ceiling((double)((double)cipherText.Length / key));

            char[,] table = new char[depth, width];

            int row = 0;
            int col = 0;

            for (int i = 0; i < cipherText.Length; i++)
            {
                table[row, col] = cipherText[i];

                // fix this
                col++;
                if (col == width)
                {
                    row = (row + 1) % depth;
                    col = 0;
                }
            }

            var text = new StringBuilder();

            for (int i = 0; i < width; i++)
            {
                for (int j = 0; j < depth; j++)
                {
                    text.Append(table[j, i]);
                }
            }

            return text.ToString();

        }

        public string Encrypt(string plainText, int key)
        {
            int depth = key;
            int width = (int)Math.Ceiling((double)((double)plainText.Length / key));

            char[,] table = new char[depth, width];

            int row = 0;
            int col = 0;

            for (int i = 0; i < plainText.Length; i++)
            {
                table[row, col] = plainText[i];

                // fix this
                row++;
                if (row == depth)
                {
                    col = (col + 1) % width;
                    row = 0;
                }
            }

            var cipher = new StringBuilder();

            for (int i = 0; i < depth; i++)
            {
                for (int j = 0; j < width; j++)
                {
                    cipher.Append(table[i, j]);
                }
            }

            return cipher.ToString();
        }
    }
}
