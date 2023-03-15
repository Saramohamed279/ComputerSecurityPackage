using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            int num_of_cols = 0;
            List<int> key = new List<int>();

            int depth = 0;
            int width = 0;
            char[,] table = new char[0, 0];

            for (int i = 2; i<100; i++)
            {
                depth = i;
                width = (int)Math.Ceiling((double)((double)plainText.Length / depth));
                table = devide_string_into_columns(plainText, depth);

                if(check_columns_exists_in_string(table, cipherText))
                {
                    break;
                }
            }

            for (int j = 0; j < width; j++)
            {
                var col = new StringBuilder();

                for (int i = 0; i < depth; i++)
                {
                    if (table[i, j] != '\0')
                    {
                        col.Append(table[i, j]);
                    }
                }

                key.Add(cipherText.IndexOf(col.ToString()) / depth + 1);
            }

            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int width = key.Count;
            int depth = (int)Math.Ceiling((double)((double)cipherText.Length / width));

            char[,] table = new char[depth, width];

            int row = 0;
            int col = 0;

            for (int i = 0; i < cipherText.Length; i++)
            {
                table[row, col] = cipherText[i];

                // fix this
                row++;
                if (row == depth)
                {
                    col = (col + 1) % width;
                    row = 0;
                }
            }

            List<int> decryption_key = new List<int>();

            for (int i = 0; i < key.Count; i++)
            {
                decryption_key.Add(-1);
            }

            for (int i = 0; i < key.Count; i++)
            {
                decryption_key[key[i] - 1] = i;
            }

            char[,] plainTable = new char[depth, width];

            for (int i = 0; i < key.Count; i++)
            {
                int col_number = decryption_key.IndexOf(i);

                for (int j = 0; j < depth; j++)
                {
                    plainTable[j, i] = table[j, col_number];

                }
            }

            var plain = new StringBuilder();

            for (int i = 0; i<depth; i++){
                
                for(int j = 0; j < width; j++)
                {
                    plain.Append(plainTable[i, j]);
                }

            }

            return plain.ToString();

        }


        public string Encrypt(string plainText, List<int> key)
        {
            int width = key.Count;
            int depth = (int)Math.Ceiling((double)((double)plainText.Length / width));

            char[,] table = new char[depth, width];

            int row = 0;
            int col = 0;

            for (int i = 0; i < plainText.Length; i++)
            {
                table[row, col] = plainText[i];

                // fix this
                col++;
                if (col == width)
                {
                    row = (row + 1) % depth;
                    col = 0;
                }
            }

            var cipher = new StringBuilder();

            for(int i = 0; i<key.Count; i++)
            {
                int col_number = key.IndexOf(i + 1);

                for(int j = 0; j< depth; j++)
                {
                    cipher.Append(table[j, col_number]);
                }
            }

            return cipher.ToString();
        }

        char[,] devide_string_into_columns(string text, int number_of_cols)
        {
            int depth = number_of_cols;
            int width = (int)Math.Ceiling((double)((double)text.Length / depth));

            char[,] table = new char[depth, width];

            int row = 0;
            int col = 0;

            for (int i = 0; i < text.Length; i++)
            {
                table[row, col] = text[i];

                // fix this
                col++;
                if (col == width)
                {
                    row = (row + 1) % depth;
                    col = 0;
                }
            }

            return table;
        }


        bool check_columns_exists_in_string(char[,] columns, string cipher)
        {
            int width = columns.GetLength(0);
            int depth = columns.GetLength(1);

            for(int j = 0; j< depth; j++)
            {
                var col = new StringBuilder();

                for (int i = 0; i < width; i++)
                {
                    if(columns[i, j] != '\0')
                    {
                        col.Append(columns[i, j]);
                    }
                }

                if (!cipher.Contains(col.ToString()))
                {
                    return false;
                }
            }
    
            return true;
        }

    }
}
