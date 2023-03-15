using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();

            cipherText.Replace("j", "i");
            key.Replace("j", "i");

            char[,] KeyMatrix = GetKeyMatrix(key);
            string plainText = DeCipher(cipherText , KeyMatrix);

            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();

            plainText.Replace("j", "i");
            key.Replace("j", "i");

            char[,] KeyMatrix = GetKeyMatrix(key);
            plainText = InsertX(plainText);

            string cypherText = Cipher(plainText, KeyMatrix);

            return cypherText;
        }

        public char[,] GetKeyMatrix(string key)
        {
            HashSet<char> UniqueKeyChars = new HashSet<char>();

            foreach (char c in key)
            {
                UniqueKeyChars.Add(c);
            }

            char[,] KeyMatrix = new char[5, 5];
            int index_i = 0, index_j = 0;

            foreach (char c in UniqueKeyChars)
            {
                if (c == 'j') continue;
                if (index_i >= 5 || index_j >= 5) break;
                KeyMatrix[index_i, index_j] = c;
                index_j++;
                if (index_j >= 5)
                {
                    index_i++;
                    if (index_i >= 5) break;
                    index_j = 0;
                }
            }

            for (char c = 'a'; c <= 'z'; c++)
            {
                if (c == 'j') continue;
                if (!UniqueKeyChars.Contains(c))
                {
                    if (index_i >= 5 || index_j >= 5) break;
                    KeyMatrix[index_i, index_j] = c;
                    index_j++;
                    if (index_j >= 5)
                    {
                        index_i++;
                        if (index_i >= 5) break;
                        index_j = 0;
                    }
                }
            }

            return KeyMatrix;
        }

        public string InsertX(string plainText)
        {
            while (true)
            {
                bool IsChanged = false;
                for (int i = 0; i < plainText.Length - 1; i += 2)
                {
                    if (plainText[i] == plainText[i + 1])
                    {
                        plainText = plainText.Insert(i + 1, "x");
                        IsChanged = true;
                        break;
                    }
                }
                if (!IsChanged) break;
            }
            if (plainText.Length % 2 == 1) plainText += 'x';

            return plainText;
        }

        public string Cipher(string plainText, char[,] KeyMatrix)
        {
            string cipherText = "";
            for (int k = 0; k < plainText.Length-1; k += 2)
            {
                int x1 = 0, x2 = 0, y1 = 0, y2 = 0;
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (plainText[k] == KeyMatrix[i, j])
                        {
                            x1 = i;
                            y1 = j;
                        }
                        else if (plainText[k + 1] == KeyMatrix[i, j])
                        {
                            x2 = i;
                            y2 = j;
                        }
                    }
                }
                if (x1 == x2)
                {
                    y1 = (y1 + 1) % 5;
                    y2 = (y2 + 1) % 5;

                    cipherText += KeyMatrix[x1, y1];
                    cipherText += KeyMatrix[x2, y2];
                }
                else if (y1 == y2)
                {
                    x1 = (x1 + 1) % 5;
                    x2 = (x2 + 1) % 5;

                    cipherText += KeyMatrix[x1, y1];
                    cipherText += KeyMatrix[x2, y2];
                }
                else
                {
                    cipherText += KeyMatrix[x1, y2];
                    cipherText += KeyMatrix[x2, y1];
                }
            }

            return cipherText;
        }

        public string DeCipher(string cipherText, char[,] KeyMatrix)
        {
            if (cipherText.Length % 2 == 1) cipherText += 'x';
            string plainText = "";
            for (int k = 0; k < cipherText.Length - 1; k += 2)
            {
                int x1 = 0, x2 = 0, y1 = 0, y2 = 0;
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (cipherText[k] == KeyMatrix[i, j])
                        {
                            x1 = i;
                            y1 = j;
                        }
                        else if (cipherText[k + 1] == KeyMatrix[i, j])
                        {
                            x2 = i;
                            y2 = j;
                        }
                    }
                }
                if (x1 == x2)
                {
                    y1 = (y1 - 1 + 5) % 5;
                    y2 = (y2 - 1 + 5) % 5;

                    plainText += KeyMatrix[x1, y1];
                    plainText += KeyMatrix[x2, y2];
                }
                else if (y1 == y2)
                {
                    x1 = (x1 - 1 + 5) % 5;
                    x2 = (x2 - 1 + 5) % 5;

                    plainText += KeyMatrix[x1, y1];
                    plainText += KeyMatrix[x2, y2];
                }
                else
                {
                    plainText += KeyMatrix[x1, y2];
                    plainText += KeyMatrix[x2, y1];
                }
            }

            for (int i = 1; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == 'x')
                {
                    if (plainText[i - 1] == plainText[i + 1])
                    {
                        plainText = plainText.Remove(i, 1);
                        i--;
                    }
                }
            }

            if (plainText[plainText.Length - 1] == 'x')
            {
                plainText = plainText.Remove(plainText.Length - 1 , 1);
            }

            return plainText;
        }
    }
}
