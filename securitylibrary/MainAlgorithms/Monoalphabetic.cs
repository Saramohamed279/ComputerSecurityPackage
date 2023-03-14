using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            // key
            SortedDictionary<string, string> keydic = new SortedDictionary<string, string>();
            cipherText = cipherText.ToLower();
            List<string> cipherTex = cipherText.Select(c => c.ToString()).ToList();
            List<string> missing = new List<string>();
            var key = new StringBuilder();
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i].Equals('a')        && !keydic.ContainsKey("a"))
                    keydic.Add("a",cipherTex[i]);    
                if (plainText[i].Equals('b')        && !keydic.ContainsKey("b"))
                    keydic.Add("b", cipherTex[i]);   
                if (plainText[i].Equals('c')        && !keydic.ContainsKey("c"))
                    keydic.Add("c", cipherTex[i]);   
                if (plainText[i].Equals('d')        && !keydic.ContainsKey("d"))
                    keydic.Add("d", cipherTex[i]);   
                if (plainText[i].Equals('e')        && !keydic.ContainsKey("e"))
                    keydic.Add("e", cipherTex[i]);  
                if (plainText[i].Equals('f')        && !keydic.ContainsKey("f"))
                    keydic.Add("f", cipherTex[i]);  
                if (plainText[i].Equals('g')        && !keydic.ContainsKey("g"))
                    keydic.Add("g", cipherTex[i]);  
                if (plainText[i].Equals('h')        && !keydic.ContainsKey("h"))
                    keydic.Add("h", cipherTex[i]);  
                if (plainText[i].Equals('i')        && !keydic.ContainsKey("i"))
                    keydic.Add("i", cipherTex[i]);  
                if (plainText[i].Equals('j')        && !keydic.ContainsKey("j"))
                    keydic.Add("j", cipherTex[i]);  
                if (plainText[i].Equals('k')        && !keydic.ContainsKey("k"))
                    keydic.Add("k", cipherTex[i]);  
                if (plainText[i].Equals('l')        && !keydic.ContainsKey("l"))
                    keydic.Add("l", cipherTex[i]);   
                if (plainText[i].Equals('m')        && !keydic.ContainsKey("m"))
                    keydic.Add("m", cipherTex[i]);   
                if (plainText[i].Equals('n')        && !keydic.ContainsKey("n"))
                    keydic.Add("n", cipherTex[i]);   
                if (plainText[i].Equals('o')        && !keydic.ContainsKey("o"))
                    keydic.Add("o", cipherTex[i]);   
                if (plainText[i].Equals('p')        && !keydic.ContainsKey("p"))
                    keydic.Add("p", cipherTex[i]);   
                if (plainText[i].Equals('q')        && !keydic.ContainsKey("q"))
                    keydic.Add("q", cipherTex[i]);  
                if (plainText[i].Equals('r')        && !keydic.ContainsKey("r"))
                    keydic.Add("r", cipherTex[i]);   
                if (plainText[i].Equals('s')        && !keydic.ContainsKey("s"))
                    keydic.Add("s", cipherTex[i]);  
                if (plainText[i].Equals('t')        && !keydic.ContainsKey("t"))
                    keydic.Add("t", cipherTex[i]);   
                if (plainText[i].Equals('u')        && !keydic.ContainsKey("u"))
                    keydic.Add("u", cipherTex[i]);  
                if (plainText[i].Equals('v')        && !keydic.ContainsKey("v"))
                    keydic.Add("v", cipherTex[i]);  
                if (plainText[i].Equals('w')        && !keydic.ContainsKey("w"))
                    keydic.Add("w", cipherTex[i]);   
                if (plainText[i].Equals('x')        && !keydic.ContainsKey("x"))
                    keydic.Add("x", cipherTex[i]);   
                if (plainText[i].Equals('y')        && !keydic.ContainsKey("y"))
                    keydic.Add("y", cipherTex[i]); 
                if (plainText[i].Equals('z')        && !keydic.ContainsKey("z"))
                    keydic.Add("z", cipherTex[i]);
            }

            for(char i=(char)97;  i<=122; i++)
            {
               if (!keydic.ContainsKey(Convert.ToChar(i).ToString()))
                {
                    missing.Add(Convert.ToChar(i).ToString());
                }
            }
            int ccc = 0;
            if (missing.Count != 0)
            {
                for (char i = (char)97; i <= 122; i++)
                {
                    if (!keydic.ContainsValue(Convert.ToChar(i).ToString()) && ccc < missing.Count)
                    {
                        keydic.Add(missing[ccc], Convert.ToChar(i).ToString());
                        ccc++;
                    }
                }
            }
            for (char i = (char)97; i <= 122; i++)
            {
                key.Append(keydic[Convert.ToChar(i).ToString()]);

            }
            
            string final_key =key.ToString();

            return final_key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            // plaintext
            Console.WriteLine(key.ToString());
            Console.WriteLine(cipherText.ToString());
            List<string> listofkey = key.Select(c => c.ToString()).ToList();
            var realtext = new StringBuilder();
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                if(cipherText[i].Equals(key[0]))
                        realtext.Append("a");
                if (cipherText[i].Equals(key[1]))
                    realtext.Append("b");
                if (cipherText[i].Equals(key[2]))
                    realtext.Append("c");
                if (cipherText[i].Equals(key[3]))
                    realtext.Append("d");
                if (cipherText[i].Equals(key[4]))
                    realtext.Append("e");
                if (cipherText[i].Equals(key[5]))
                    realtext.Append("f");
                if (cipherText[i].Equals(key[6]))
                    realtext.Append("g");
                if (cipherText[i].Equals(key[7]))
                    realtext.Append("h");
                if (cipherText[i].Equals(key[8]))
                    realtext.Append("i");
                if (cipherText[i].Equals(key[9]))
                    realtext.Append("j");
                if (cipherText[i].Equals(key[10]))
                    realtext.Append("k");
                if (cipherText[i].Equals(key[11]))
                    realtext.Append("l");
                if (cipherText[i].Equals(key[12]))
                    realtext.Append("m");
                if (cipherText[i].Equals(key[13]))
                    realtext.Append("n");
                if (cipherText[i].Equals(key[14]))
                    realtext.Append("o");
                if (cipherText[i].Equals(key[15]))
                    realtext.Append("p");
                if (cipherText[i].Equals(key[16]))
                    realtext.Append("q");
                if (cipherText[i].Equals(key[17]))
                    realtext.Append("r");
                if (cipherText[i].Equals(key[18]))
                    realtext.Append("s");
                if (cipherText[i].Equals(key[19]))
                    realtext.Append("t");
                if (cipherText[i].Equals(key[20]))
                    realtext.Append("u");
                if (cipherText[i].Equals(key[21]))
                    realtext.Append("v");
                if (cipherText[i].Equals(key[22]))
                    realtext.Append("w");
                if (cipherText[i].Equals(key[23]))
                    realtext.Append("x");
                if (cipherText[i].Equals(key[24]))
                    realtext.Append("y");
                if (cipherText[i].Equals(key[25]))
                    realtext.Append("z");

            }
            Console.WriteLine(realtext.ToString());
            return realtext.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            //char[] aplha = Enumerable.Range('a', 'z' - 'a' + 1).Select(i => (Char)i).ToArray();
            //List<string> listofchars = plainText.Select(c => c.ToString()).ToList();
            List<string> listofkey = key.Select(c => c.ToString()).ToList();
            //List<string> []cipherlist = new List<string> [listofchars.Count];
           // Console.WriteLine(key);
            var cipherlist = new StringBuilder();
             for (int i = 0; i<plainText.Length;i++)
             {
                 switch (plainText[i])
                 {
                     case 'a':
                         cipherlist.Append(listofkey[0]);
                         break;
                     case 'b':
                        cipherlist.Append(listofkey[1]);
                        break;
                     case 'c':
                         cipherlist.Append(listofkey[2]);
                        break;
                     case 'd':
                         cipherlist.Append(listofkey[3]);
                        break;
                     case 'e':
                         cipherlist.Append(listofkey[4]);
                        break;
                     case 'f':
                         cipherlist.Append(listofkey[5]);
                        break;
                     case 'g':
                         cipherlist.Append(listofkey[6]);
                        break;
                     case 'h':
                         cipherlist.Append(listofkey[7]);
                        break;
                     case 'i':
                         cipherlist.Append(listofkey[8]);
                        break;
                     case 'j':
                         cipherlist.Append(listofkey[9]);
                        break;
                     case 'k':
                         cipherlist.Append(listofkey[10]);
                        break;
                     case 'l':
                         cipherlist.Append(listofkey[11]);
                        break;
                     case 'm':
                         cipherlist.Append(listofkey[12]);
                        break;
                     case 'n':
                         cipherlist.Append(listofkey[13]);
                        break;
                     case 'o':
                         cipherlist.Append(listofkey[14]);
                        break;
                     case 'p':
                         cipherlist.Append(listofkey[15]);
                        break;
                     case 'q':
                         cipherlist.Append(listofkey[16]);
                        break;
                     case 'r':
                         cipherlist.Append(listofkey[17]);
                        break;
                     case 's':
                         cipherlist.Append(listofkey[18]);
                        break;
                    case 't':
                         cipherlist.Append(listofkey[19]);
                        break;
                     case 'u':
                         cipherlist.Append(listofkey[20]);
                        break;
                     case 'v':
                         cipherlist.Append(listofkey[21]);
                        break;
                     case 'w':
                         cipherlist.Append(listofkey[22]);
                        break;
                     case 'x':
                         cipherlist.Append(listofkey[23]);
                        break;
                     case 'y':
                         cipherlist.Append(listofkey[24]);
                        break;
                     case 'z':
                         cipherlist.Append(listofkey[25]);
                        break;

                 }
             }
            //string cipheroutput = cipherlist.Aggregate("", (current, s) => current + (s));
            Console.WriteLine(cipherlist.ToString().ToUpper());
            return cipherlist.ToString().ToUpper();
            // cipher
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            throw new NotImplementedException();
            //key
        }
    }
}
