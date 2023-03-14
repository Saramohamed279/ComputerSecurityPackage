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
            throw new NotImplementedException();
            //return null;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            throw new NotImplementedException();
            //return null;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            throw new NotImplementedException();
            
        }
    }
}
