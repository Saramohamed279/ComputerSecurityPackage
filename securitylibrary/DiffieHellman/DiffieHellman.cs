using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        static int modulus(int bas, int pow, int m)
        {
            int p = 1;
            int a1 = bas % m;
            for (int i = 1; i <= pow; i++)
            {
                p *= a1;
                p = p % m;
            }
            return p;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {

            //throw new NotImplementedException();
            int Ya = modulus(alpha, xa, q);
            int Yb = modulus(alpha, xb, q);
            int Ka = modulus(Yb, xa, q);
            int Kb = modulus(Ya, xb, q);
            List<int> keys = new List<int> { Ka, Kb };
            return keys;

        }
    }
}
