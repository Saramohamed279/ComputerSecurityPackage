using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = N(p, q);
            int C = IterativePower(M, e, n);

            return C;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = N(p, q);
            int euler = Euler(p, q);
            int d = D(e, euler);
            int M = IterativePower(C, d, n);

            return M;
        }

        private static int N(int p, int q)
        {
            return p * q;
        }

        private static int Euler(int p, int q)
        {
            return (p - 1) * (q - 1);
        }

        private static int D(int e, int euler)
        {
            return ModInv(e, euler);
        }

        private static int IterativePower(int b, int p, int mod)
        {
            int ret = 1;
            b %= mod;
            
            for (int i = 0; i < p; i++)
            {
                ret = (ret * b) % mod;
            }

            return ret;
        }

        private static int ModInv(int num, int mod)
        {
            int i = mod, ret = 0, d = 1;
            
            while (num > 0)
            {
                int t = i / num;
                int x = num;
                num = i % x;
                i = x;
                x = d;
                d = ret - t * x;
                ret = x;
            }
            
            ret = (ret%mod + mod) % mod;
            
            return ret;
        }
    }
}
