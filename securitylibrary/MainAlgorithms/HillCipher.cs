using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<List<int>> CT2mul6 = new List<List<int>>();
            List<List<int>> PT2mul6 = new List<List<int>>();
            int n = plainText.Count;

            List<List<int>> CTrowbased = new List<List<int>>();
            List<List<int>> PTrowbased = new List<List<int>>();
            int m = (plainText.Count / 2);
            for (int i = 0; i < n; i += 2)
            {
                List<int> CTcolumns = new List<int>();
                List<int> PTcolumns = new List<int>();
                
                CTcolumns.Add(cipherText[i]);
                CTcolumns.Add(cipherText[i + 1]);
                CT2mul6.Add(CTcolumns);

                PTcolumns.Add(plainText[i]);
                PTcolumns.Add(plainText[i + 1]);
                PT2mul6.Add(PTcolumns);
            }
           
            for (int i = 0; i < m - 1; i++)//two times 
            {
                for (int j = i + 1; j < m; j++)
                {
                    //pt columns advances pt row based
                    List<int> CTcolumns = new List<int>();
                    List<int> PTcolumns = new List<int>();
                    
                    CTcolumns.Add(CT2mul6[i].ElementAt(0));
                    CTcolumns.Add(CT2mul6[i].ElementAt(1));
                    CTcolumns.Add(CT2mul6[j].ElementAt(0));
                    CTcolumns.Add(CT2mul6[j].ElementAt(1));
                    CTrowbased.Add(CTcolumns);
                   
                    
                    PTcolumns.Add(PT2mul6[i].ElementAt(0));
                    PTcolumns.Add(PT2mul6[i].ElementAt(1));
                    PTcolumns.Add(PT2mul6[j].ElementAt(0));
                    PTcolumns.Add(PT2mul6[j].ElementAt(1));
                    PTrowbased.Add(PTcolumns);
                }
            }
            int k = 4;
            int alphabetnum = 26;
            for (int i = 0; i < PTrowbased.Count; i++)
            {
                List<int> detcorrection = new List<int>();
                for (int j = 0; j < k; j++)
                {
                     if (PTrowbased[i].ElementAt(j) >= alphabetnum)
                    {
                        detcorrection.Insert(j, (PTrowbased[i].ElementAt(j) % alphabetnum));
                    }
                    else if (PTrowbased[i].ElementAt(j) < 0)
                    {
                        detcorrection.Insert(j, (PTrowbased[i].ElementAt(j) % alphabetnum) + alphabetnum);
                    }
                   
                    else
                        detcorrection.Insert(j, PTrowbased[i].ElementAt(j));
                }
                int A;
                A = ((detcorrection[0] * detcorrection[3]) - (detcorrection[1] * detcorrection[2]));

                int DetConstant;
                //GCD
                if (A != 1 && A != -1)
                {
                    int a = A;
                    int b = alphabetnum;

                    int x0 = 1,  x1 = 0, xn = 1;
                    int y0 = 0, y1 = 1, yn;
                  
                    // b == 0 ? a : Gcd(b, a % b);
                    int modulus = a % b;

                    while (modulus > 0)
                    {
                        int div = a / b;
                        yn = y0 - div * y1;
                        xn = x0 - div * x1;//1
                    
                        x0 = x1;  y0 = y1;  x1 = xn;  y1 = yn;
                        a = b; b = modulus; modulus = a % b;
                    }

                    DetConstant = xn;
                    int num=26;
                    if (DetConstant < 0)
                    {
                        DetConstant += num;
                    }
                   
                }
                else
                {
                    DetConstant = A;
                }
                List<int> PlainInversion = new List<int>();

                PlainInversion.Insert(0, detcorrection[3] * DetConstant);
                PlainInversion.Insert(1, detcorrection[1] * DetConstant * -1);
                PlainInversion.Insert(2, detcorrection[2] * DetConstant * -1);
                PlainInversion.Insert(3, detcorrection[0] * DetConstant);

                List<int> keytwomultwo = new List<int>();
                keytwomultwo.Insert(0, (CTrowbased[i].ElementAt(0) * PlainInversion[0]) + (CTrowbased[i].ElementAt(2) * PlainInversion[1]));
                keytwomultwo.Insert(1, (CTrowbased[i].ElementAt(0) * PlainInversion[2]) + (CTrowbased[i].ElementAt(2) * PlainInversion[3]));
                keytwomultwo.Insert(2, (CTrowbased[i].ElementAt(1) * PlainInversion[0]) + (CTrowbased[i].ElementAt(3) * PlainInversion[1]));
                keytwomultwo.Insert(3, (CTrowbased[i].ElementAt(1) * PlainInversion[2]) + (CTrowbased[i].ElementAt(3) * PlainInversion[3]));
                
                int row=4;
                List<int> correctkey= new List<int>();
                for (int j = 0; j < row; j++)
                {
                      if (keytwomultwo[j] >= alphabetnum)
                    {
                        correctkey.Insert(j, (keytwomultwo[j] % alphabetnum));
                    }
                   else  if (keytwomultwo[j] < 0)
                    {
                        correctkey.Insert(j, (keytwomultwo[j] % alphabetnum) + alphabetnum);
                    }

                    else {
                        correctkey.Insert(j, keytwomultwo[j]);
                    }
                        
                }
                List<int> ReturnedCipher = new List<int>();
                ReturnedCipher = Encrypt(plainText, correctkey);
                if (ReturnedCipher.SequenceEqual(cipherText))
                {

                    return correctkey;
                }

            }
            throw new InvalidAnlysisException();
            //return null;
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int num = 26;
            List<int> keycorrection = new List<int>();
            int keyLength = key.Count;
            for (int i = 0; i < keyLength; i++)
            {
                 if (key[i] >= num)
                {
                    keycorrection.Insert(i, (key[i] %num));
                }
               else if (key[i] < 0)
                {
                    keycorrection.Insert(i, (key[i] % num) + num);
                }
                
                else
                    keycorrection.Insert(i, key[i]);
            }
            int m = 4;
            List<int> keyInversion = new List<int>();
            int KeyCounter = keycorrection.Count;
            int keynum = key.Count;
            if (KeyCounter == m)
            {
                int InitDeterminant = (key[0] * key[3]) - (key[1] * key[2]);
                if ((InitDeterminant % 2) == 0 || InitDeterminant == 0 || (InitDeterminant % num) == 0)
                {
                    throw new InvalidAnlysisException();
                }
                int A;
                int DetConstant;
                int firstHalf = (keycorrection[0] * keycorrection[3]);
                int secondHalf = (keycorrection[1] * keycorrection[2]);
                A = (firstHalf - secondHalf);
                
                if (A != 1 && A != -1)
                {
                    int a = A;
                    int b = num;

                    int x0 = 1, x1 = 0, xn = 1;
                    int y0 = 0, y1 = 1,yn ;
                    
                    int modulus = a % b;
                    
                    while (modulus > 0)
                    {
                       int div = a / b;
                        yn = y0 - div * y1;
                        xn = x0 - div * x1;


                        x0 = x1; x1 = xn;
                        y0 = y1; y1 = yn;
                        a = b; b = modulus; modulus = a % b;
                    }
                    DetConstant = xn;
                    if (DetConstant < 0)
                    {
                        DetConstant += num;
                    }
                }
                else
                {
                    DetConstant = A;
                }
                keyInversion.Insert(0, keycorrection[3] * DetConstant);
                keyInversion.Insert(1, keycorrection[1] * DetConstant * -1);
                keyInversion.Insert(2, keycorrection[2] * DetConstant * -1);
                keyInversion.Insert(3, keycorrection[0] * DetConstant);
            }
            
            else if (keynum > m)
            {
                int RuleOne=0;
                int cofactors1 = (keycorrection[4] * keycorrection[8] - keycorrection[5] * keycorrection[7]);
                int cofactors2 = (keycorrection[3] * keycorrection[8] - keycorrection[5] * keycorrection[6]);
                int cofactors3 = (keycorrection[3] * keycorrection[7] - keycorrection[4] * keycorrection[6]);
               int Det3mul3 = ((keycorrection[0] * cofactors1) - (keycorrection[1] *cofactors2 ) + (keycorrection[2] * cofactors3));
                if ((Det3mul3 % 2) == 0 || Det3mul3 == 0 ||  (Det3mul3 % num) == 0)
                {
                    throw new InvalidAnlysisException();
                }
               
                if (Det3mul3 >= num)
                {
                    RuleOne = num;
                    
                }
                else if (Det3mul3 < num)
                {
                    RuleOne = Det3mul3;
                }
                int count = 2;
                for (int j = RuleOne; j >= count; j--)
                {
                    if (num % j == 0&& Det3mul3 % j == 0)
                    {
                       //gcd checking
                        throw new InvalidAnlysisException();
                    }
                }
                int modifiedDet;
                modifiedDet = Det3mul3 % num;
                if (modifiedDet < 0)
                {
                    modifiedDet += num;
                }
              
                int y;
                int Count = 0;
               
                while (true)
                {
                    float c = ((float)((float)(Count * num) + 1) / (float)(num - modifiedDet));
                   
                    if (c == (int)c)
                    {
                        y = (int)c;
                        break;
                    }
                    else
                    {
                        Count++;
                    }
                }
                    int b = num - y;
                List<int> keyInversionbefTrans = new List<int>();
                //matrices of cofactors
                keyInversionbefTrans.Insert(0, b * cofactors1);
                keyInversionbefTrans.Insert(1, -1 * b * cofactors2);
                keyInversionbefTrans.Insert(2, b *cofactors3);
                int cofactors4 = (keycorrection[1] * keycorrection[8] - keycorrection[2] * keycorrection[7]);
                keyInversionbefTrans.Insert(3, -1 * b * cofactors4);
                int cofactors5 = (keycorrection[0] * keycorrection[8] - keycorrection[2] * keycorrection[6]);
                keyInversionbefTrans.Insert(4, b *cofactors5);
                int cofactors6 = (keycorrection[0] * keycorrection[7] - keycorrection[1] * keycorrection[6]);
                keyInversionbefTrans.Insert(5, -1 * b * cofactors6);
                int cofactors7 = (keycorrection[1] * keycorrection[5] - keycorrection[2] * keycorrection[4]);
                keyInversionbefTrans.Insert(6, b *cofactors7 );
                int cofactors8 = (keycorrection[0] * keycorrection[5] - keycorrection[2] * keycorrection[3]);
                keyInversionbefTrans.Insert(7, -1 * b * cofactors8);
                int cofactors9 = (keycorrection[0] * keycorrection[4] - keycorrection[1] * keycorrection[3]);
                keyInversionbefTrans.Insert(8, b *cofactors9 );
               
                //inverse of key after transpose
                keyInversion.Insert(0, keyInversionbefTrans[0]);
                keyInversion.Insert(1, keyInversionbefTrans[3]);
                keyInversion.Insert(2, keyInversionbefTrans[6]);
                keyInversion.Insert(3, keyInversionbefTrans[1]);
                keyInversion.Insert(4, keyInversionbefTrans[4]);
                keyInversion.Insert(5, keyInversionbefTrans[7]);
                keyInversion.Insert(6, keyInversionbefTrans[2]);
                keyInversion.Insert(7, keyInversionbefTrans[5]);
                keyInversion.Insert(8, keyInversionbefTrans[8]);
            }
           
            List<int> DecryptionText = new List<int>();
            int CTLen = cipherText.Count;
            int squareKey = (int)(Math.Sqrt(key.Count));
            //int len = 26;
            for (int i = 0; i < CTLen; i++)
            {
                DecryptionText.Insert(i, 0);
            }
            int RowIndecies = 0;
            int matrixId = 0;
            for (int i = 0; i < CTLen; i++)
            {

                for (int j = 0; j < squareKey; j++)
                {

                    if ((i % (squareKey)) == 0)
                    {
                        matrixId = i;
                    }
                    else
                    {
                        int k = i;
                        
                        while (k >= 0)
                        {
                            if ((k % (squareKey)) == 0)
                            {
                                matrixId = k;
                                break;
                            }
                            k--;
                        } 

                    }
                    DecryptionText[i] += keyInversion[j + (RowIndecies * squareKey)] * cipherText[matrixId + j];
                }
               
                DecryptionText[i] = DecryptionText[i] % num;
                if (RowIndecies == (squareKey - 1))
                {
                    RowIndecies = 0;
                }
                else
                {
                    RowIndecies++;
                }
            }

            int DTlen = DecryptionText.Count;
            for (int i = 0; i < DTlen; i++)
            {
                 if (DecryptionText[i] >= num)
                {
                    DecryptionText[i] = DecryptionText[i] % num;

                }
               else if (DecryptionText[i] < 0)
                {
                    DecryptionText[i] = DecryptionText[i] %num;
                    DecryptionText[i] += num;
                }
                
            }
            return DecryptionText;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int key_length = key.Count;
            int p = plainText.Count;
            if (key_length % 2 == 0)
            {
                key_length /= 2;
            }
            else if (key_length % 2 == 1)
            {
                key_length /= 2;
                key_length = key_length - 1;
            }

            int m = p / key_length;//6
            int[,] keymatrix = new int[key_length, key_length];
            //it is used to form 2*2 key matrix
            int key_index = 0;
            for (int i = 0; i < key_length; i++)
            {
                int index = key_index;
                for (int j = 0; j < key_length; j++)
                {
                    keymatrix[i, j] = key[index];
                    key_index++;
                    index++;
                }
                index = key_index;
            }
            key_index = 0;
            int[,] plainmatrix = new int[key_length, m];
            for (int i = 0; i < m; i++)
            {
                int index = key_index;
                for (int j = 0; j < key_length; j++)
                {
                    plainmatrix[j, i] = plainText[index];
                    key_index++;
                    index++;
                }
                index = key_index;
            }
            int[,] ciphermatrix = new int[key_length, m];
            for (int i = 0; i < key_length; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    int totalSum = 0;
                    for (int c = 0; c < key_length; c++)
                    {
                        totalSum += keymatrix[i, c] * plainmatrix[c, j];
                    }
                    ciphermatrix[i, j] = totalSum % 26;
                }
            }
            List<int> Finalcipher = new List<int>();
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < key_length; j++)
                {
                    Finalcipher.Add(ciphermatrix[j, i]);
                }
            }
            return Finalcipher;

        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            //throw new Exception();
            int n = plainText.Count;
            List<List<int>> CT2mul6 = new List<List<int>>();
            List<List<int>> PT2mul6 = new List<List<int>>();

            List<List<int>> CTrowbased = new List<List<int>>();
            List<List<int>> PTrowbased = new List<List<int>>();

            int m = (plainText.Count / 3);
            for (int i = 0; i < n; i += 3)
            {
               

                List<int> CTcolumns = new List<int>();
                List<int> PTcolumns = new List<int>();

                CTcolumns.Add(cipherText[i]);
                CTcolumns.Add(cipherText[i + 1]);
                CTcolumns.Add(cipherText[i + 2]);
                CT2mul6.Add(CTcolumns);

               
                PTcolumns.Add(plainText[i]);
                PTcolumns.Add(plainText[i + 1]);
                PTcolumns.Add(plainText[i + 2]);
                PT2mul6.Add(PTcolumns);
            }
            

            for (int i = 0; i < m - 1; i++)
            {
                for (int j = i + 1; j < m; j++)
                {
                    for (int k = j + 1; k < m; k++)

                    {
                        List<int> CTcolumns = new List<int>();
                        List<int> PTcolumns = new List<int>();
                        CTcolumns.Add(CT2mul6[i].ElementAt(0));
                        CTcolumns.Add(CT2mul6[i].ElementAt(1));
                        CTcolumns.Add(CT2mul6[i].ElementAt(2));
                        CTcolumns.Add(CT2mul6[j].ElementAt(0));
                        CTcolumns.Add(CT2mul6[j].ElementAt(1));
                        CTcolumns.Add(CT2mul6[j].ElementAt(2));
                        CTcolumns.Add(CT2mul6[k].ElementAt(0));
                        CTcolumns.Add(CT2mul6[k].ElementAt(1));
                        CTcolumns.Add(CT2mul6[k].ElementAt(2));
                        CTrowbased.Add(CTcolumns);
                       
                        PTcolumns.Add(PT2mul6[i].ElementAt(0));
                        PTcolumns.Add(PT2mul6[i].ElementAt(1));
                        PTcolumns.Add(PT2mul6[i].ElementAt(2));
                        PTcolumns.Add(PT2mul6[j].ElementAt(0));
                        PTcolumns.Add(PT2mul6[j].ElementAt(1));
                        PTcolumns.Add(PT2mul6[j].ElementAt(2));
                        PTcolumns.Add(PT2mul6[k].ElementAt(0));
                        PTcolumns.Add(PT2mul6[k].ElementAt(1));
                        PTcolumns.Add(PT2mul6[k].ElementAt(2));
                        PTrowbased.Add(PTcolumns);
       
                    }

                }
            }
            int alphabetnum = 26;
            int ptr = PTrowbased.Count;
            for (int i = 0; i <ptr ; i++)
            {
                List<int> detCorrection = new List<int>();
                for (int j = 0; j < PTrowbased[i].Count; j++)
                {
                    if (PTrowbased[i].ElementAt(j) >= alphabetnum)
                    {
                        detCorrection.Insert(j, (PTrowbased[i].ElementAt(j) % alphabetnum));
                    }
                   else if (PTrowbased[i].ElementAt(j) < 0)
                    {
                        detCorrection.Insert(j, (PTrowbased[i].ElementAt(j) % alphabetnum) + alphabetnum);
                    }
                    
                    else
                        detCorrection.Insert(j, PTrowbased[i].ElementAt(j));
                }

                int A;
                int cofactors1 = (detCorrection[4] * detCorrection[8] - detCorrection[5] * detCorrection[7]);
                int cofactors2 = (detCorrection[3] * detCorrection[8] - detCorrection[5] * detCorrection[6]);
                int cofactors3 = (detCorrection[3] * detCorrection[7] - detCorrection[4] * detCorrection[6]);
               
                A = (detCorrection[0] * cofactors1) - (detCorrection[1] * cofactors2) + (detCorrection[2] * cofactors3);
                int InitialRule=0;
                if (A < alphabetnum)
                {
                    InitialRule = A;
                }
                else if (A >= alphabetnum)
                {
                    InitialRule = alphabetnum ;
                }
                if (A == 0)
                {
                    throw new InvalidAnlysisException();
                }


                //bool GCD = false;
               
                int modDet = A % alphabetnum;
                if (modDet < 0)
                {
                    modDet += alphabetnum;
                }
                int o = 2;
                for (int l = InitialRule; l >= o; l--)
                {
                    if (alphabetnum % l == 0 && A % l == 0)
                    {
                        //GCD = true;
                        throw new InvalidAnlysisException();
                    }
                }

                int y ;
                int Count = 0;
                
                while (true)
                {
                    float c;
                    c = ((float)((float)(Count * alphabetnum) + 1) / (float)(alphabetnum - modDet));
                   
                    if ((c == (int)c))
                    {
                        y = (int)c;
                        break;
                    }
                    else
                    {
                        Count++;
                    }
                }
                List<int> PTInversion = new List<int>();
                int b = alphabetnum - y;
                List<int> KeyInversionbefTrans = new List<int>();
                
                KeyInversionbefTrans.Insert(0, b * cofactors1);
                KeyInversionbefTrans.Insert(1, -1 * b * cofactors2);
                KeyInversionbefTrans.Insert(2, b * cofactors3);
                int cofactors4 = (detCorrection[1] * detCorrection[8] - detCorrection[2] * detCorrection[7]);
                KeyInversionbefTrans.Insert(3, -1 * b * cofactors4);
                int cofactors5 = (detCorrection[0] * detCorrection[8] - detCorrection[2] * detCorrection[6]);
                KeyInversionbefTrans.Insert(4, b * cofactors5);
                int cofactors6 = (detCorrection[0] * detCorrection[7] - detCorrection[1] * detCorrection[6]);
                KeyInversionbefTrans.Insert(5, -1 * b * cofactors6);
                int cofactors7 = (detCorrection[1] * detCorrection[5] - detCorrection[2] * detCorrection[4]);
                KeyInversionbefTrans.Insert(6, b * cofactors7);
                int cofactors8 = (detCorrection[0] * detCorrection[5] - detCorrection[2] * detCorrection[3]);
                KeyInversionbefTrans.Insert(7, -1 * b *cofactors8 );
                int cofactors9 = (detCorrection[0] * detCorrection[4] - detCorrection[1] * detCorrection[3]);
                KeyInversionbefTrans.Insert(8, b *cofactors9 );
                PTInversion.Insert(0, KeyInversionbefTrans[0]);
                PTInversion.Insert(1, KeyInversionbefTrans[3]);
                PTInversion.Insert(2, KeyInversionbefTrans[6]);
                PTInversion.Insert(3, KeyInversionbefTrans[1]);
                PTInversion.Insert(4, KeyInversionbefTrans[4]);
                PTInversion.Insert(5, KeyInversionbefTrans[7]);
                PTInversion.Insert(6, KeyInversionbefTrans[2]);
                PTInversion.Insert(7, KeyInversionbefTrans[5]);
                PTInversion.Insert(8, KeyInversionbefTrans[8]);
                int PTLen = PTInversion.Count;
                for (int j = 0; j <PTLen ; j++)
                {
                    
                    if (PTInversion[j] >= alphabetnum)
                    {
                        PTInversion[j] = PTInversion[j] % alphabetnum;

                    }
                   else if (PTInversion[j] < 0)
                    {
                        PTInversion[j] = PTInversion[j] % alphabetnum;
                        PTInversion[j] += alphabetnum;
                    }
                }
               
                
                List<int> DecryptionText = new List<int>();
                List<int> TransCT = new List<int>();
                int RowIndecies = 0;
                int num = 9;
                for (int k = 0; k < num; k++)
                {
                    DecryptionText.Insert(k, 0);
                }
               

                TransCT.Insert(0, CTrowbased[i].ElementAt(0));
                TransCT.Insert(1, CTrowbased[i].ElementAt(3));
                TransCT.Insert(2, CTrowbased[i].ElementAt(6));
                TransCT.Insert(3, CTrowbased[i].ElementAt(1));
                TransCT.Insert(4, CTrowbased[i].ElementAt(4));
                TransCT.Insert(5, CTrowbased[i].ElementAt(7));
                TransCT.Insert(6, CTrowbased[i].ElementAt(2));
                TransCT.Insert(7, CTrowbased[i].ElementAt(5));
                TransCT.Insert(8, CTrowbased[i].ElementAt(8));

                int MatrixID = 0;
                for (int q = 0; q < num; q++)
                {

                    for (int j = 0; j < 3; j++)
                    {
                        int modq = q % (3);
                        if (modq == 0)
                        {
                            MatrixID = q;
                        }
                        else
                        {
                            for (int d = q; d >= 0; d--)

                            {
                                int modd = d % (3);
                                if (modd == 0)
                                {
                                    MatrixID = d;
                                    break;
                                }
                            }

                        }
                        DecryptionText[q] += TransCT[j + (RowIndecies * 3)] * PTInversion[MatrixID + j];
                    }
                   
                    if (RowIndecies == 2)
                    {
                        RowIndecies = 0;
                    }
                    else
                    {
                        RowIndecies++;
                    }
                    DecryptionText[q] = DecryptionText[q] % alphabetnum;
                }
                List<int> ThreeMultKey = new List<int>();
                List<int> DecText;
                ThreeMultKey.Insert(0, DecryptionText[0]);
                ThreeMultKey.Insert(1, DecryptionText[3]);
                ThreeMultKey.Insert(2, DecryptionText[6]);
                ThreeMultKey.Insert(3, DecryptionText[1]);
                ThreeMultKey.Insert(4, DecryptionText[4]);
                ThreeMultKey.Insert(5, DecryptionText[7]);
                ThreeMultKey.Insert(6, DecryptionText[2]);
                ThreeMultKey.Insert(7, DecryptionText[5]);
                ThreeMultKey.Insert(8, DecryptionText[8]);
              
                DecText = Encrypt(plainText, ThreeMultKey);
                if (DecText.SequenceEqual(cipherText))
                {

                    return ThreeMultKey;
                }
            }
            throw new InvalidAnlysisException();

    }
    }
}
