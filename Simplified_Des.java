package simplified.des;

import java.util.Arrays;

/**
 * Simplified-DES Algorithm, from W.Stalling's Book Cryptograpgy and Network
 * Security,Forth Edition.
 *
 * @author Nikolaos Bafatakis A.E.M 2383
 */
public abstract class Simplified_Des {

    private static final int[] p10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6}; //mode=10
    private static final int[] p8 = {6, 3, 7, 4, 8, 5, 10, 9};  //mode=8
    private static final int[] p4 = {2, 4, 3, 1}; //mode=4
    private static final int[] ip = {2, 6, 3, 1, 4, 8, 5, 7}; //mode=-2
    private static final int[] ip_1 = {4, 1, 3, 5, 7, 2, 8, 6}; //mode=-3
    private static final int[] e_p = {4, 1, 2, 3, 2, 3, 4, 1}; //mode=-1
    private static final int[][] s0 = {{1, 0, 3, 2}, {3, 2, 1, 0}, {0, 2, 1, 3}, {3, 1, 3, 2}};
    private static final int[][] s1 = {{0, 1, 2, 3}, {2, 0, 1, 3}, {3, 0, 1, 0}, {2, 1, 0, 3}};

    /**
     * Function that encrypts a message.
     *
     * @param plaintext The plaintext provided
     * @param key The key agreed.
     * @return The decrypted message.
     */
    public static char[] encrypt(char[] plaintext, char[] key) {
        char[] k1 = new char[8];
        char[] k2 = new char[8];
        char[][] temp = makeSubKeys(key);

        k1 = temp[0];
        k2 = temp[1];

        return permutation(f_k(SW(f_k(permutation(plaintext, -2), k1)), k2), -3);

    }

    /**
     * Function that decrypts a message.
     *
     * @param ciphertext The ciphertext provided.
     * @param key the key agreed.
     * @return the decrypted message.
     */
    public static char[] decrypt(char[] ciphertext, char[] key) {
        char[] k1 = new char[8];
        char[] k2 = new char[8];
        char[][] temp = makeSubKeys(key);

        k1 = temp[0];
        k2 = temp[1];
        //This is the reverse function as described in Staling's paper.
        return permutation(f_k(SW(f_k(permutation(ciphertext, -2), k2)), k1), -3);

    }

    /**
     * Function that creates the two subkeys needed both for encryption and
     * decryption.
     *
     * @param key the key
     * @return the 2 keys, K1 and K2
     */
    private static char[][] makeSubKeys(char[] key) {
        //KI,K2
        char[][] result = {permutation(shift(permutation(key, 10), 0), 8), permutation(shift(shift(shift(permutation(key, 10), 0), 0), 0), 8)};
        return result;
    }

    /**
     * This function performes the permutation needed as the paper describes.
     *
     * @param k the array to be permutated
     * @param mode the permutation mode ex. P10,P8,P4,IP,IP^-1,E/P
     * @return
     */
    private static char[] permutation(char[] k, int mode) { //permutation
        int pMatrix[];
        char result[];
        //Select the mode,for every permutation mode, an array is available
        if (mode == 10) {
            pMatrix = p10;
            result = new char[10];
        } else if (mode == 8) {
            pMatrix = p8;
            result = new char[8];
        } else if (mode == -1) {
            pMatrix = e_p;
            result = new char[8];
        } else if (mode == -2) {
            pMatrix = ip;
            result = new char[8];
        } else if (mode == -3) {
            pMatrix = ip_1;
            result = new char[8];
        } else {
            pMatrix = p4;
            result = new char[4];
        }
        //Alter the table based on pMatrix
        for (int i = 0; i < pMatrix.length; i++) {
            result[i] = k[pMatrix[i] - 1];
        }
        return result;
    }

    /**
     * Recursive method that performs a left circular shift in an array.
     *
     * @param k an array
     * @param num the number of times the shift will be executed,not working to
     * be implemented in future versions(!)..
     * @return the shifted array. ex input={1,2,3,4,5,6,7,8,9,10},
     * output={2,3,4,5,1,7,8,9,10,6}
     */
    private static char[] shift(char k[], int num) {
        char[] result = new char[k.length];
        int count = 0;
        //If the array has longer than 5 positions, in our case the initial array has 10
        if (k.length > 5) {
            char[] array = new char[5];
            //split them and recursively call the method on each of the seperated arrays
            char[] array1 = shift(Arrays.copyOf(k, 5), 0);
            char[] array2 = shift(Arrays.copyOfRange(k, 5, k.length), 0);
            for (int i = 0; i < array1.length; i++) {
                result[i] = array1[i];
            }
            //concat them in a final array
            for (int i = 0; i < array2.length; i++) {
                result[i + array1.length] = array2[i];
            }
            //else if the array has exactly 5 positions
        } else if (k.length == 5) {
            result = new char[5];
            //shift the array into the new array
            for (int i = 0; i <= 3; i++) {
                result[i] = k[i + 1];
            }
            result[4] = k[0];
        }
        return result;
    }

    /**
     * This is the most complex component of the S-DES,which consists of a
     * combination of permutation and substitution functions.The function was
     * build as it was descried in the paper f_k(L,R)=(L OR F(R,SK),R) where L,R
     * the left and right parts of the plaintext.
     *
     * @param m the plaintext
     * @param key the sub-key
     * @return the result
     */
    private static char[] f_k(char[] m, char[] key) {
        char[] l = Arrays.copyOfRange(m, 0, 4); //the left portion of the message
        char[] r = Arrays.copyOfRange(m, 4, m.length); //the right portion of the message.
        char[] F = f(r, key); //assign the result of the f function to an array
        char[] result = new char[8];
        for (int i = 0; i < r.length; i++) { //The bit-by-bit exclusive-OR mechanism
            if ((l[i] == '0' && F[i] == '0') || (l[i] == '1' && F[i] == '1')) {
                result[i] = '0';
            } else {
                result[i] = '1';
            }
        }
        //The left and right messages are combined.
        for (int j = 0; j < 4; j++) {
            result[j + 4] = r[j];
        }
        return result;
    }

    /**
     * The F function as described in W.Stalling's paper.
     * @param r a 4-bit number
     * @param some_key a key.
     * @return the result
     */
    private static char[] f(char[] r, char[] some_key) {
        char[] n = new char[r.length * 2];
        //Expansion operation
        for (int i = 0; i < n.length; i++) {
            if (i < r.length) {
                n[i] = r[i];
            } else {
                n[i] = r[i - 4];
            }
        }
        n = permutation(n, -1);//Permutation E/P
        //The subkey some_key is added to array 'n' using exclusive-OR
        for (int i = 0; i < n.length; i++) {
            if ((n[i] == '0' && some_key[i] == '0') || (n[i] == '1' && some_key[i] == '1')) {
                n[i] = '0';
            } else {
                n[i] = '1';
            }
        }
        /*Interchange the bits in array 'n' so that
         the first and forth produces an 2-bit number with range 0-3 and 
        second and third a 2-bit number with range 0-3
         */
        char temp;
        temp = n[1]; //p01
        n[1] = n[3]; //p03
        n[3] = n[2]; //p02
        n[2] = temp; //p01

        temp = n[4]; //p11
        n[5] = n[7]; //p13
        n[7] = n[6]; //p12
        n[6] = temp; //p11

        Byte p01 = Byte.parseByte(String.valueOf(Arrays.copyOfRange(n, 0, 2)), 2); //0,3
        Byte p02 = Byte.parseByte(String.valueOf(Arrays.copyOfRange(n, 2, 4)), 2); //1,2
        Byte p03 = Byte.parseByte(String.valueOf(Arrays.copyOfRange(n, 4, 6)), 2);
        Byte p04 = Byte.parseByte(String.valueOf(Arrays.copyOfRange(n, 6, 8)), 2);
        int s_0 = s0[p01.intValue()][p02.intValue()]; //gather the numbers from the S arrays
        int s_1 = s1[p03.intValue()][p04.intValue()];
        char[] result = new char[4];
        
        //Separate each of the 2-bit numbers into separate bits
        if (s_0 <= 1) { //if the number is below 1(in our case  zero)
            result[0] = '0'; //put a zero in front
            result[1] = Integer.toBinaryString(s_0).charAt(0);
            /*the 2-bit representation of zero is only one bit, but the method 
            requires 2 bits to work
             */
        } else {
            result[0] = Integer.toBinaryString(s_0).charAt(0);
            result[1] = Integer.toBinaryString(s_0).charAt(1);
        }
        if (s_1 <= 1) {
            result[2] = '0';
            result[3] = Integer.toBinaryString(s_1).charAt(0);
        } else {
            result[2] = Integer.toBinaryString(s_1).charAt(0);
            result[3] = Integer.toBinaryString(s_1).charAt(1);
        }
        //return the result and do a final permutation as the paper notes.
        return permutation(result, 4);
    }

    /**
     * This function utilises the switch function(SW) as described in the paper.
     * The method interchanges the left and right 4 bis so that the second
     * instance of fk operates on a different 4 bits.
     *
     * @param m an array with length 8.
     * @return the switched array. ex. the array {1,2,3,4,5,6,7,8} becomes
     * {5,6,7,8,1,2,3,4}
     */
    private static char[] SW(char[] m) {
        char[] result = new char[m.length];
        //Break the 8bit char array into 2 seperate ones.
        char[] l = Arrays.copyOfRange(m, 0, 4);
        char[] r = Arrays.copyOfRange(m, 4, m.length);
        //Interchange them.
        for (int i = 0; i < m.length; i++) {
            if (i < 4) {
                result[i] = r[i];
            } else {
                result[i] = l[i - 4];
            }
        }

        return result;

    }
}
