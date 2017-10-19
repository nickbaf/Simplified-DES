package simplified.des;

import java.util.Arrays;
import java.util.Random;

/**
 * Simplified-DES Algorithm, from W.Stalling's Book Cryptograpgy and Network Security,Forth Edition,
 * Aristotle University of Thessaloniki,School of Sciences,Department of Computer Science,
 * Lesson: Network Security.
 * @author Nikolaos Bafatakis A.E.M 2383
 */
public class main {

    /**
     * The main function tests the integrity of the Algorithm,
     * by producing 200000 random 8-bit numbers and its ciphertexts by encrypting them
     * using the encrypt mehtod.Then using the ciphertext the function decrypts the message
     * using the decrypt method.In the end the original message(plaintext) and the 
     * decrypted one are compared.
     * 
     * @param args No arguments used.!
     */
    public static void main(String[] args) {
        char[] key = {'1', '0', '1', '0', '0', '0', '0', '0', '1', '0'}; //encryption key
        System.out.println("________________________________________________");
        System.out.println("|   Plaintext   |    Ciphertext   |   Decrypted  |");
        Random rn = new Random();
        //Testing the Algorithm
        int i;
        int correct=0;
        for (i = 0; i < 200000; i++) {//Produce random numbers     
            int k = rn.nextInt(Integer.MAX_VALUE) + 256; //numbers must have 8 bits or more
            char[] plain;
            plain = Integer.toBinaryString(k).toCharArray();
            //take the first 8 bits, encrypt using the key and return the ciphertext
            char[] ciphertext = Simplified_Des.encrypt(Arrays.copyOf(plain, 8), key);  
            //use the same ciphertext you got, decrypt the message to get the original one.
            char[] rev = Simplified_Des.decrypt(ciphertext, key); 
            System.out.println("|    "+String.valueOf(Arrays.copyOf(plain, 8))+"   |     "+String.valueOf(ciphertext)+"    |   "+String.valueOf(rev)+"   |");
            System.out.println("|________________________________________________|");
           //if the decrypted message isn't equal to the original one, alert
            if (Arrays.equals(Arrays.copyOf(plain, 8), rev)) {
                correct++;
            }
        }
        System.out.println("Produced "+i+" random 8-bit numbers\nCorrect messages decrypted: "+correct+"\nIncorrect messages decrypted:"+(i-correct));
        if((i-correct)==0){
            System.out.println("\nThe Algorithm works correct!!!");
        }
    }

}
