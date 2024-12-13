using System;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

class Program
{
    static void Main(string[] args)
    {
        try
        {
            // Шляхи до файлів
            string inputFile = "input.txt";
            string encryptedFile = "encrypted.bin";
            string authTagFile = "auth_tag.bin";

            // Генерація випадкового ключа та IV
            byte[] key = new byte[32]; // 256-bit key
            byte[] iv = new byte[12]; // 96-bit IV
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
                rng.GetBytes(iv);
            }

            // Читання вхідного тексту
            byte[] plaintext = File.ReadAllBytes(inputFile);

            // Ініціалізація AES-GCM
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), 128, iv);
            cipher.Init(true, parameters);

            // Шифрування
            byte[] ciphertext = new byte[cipher.GetOutputSize(plaintext.Length)];
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
            cipher.DoFinal(ciphertext, len);

            // Отримання тегу автентифікації
            byte[] authTag = new byte[16]; // 128-bit auth tag
            Array.Copy(ciphertext, ciphertext.Length - 16, authTag, 0, 16);

            // Збереження шифротексту (без тегу автентифікації)
            byte[] finalCiphertext = new byte[ciphertext.Length - 16];
            Array.Copy(ciphertext, 0, finalCiphertext, 0, ciphertext.Length - 16);
            File.WriteAllBytes(encryptedFile, finalCiphertext);

            // Збереження тегу автентифікації
            File.WriteAllBytes(authTagFile, authTag);

            // Збереження ключа та IV (в реальному застосуванні потрібно зберігати безпечно)
            File.WriteAllBytes("key.bin", key);
            File.WriteAllBytes("iv.bin", iv);

            Console.WriteLine("Шифрування завершено успішно!");
            Console.WriteLine($"Шифротекст збережено у файлі: {encryptedFile}");
            Console.WriteLine($"Тег автентифікації збережено у файлі: {authTagFile}");

            // Виведення hexdump шифротексту та тегу
            Console.WriteLine("\nШифротекст (hex):");
            PrintHexDump(finalCiphertext);
            
            Console.WriteLine("\nТег автентифікації (hex):");
            PrintHexDump(authTag);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Помилка: {ex.Message}");
        }
    }

    static void PrintHexDump(byte[] bytes)
    {
        for (int i = 0; i < bytes.Length; i++)
        {
            Console.Write($"{bytes[i]:X2} ");
            if ((i + 1) % 16 == 0)
                Console.WriteLine();
        }
        Console.WriteLine();
    }
}

