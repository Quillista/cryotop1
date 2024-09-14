using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
class Server
{
    static void Main()
    {
        //se inicializa el servidor
        IPEndPoint localEndPoint = new IPEndPoint(IPAddress.Any, 11000);
        Socket listener = new Socket(IPAddress.Any.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

        try
        {
            listener.Bind(localEndPoint);
            listener.Listen(10);
            Aes aes = Aes.Create();

            aes.KeySize = 256; // 256 bits
            aes.GenerateKey();
            aes.GenerateIV();


            byte[] key = aes.Key;
            byte[] nonce = aes.IV;
            //Pass the filepath and filename to the StreamWriter Constructor
            using (FileStream fs = new FileStream("C:\\Users\\Factin\\Desktop\\clave.bin", FileMode.Create, FileAccess.Write))
            {
                // Escribir primero la clave
                fs.Write(key, 0, key.Length);
                // Luego escribir el IV
                fs.Write(nonce, 0, nonce.Length);
            }

            while (true)
            {
                Console.WriteLine("Esperando conexión...");

                Socket handler = listener.Accept();




                // Recibe mensaje cifrado
                byte[] buffer = new byte[1024];
                int bytesReceived = handler.Receive(buffer);
                // Descifrar el mensaje
                byte[] encryptedMessage = new byte[bytesReceived];
                Array.Copy(buffer, encryptedMessage, bytesReceived);
                //se usa Aes256 para descifrarlo
                byte[] decryptedMessage = DecryptAes256Cbc(encryptedMessage, key, nonce);

                Console.WriteLine("Mensaje recibido y descifrado: {0}", Encoding.ASCII.GetString(decryptedMessage));

                // Responder al cliente
                byte[] msg = Encoding.ASCII.GetBytes("Mensaje recibido en el servidor.");
                handler.Send(msg);

            }
            //handler.Shutdown(SocketShutdown.Both);
            //handler.Close();
        }
        catch (Exception e)
        {
            Console.WriteLine(e.ToString());
        }

        Console.WriteLine("Servidor cerrado.");
    }


    // Función para descifrar usando Salsa20, usamos la biblioteca BouncyCastle en c#

    public static byte[] DecryptAes256Cbc(byte[] cipherText, byte[] key, byte[] iv)
    {
        // Asegúrate de que la clave y el IV tengan el tamaño adecuado
        if (key.Length != 32) // 256 bits
            throw new ArgumentException("La clave debe tener 256 bits (32 bytes).");
        if (iv.Length != 16) // 128 bits (tamaño del bloque AES)
            throw new ArgumentException("El IV debe tener 128 bits (16 bytes).");

        // Crear el motor AES en modo CBC
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));

        // Inicializar el cifrador para descifrar
        cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

        // Descifrar el texto cifrado
        byte[] plainText = new byte[cipher.GetOutputSize(cipherText.Length)];
        int length = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
        cipher.DoFinal(plainText, length);

        return plainText;
    }
}
