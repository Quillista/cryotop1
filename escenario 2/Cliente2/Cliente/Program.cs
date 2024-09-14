using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

class Client
{
    static void Main()
    {
        while (true) {


            try
            {

                // Se inicializa el cliente
                IPHostEntry host = Dns.GetHostEntry("localhost");
                IPAddress ipAddress = host.AddressList[1];
                IPEndPoint remoteEP = new IPEndPoint(ipAddress, 11000);

                Socket sender = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                sender.Connect(remoteEP);

                //se solicita la llave al servidor para cifrar el mensaje
                Console.WriteLine("Conectado al servidor. Recibiendo llave...");
                Console.WriteLine("Por favor, ingrese su mensaje:");

                // Leer lo que el usuario escribe y guardarlo en una variable
                string mensajerec = Console.ReadLine();
                byte[] key = new byte[32]; // 256 bits = 32 bytes
                byte[] nonce = new byte[16]; // 128 bits = 16 bytes

                using (FileStream fs = new FileStream("C:\\Users\\Factin\\Desktop\\clave.bin", FileMode.Open, FileAccess.Read))
                {
                    // Leer primero la clave
                    fs.Read(key, 0, key.Length);
                    // Luego leer el IV
                    fs.Read(nonce, 0, nonce.Length);
                }



                // Mensaje original
                string message = mensajerec;
                byte[] messageBytes = Encoding.ASCII.GetBytes(message);

                // Cifrar con Aes256
                byte[] encryptedMessage = EncryptAes256Cbc(messageBytes, key, nonce);

                Console.WriteLine("Conectado al servidor. Enviando mensaje cifrado...");

                // Enviar el mensaje cifrado
                sender.Send(encryptedMessage);

                // Recibir respuesta del servidor
                byte[] buffer = new byte[1024];
                int bytesRec = sender.Receive(buffer);
                Console.WriteLine("Respuesta del servidor: {0}", Encoding.ASCII.GetString(buffer, 0, bytesRec));

                //sender.Shutdown(SocketShutdown.Both);
                //sender.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }

        }

    }

    //Funcion para cifrar usando Salsa20,usamos la biblioteca BouncyCastle en c#
    public static byte[] EncryptAes256Cbc(byte[] plainText, byte[] key, byte[] iv)
    {
        // Asegúrate de que la clave y el IV tengan el tamaño adecuado
        if (key.Length != 32) // 256 bits
            throw new ArgumentException("La clave debe tener 256 bits (32 bytes).");
        if (iv.Length != 16) // 128 bits (tamaño del bloque AES)
            throw new ArgumentException("El IV debe tener 128 bits (16 bytes).");

        // Crear el motor AES en modo CBC
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));

        // Inicializar el cifrador para cifrar
        cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

        // Cifrar el texto plano
        byte[] cipherText = new byte[cipher.GetOutputSize(plainText.Length)];
        int length = cipher.ProcessBytes(plainText, 0, plainText.Length, cipherText, 0);
        cipher.DoFinal(cipherText, length);

        return cipherText;
    }
}
