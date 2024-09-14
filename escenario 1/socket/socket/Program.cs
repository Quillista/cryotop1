using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

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

            Console.WriteLine("Esperando conexión...");

            Socket handler = listener.Accept();

            // Recibe mensaje cifrado
            byte[] buffer2 = new byte[1024];
            int bytesReceived2 = handler.Receive(buffer2);
            //el cliente solicita la llave y el servidor procede a enviarla por sockets

            Console.WriteLine("Enviando llave...");
            // Clave secreta de 32 bytes y nonce de 8 bytes (que sera enviada al cliente)
            byte[] key = Encoding.ASCII.GetBytes("12345678901234567890123456789012");
            byte[] nonce = Encoding.ASCII.GetBytes("12345678");
            handler.Send(key);
            while (true)
            {
                // Recibe mensaje cifrado
                byte[] buffer = new byte[1024];
                int bytesReceived = handler.Receive(buffer);
                // Descifrar el mensaje
                byte[] encryptedMessage = new byte[bytesReceived];
                Array.Copy(buffer, encryptedMessage, bytesReceived);
                //se usa salsa20 para descifrarlo
                byte[] decryptedMessage = DecryptSalsa20(encryptedMessage, key, nonce);

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

    public static byte[] DecryptSalsa20(byte[] cipherText, byte[] key, byte[] nonce)
    {
        Salsa20Engine engine = new Salsa20Engine(); // Salsa20
        ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), nonce);

        engine.Init(false, parameters); // false para descifrar
        byte[] plainText = new byte[cipherText.Length];
        engine.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);

        return plainText;
    }
}
